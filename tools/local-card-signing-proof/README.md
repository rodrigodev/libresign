# Local card signing proof (issue #8356)

An isolated, reproducible proof that LibreSign's external PDF-signing
lifecycle (#9216) can be completed by a SEPARATE local signer process
using synthetic RSA and ECDSA P-256 credentials and real cryptographic
signatures.

**What this is NOT:**

- NOT an emulator of the Portuguese Citizen Card, its reader, or the
  official Autenticação.gov middleware or SDK.
- NOT evidence of compatibility with the physical Citizen Card.
- NOT a browser-facing service, native-messaging host, HTTP service,
  CSC/PSC adapter or durable signing session. The operation identifier
  is correlation data only — not authentication, not idempotency.
- NOT a production fallback to software keys. Everything here is
  test-only.

## Layout

```
signer/local_signer.py   The local signer process (Python, `cryptography` only).
harness/*.php            Harness-side protocol client (required explicitly by the test).
fixtures/                GIT-IGNORED. Synthetic keys and certificates. Never commit.
run-proof.sh             One-shot reproduction script.
```

Production code, dependency constraints, routes and database entities
are untouched. The only change outside this directory is the
integration test that exercises the proof:
`tests/php/Integration/Tools/LocalCardSigningProofTest.php` plus its
test-only operation record.

## Reproduction

Requires PHP 8.3 with a bootstrapped Nextcloud test server whose
`apps/libresign` checkout holds this branch, and Python 3.9+.

```bash
cd tools/local-card-signing-proof

# 1. Python environment (one time)
python3 -m venv .venv
.venv/bin/pip install 'cryptography>=42,<46'

# 2. Synthetic fixtures (explicit init step; keys stay in fixtures/)
.venv/bin/python signer/local_signer.py init

# 3. The proof (RSA + EC lifecycles, cross-process completion,
#    preservation of prior signatures, and every failure scenario)
#    Run from the Nextcloud server checkout that contains this app:
CI=1 php -d memory_limit=1G vendor/bin/phpunit --do-not-cache-result \
  -c tests/php/phpunit.xml --testsuite integration \
  --filter LocalCardSigningProofTest
```

Or run `./run-proof.sh` from this directory with the server checkout
root as argument. Skips: the test reports a skip when the Python
environment is absent.

## Process protocol

One JSON request on stdin, one JSON response line on stdout, diagnostics
on stderr. Limits: 64 KiB per request, 1 MiB per response, hard process
timeout (default 10 s; the harness kills the child and classifies the
outcome as UNKNOWN — never automatically retried).

Request (only these fields are accepted; unknown top-level keys,
unknown payload keys and a null `simulation` are rejected). Timeouts
cover the WHOLE process lifetime, not just the first output line: a
child that answers and then refuses to exit is still classified as
UNKNOWN. Diagnostics: the signer writes stderr; the harness captures it
and includes its tail in timeout and crash exceptions.

```json
{
  "protocolVersion": "1",
  "operationId": "correlation id chosen by the harness",
  "credentialRef": "synthetic-rsa-leaf | synthetic-ec-leaf",
  "expectedCertificateFingerprint": "sha256 hex of the certificate DER",
  "payload": {
    "inputBase64": "base64 of the PRE-HASHED sha256 digest of CMS signed attributes",
    "inputType": "digest",
    "digestAlgorithm": "sha256",
    "signatureAlgorithm": "rsa-pkcs1-v1_5 | ecdsa",
    "signatureEncoding": "rsa-pkcs1 | ecdsa-der"
  },
  "simulation": {"scenario": "ok | no-reader | cancelled | pin-rejected | pin-blocked | wrong-key | hang | output-then-hang | malformed-response | oversized-response | wrong-operation-id | wrong-credential-ref"}
}
```

Success response: `{protocolVersion, operationId, credentialRef,
signatureBase64, signatureEncoding}`. RSA responses are RSASSA-PKCS1-v1_5
over the supplied digest (`rsa-pkcs1`). EC responses are the SIMULATED
card output: fixed-width r||s (`ecdsa-raw`), normalized to DER by the
harness — this models an ENCODING BOUNDARY; real middleware output still
needs verification. Error responses carry
`{error: {code, message}}`.

Supported combinations (the only ones the inspected lifecycle produces):

- SHA-256 + `rsa-pkcs1-v1_5` + `rsa-pkcs1` (RSA leaf, 2048 bit)
- SHA-256 + `ecdsa` + `ecdsa-der` (EC leaf, P-256)

No RSA-PSS. No silent algorithm substitution. The FULL combination is
validated before the private key is touched. The digest supplied in the
payload is signed EXACTLY ONCE via prehashed APIs — never re-hashed.

Protocol error codes: `unsupported-protocol`, `invalid-request`,
`invalid-digest` (bad Base64 or wrong length), `unsupported-input-type`,
`unsupported-algorithm`, `unsupported-encoding`, `unexpected-parameter`,
`credential-not-found`, `fingerprint-mismatch`, `no-reader`,
`cancelled`, `pin-rejected`, `pin-blocked`. The PIN scenarios are named
codes only — no PIN value exists, is stored, or transits the harness.

## Synthetic credentials

`signer/local_signer.py init` generates, into the git-ignored
`fixtures/` directory:

- A synthetic test root CA (`CA:TRUE` critical, `keyCertSign`/`cRLSign`),
  subject `SYNTHETIC TEST Root (not a Portuguese CA)`.
- `synthetic-rsa-leaf` — RSA-2048 signing leaf
  (`CA:FALSE` critical, `digitalSignature`+`nonRepudiation` critical).
- `synthetic-ec-leaf` — EC P-256 signing leaf with the same usage.

Private keys are PKCS#8 PEM, mode 0600, inside `fixtures/` only. The
LibreSign harness receives certificates and digests — never keys. The
`wrong-key` scenario uses a TRANSIENT in-memory key of the same type;
nothing is persisted.

## Reused #9216 guarantees (unchanged code)

The proof drives LibreSign's real `ExternalPdfSigningService`:

- prepare(): DocMDP gate, upstream payload creation, preparation-input
  fingerprint binding (`PreparedExternalOperation`).
- complete(): preparation-input comparison, exactly-one-new-signature,
  completed-revision coverage, cryptographic validity through the real
  validation layer, signer identity resolved from the CMS SignerInfo and
  matched against the expected certificate, prior-signature retention
  with unchanged contents.
- The prepared state survives process termination (proof: completion in
  a fresh PHP process through the same `SubprocessInfrastructure` the
  #9216 tests use, unchanged).

## Simulated vs. real

| Aspect | Status |
| --- | --- |
| PDF/CMS prepare + complete | real (signerphp/pdf-signer + LibreSign service) |
| RSA / ECDSA P-256 signatures | real cryptography, separate OS process |
| Signature validation | real (LibreSign validation layer) |
| Independent CMS verification | real (OpenSSL CLI, `-noverify -binary`) |
| Card, reader, dialogs, middleware | simulated (JSON codes, no PIN material) |
| Certificates | synthetic test identities |
| EC output encoding | simulated fixed-width r||s → harness normalizes to DER |

## Failure behavior and retry limitations

- Protocol failures (reader missing, cancellation, PIN rejection, card
  blocked, malformed/oversized IO, correlation mismatch, unsupported
  combination, invalid digest): rejected before any signature exists.
  The prepared operation is simply discarded.
- Cryptographic failures (wrong key, double-hashed input, signature from
  another operation): rejected during completion by the real validator.
- Timeout or process death: outcome UNKNOWN. The harness operation
  record marks the operation `uncertain` and REFUSES to resend it. No
  automatic retry of a potentially completed signing operation, ever.
- Duplicate completion: refused by the test-harness operation record
  (`ProofOperationRecord`). No production persistence is added.

## Future SDK mapping (Autenticação.gov middleware)

| Proof element | Future real-card equivalent |
| --- | --- |
| `discover` subcommand | enumerate readers/card via the official middleware |
| signing-certificate selection | select the SIGNING certificate/key object, never the authentication one (older cards RSA, newer ECDSA P-256) |
| `sign` with prehashed digest | feed the prepared digest to the SDK's sign-digest API; never re-hash |
| `ecdsa-raw` → DER normalization | adapt the middleware's fixed-width r||s (or its native DER) to the encoding `complete()` expects |

## Remaining work before a physical Citizen Card

- Middleware integration through the official Autenticação.gov stack and
  real PIN dialogs (never a PIN in protocol payloads).
- Card-removal behavior mid-operation and reader/OS differences.
- The REAL certificate chain (EC do Estado Português root) and trust
  assessment — deliberately out of scope here, as is timestamp/LTV
  support.
- Verification of the actual signature encoding the middleware returns.

## Checks

php-cs-fixer and Psalm were run against every PHP file added by this
proof (full-project Psalm run: no errors); see the handoff report for
the exact commands and results. The `tools/` PHP harness is NOT part of
the application autoloader and is loaded explicitly by the test.
