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

Preferred: the dedicated proof command. It resolves ONE authoritative
app directory, prepares the Python environment and fixtures for THAT
checkout, and fails on failures, skips, or zero executed tests.

```bash
# From a Nextcloud server checkout:
tools/local-card-signing-proof/run-proof.sh /path/to/nextcloud-server
# Or with a nonstandard apps layout:
tools/local-card-signing-proof/run-proof.sh /path/to/server apps/libresign
# Or pointing directly at the app checkout:
tools/local-card-signing-proof/run-proof.sh /path/to/apps/libresign
```

Manual steps (step 1 and 2 run from the APP checkout
`<server>/apps/libresign`; step 3 runs from the SAME app root, which is
where `vendor/bin/phpunit` and `tests/php/phpunit.xml` live):

```bash
cd <server>/apps/libresign/tools/local-card-signing-proof

# 1. Python environment (one time)
python3 -m venv .venv
.venv/bin/pip install -r signer/requirements.txt

# 2. Synthetic fixtures (explicit init step; keys stay in fixtures/)
.venv/bin/python signer/local_signer.py init

# 3. The proof — run from the APP root, not the server root:
cd <server>/apps/libresign
LOCAL_CARD_SIGNER_PYTHON=tools/local-card-signing-proof/.venv/bin/python \
CI=1 php -d memory_limit=1G vendor/bin/phpunit --do-not-cache-result \
  -c tests/php/phpunit.xml --testsuite integration \
  --filter LocalCardSigningProofTest
```

## Process protocol

One JSON request on stdin, one JSON response line on stdout, diagnostics
on stderr. Limits: 64 KiB per request, 1 MiB cumulative response, hard
process deadline (default 10 s, `hrtime`-monotonic, covering the WHOLE
child lifetime — an answer-then-hang child is still an uncertain
outcome). All deadline arithmetic is monotonic; the termination grace
period (2 s) and kill confirmation period (2 s) are separate bounded
periods. Termination is CONFIRMED (SIGTERM → grace poll → SIGKILL →
exit observed) and requires `posix_kill`; without it the client refuses
to launch a child at all. GUARANTEE LIMIT: when exit cannot be
confirmed within the bounded periods, cleanup is marked exhausted (no
repeated attempts) and `termination-unconfirmed` is thrown — but error
delivery is NOT guaranteed to be prompt, because PHP resource
destruction can wait for the kernel. The independent outer watchdog is
the containment for that unsupported environmental condition.
Rejections carry stable reasons
(`REASON_*` on `SignerProtocolException`). Request validation is strict:
unknown top-level keys, unknown payload keys and a null `simulation`
are rejected. Diagnostics: the signer writes stderr; the harness
retains only a bounded 8 KiB tail and includes it in timeout and crash
exceptions.

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

The harness coordinator (`ProofOperationRecord`, test-only) classifies
outcomes AUTOMATICALLY and conservatively:

- Explicit simulated PRE-SIGN rejection (reader missing, cancellation,
  PIN rejection, card blocked, invalid request, unsupported combination,
  invalid digest, credential or fingerprint mismatch): the signer's
  documented validation runs entirely BEFORE key access, so these
  failures prove no signature exists. The operation closes as
  `rejected`.
- Anything else observed AFTER submission — unusable or malformed
  response, oversized output, trailing content, crash, nonzero exit,
  timeout or correlation failure — is a POTENTIALLY UNCERTAIN outcome:
  the signer may have used the key. The operation closes as `uncertain`
  and is NEVER resent. Protocol diagnostics in those errors are useful
  but are not proof that signing did not occur.
- Cryptographic validation failure (wrong key, double-hashed input,
  signature from another operation): rejected during completion by the
  real validator. The operation closes as `failed`; its bytes are never
  returned or published.
- Duplicate completion: refused by the coordinator BEFORE the completion
  service is invoked. The completion callback runs exactly once per
  operation. No production persistence is added.

`run-proof.sh` resolves ONE authoritative app directory (a Nextcloud
server root with `apps/libresign`, or an explicit app path), verifies
the checkout contains the proof and the real service, prepares the
Python environment and fixtures for THAT checkout, exports the exact
Python binary via `LOCAL_CARD_SIGNER_PYTHON`, and FAILS on PHPUnit
errors, skipped tests, or a run with zero executed tests (JUnit report,
never parsed console output).

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

Proof-specific Psalm analysis: the application's `psalm.xml` analyzes
`lib/` ONLY, so a default application scan does NOT cover the proof.
A committed generator creates a temporary proof-specific config whose
`projectFiles` are exactly the PHP the proof adds
(`tools/local-card-signing-proof/harness/`,
`tests/php/Integration/Tools/`); `extraFiles` resolve the dependencies
(app `lib/`, Nextcloud server `lib/`, server `tests/lib/`, the
integration `TestCase`, the app `AppConfigOverwrite` helper and the
#9216 subprocess infrastructure). A minimal committed PHPUnit stub
(`psalm/phpunit-testcase.phpstub`) provides parent-chain RESOLUTION
only — the analysis process does not load PHPUnit classes, so
behavioral typing of inherited test helpers is limited by design. The
production `psalm.xml`, baseline and error level are never modified
and no suppressions are added.

One exact command (from the APP checkout, PHP >= 8.3, Psalm from
`vendor-bin/psalm`):

```bash
php tools/local-card-signing-proof/psalm/generate-config.php \
  --server-root=/path/to/nextcloud-server
CI=1 vendor-bin/psalm/vendor/bin/psalm --no-cache --threads=4 \
  -c psalm-proof.xml
```

The generator verifies the checkout (wrong checkouts fail early) and
writes `psalm-proof.xml` into the app root; that file is GENERATED and
must not be committed. php-cs-fixer runs over the same added paths.
The `tools/` PHP harness is NOT part of the application autoloader and
is loaded explicitly by the test. Recorded results, exit codes and
subset-scan diagnostics are in the handoff reports.
