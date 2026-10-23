# External-signing lifecycle proof (investigation branch for issue #8354)

This directory is an **isolated Composer project** that proves the external
PDF-signing lifecycle (`prepare` → external private-key operation →
`complete`) of `signerphp/pdf-signer` on the commit pinned below. It is proof
tooling only: it does **not** touch the LibreSign application runtime, and
nothing here is production code.

- Upstream tracking: LibreSign/libresign#8354 (epic #8335)
- Pinned library: `signerphp/pdf-signer` `dev-main#f27e4064be107b8a662f370a9acdcecd786da9f7`
  (transitive: `signerphp/pdf-core` v0.1.1, per the library's own constraint)
- Prepared state format: version 1 JSON with an **unkeyed** SHA-256 checksum
  (integrity only — see "Trust boundary" below)

## Run

```bash
composer install          # or: ./run-proof.sh (installs on first run)
./run-proof.sh
```

Requirements: PHP >= 8.3 with `ext-openssl`, Composer, and an OpenSSL 3 CLI
(the ECDSA pre-hashed signing op uses `openssl pkeyutl`; tested with OpenSSL
3.6.4). No GMP and no other PHP extensions are required.

Exit code: `0` = every stage passed, non-zero = the first failing stage.
All artifacts (keys, certs, PDFs, signatures, exported state) are written to
`var/`, which is git-ignored. Nothing real is used: certificates and keys are
synthetic, generated locally per run, and no signing provider is contacted.

## What the stages prove

| Stage | Command | Proof target |
|---|---|---|
| 0 | `0-setup.php` | Generates ALL synthetic artifacts (CA + leaf cert + private key per key type, an "other" wrong key, two distinct base PDFs) in their own process |
| A | `1-prepare.php`, `2-external-sign.php`, `3-complete.php`, `4-validate.php` | Real lifecycle: prepare with public cert only → payload is a **pre-computed digest** → private-key op in a separate process → complete in a new process → library validation **and independent `openssl cms -verify`** agree |
| B | `5-second-signature.php` | The whole lifecycle repeated on the signed PDF; **both** signatures validate |
| C | stages A with `ec` | Same lifecycle with EC P-256 (DER `r‖s` output, as `SignatureEncoding::EcdsaDer` requires) |
| D | `6-negative-cases.php` | Wrong key / empty / garbage signatures, corrupted state, tampered state with recomputed checksum, cross-lifecycle signature with deliberately distinct documents — and **where** each is rejected |

Stage separation is process separation plus API input separation, and the
two must not be confused:

- `0-setup` generates the private keys in its own process.
- `1-prepare` loads only the input PDF, the public certificate and the
  public chain. It never reads a private key (API input separation).
- `2-external-sign` loads only the private key and the exported payload.
- `3-complete` runs in a fresh PHP process with only the opaque state string
  and the raw signature bytes.

These are separate OS processes, not security sandboxes: nothing here
enforces OS-level access isolation, and the proof does not claim it.

## Cryptographic findings (observed on the pinned commit)

- `prepare()` returns `hash(digestAlgorithm, DER(CMS signed attributes))` as
  base64, with `inputType=digest`. The signed attributes carry the
  `messageDigest` of the PDF bytes covered by `/ByteRange`, so double hashing
  is avoided exactly when the external operation is a **pre-hashed
  signature** (RSA: DigestInfo + PKCS#1 v1.5; EC: ECDSA over the digest).
- `complete()` rejects only: empty signatures, incompatible key *type*
  (RSA/EC), invalid or checksum-failing state, and a CMS that exceeds the
  reserved `/Contents` placeholder. A signature from a **different key** or
  random garbage **is embedded** and only fails at validation time.
- The EC private-key op uses `openssl pkeyutl -sign` on the raw digest: for
  EC keys OpenSSL treats the input as a pre-hashed digest (no re-hash) and
  emits DER `r‖s`, matching `SignatureEncoding::EcdsaDer`. The RSA op is
  RSASSA-PKCS1-v1_5 over a DER `DigestInfo` via `openssl_private_encrypt`.
- State checksum is unkeyed SHA-256 (`hash('sha256', json_encode(payload))`,
  compared with `hash_equals`): detects accidental corruption, does **not**
  authenticate state. `6-negative-cases.php` case
  `tampered-state-rechecksum` demonstrates that a tampered state with a
  recomputed checksum completes and fails only at validation.
- Validation: the library engine reports per-signature `cryptoValid` /
  `trustValid`; this proof also re-verifies every signature independently via
  `openssl cms -verify -noverify -binary` (no shared code with the library;
  `-noverify` skips chain trust, which a synthetic CA cannot provide;
  `-binary` prevents text canonicalization of the supplied content).
- PDF `/ByteRange` uses the `[a b c d]` convention: covered bytes are
  `[a, a+b)` and `[c, c+d)`; the `/Contents <hex>` placeholder sits in the
  gap `[a+b, c)`.

## Trust boundary for later integration

The prepared state is a bearer token for the unsigned PDF: anyone holding it
can finalize the document with any signature-shaped bytes. Production use
(LibreSign #8354) must treat it as untrusted client input: authenticate and
authorize the caller, bind the state to the signing session server-side, and
never expose `complete()` on a public unauthenticated route. This proof does
NOT implement any of that (out of scope).

## Limitations

- No RFC3161 timestamp parameter exists in the external prepare API on the
  pinned commit (`SigningOptionsDto` timestamp is fixed to `null` there).
- Trust-chain and policy (PAdES/ICP-Brasil) validation are out of scope here;
  the synthetic CA cannot demonstrate chain trust.
- The `openssl` CLI check reads `/Contents` from each `/ByteRange` gap; it is
  a proof-grade extractor, not a general PDF parser.
