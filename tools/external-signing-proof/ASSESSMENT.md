# Dependency compatibility assessment for #8354

Compared on 2026-10-23:

| | Current (LibreSign `composer.lock`) | Proposed for #8354 |
|---|---|---|
| Package | `jeidison/signer-php` | `signerphp/pdf-signer` |
| Version | `dev-main` | no release contains the lifecycle; proof pins `dev-main#f27e4064be107b8a662f370a9acdcecd786da9f7` |
| Transitive | — | `signerphp/pdf-core` `^0.1.1` (locked v0.1.1 = `5b2e95ff62fbf4927c3a391e7f35f6570d517d7b`) |
| PHP | `^8.2` | `^8.2` |
| Extensions | openssl, curl, zlib, fileinfo | same |
| License | MIT | MIT (v0.2.0+, pdf-core v0.1.1+; the first v0.1.0 cuts carried no license field) |

## Release availability

`signerphp/pdf-signer` has Packagist tags v0.1.0 and v0.2.0 (both 2026-09-14).
The prepare/complete lifecycle (upstream SignerPHP/pdf-signer#4, closed
completed 2026-10-02) was merged afterwards (PR #5, commit `3d00abe`). **No
release contains the lifecycle.** The proof therefore locks a commit.
Production should require a tagged release once one exists; until then a
locked `dev-main#<sha>` in `composer.lock` is the reproducible equivalent.

## Namespace and packaging

- Old: PSR-4 `SignerPHP\` → `src/` (156 classes; the PDF parser travelled
  inside the package as `SignerPHP\Infrastructure\PdfCore\*`).
- New: PSR-4 `SignerPHP\PdfSigner\` → `src/`, plus a separate package
  `signerphp/pdf-core` that now owns the parser under `SignerPHP\PdfCore\*`.
- Class-level comparison: of 97 classes shared by identical path, 79 are
  byte-identical modulo the namespace prefix; 18 changed (listed below); 59
  old-only classes are the moved PdfCore subtree plus two inspectors.

## Compatibility for the classes LibreSign consumes today

(`lib/Handler/SignEngine/PhpNativeHandler.php`,
`lib/Service/SignatureStampPreview/SignatureStampAppearanceBuilder.php`,
`tests/php/Unit/Handler/SignEngine/PhpNativeHandlerTest.php`)

| Consumed symbol | Change in new stack | Source-compatible at LibreSign call sites |
|---|---|---|
| `PdfSigningService` | constructor `(OpenSslCertificateValidator, NativePdfSigningEngine)` and `sign(SignPdfRequestDto): string` unchanged; internal context rewiring | Yes |
| `NativePdfSigningEngine` | constructed with no arguments; constructor gained a defaulted provider factory; `sign()` input type changed (internal) | Yes |
| `OpenSslCertificateValidator` | identical | Yes |
| `CertificateCredentialsDto`, `PdfContentDto`, `SignatureActorDto`, `SignatureAppearanceDto`, `SignatureMetadataDto`, `SigningOptionsDto`, `SignPdfRequestDto`, `TimestampOptionsDto`, `CertificationLevel` | byte-identical after prefix change (LibreSign uses named arguments) | Yes |
| `SignatureAppearanceXObjectDto` | now extends `SignerPHP\PdfCore\AppearanceXObject`; constructor `(stream, resources)` unchanged | Yes |
| `SigningContextDto` | shape changed (request + verified certificate → pdf + options + certificate) | LibreSign never constructs it — no impact |

Migration for the synchronous path is a namespace-prefix change on the
`use` statements; no call-site shape change was found. The eventual #8354
PR must still run the existing signing suites (`PhpNativeHandlerTest`,
PKCS#7/PKCS#12 handler tests) as proof of that claim.

## External lifecycle API (verified against the pinned commit)

- `Signer::externalSigner()` → `ExternalSignerBuilder`
  (`withPdfContent`, `withCertificate(certPem, chainPem)`, `withMetadata`,
  `withAppearance`, `withoutDefaultAppearance`, `withPadesBaselineB`,
  `withCertificationLevel`, `withHashAlgorithm`).
- `prepare(): PreparedExternalSignature { payload, state }`;
  `complete(state, rawSignature): string`; `completeBase64(...)` convenience.
- Payload = `inputBase64` (SHA-256 of the DER CMS signed attributes),
  `inputType=digest`, `digestAlgorithm`, `signatureAlgorithm`
  (`rsa-pkcs1-v1_5` or `ecdsa`), `signatureEncoding` (`rsa-pkcs1` or
  `ecdsa-der`). The external operation is a **pre-hashed signature**
  (RSA: RSASSA-PKCS1-v1_5 over DER `DigestInfo`; EC: ECDSA over the digest,
  DER `r‖s`). The upstream VIDaaS provider signs the raw digest
  (`signature_format=RAW`), confirming the contract.
- Digests: sha1/224/256/384/512. Signature algorithms: RSA PKCS#1 v1.5,
  ECDSA only. No RSA-PSS/EdDSA in this path.
- Appearance, metadata and DocMDP certification level are supported by
  external prepare. RFC3161 timestamping is **not** parameterizable in the
  external API on this commit (the `timestamp` option is fixed `null`).
- State: versioned JSON (version 1) carrying the unsigned PDF, signer
  certificate + chain, signed attributes and both algorithm identifiers,
  protected by an **unkeyed** SHA-256 checksum compared with `hash_equals` —
  corruption detection, not authenticity.
- `complete()` verifies only: non-empty signature, signature-algorithm/key
  **type** match, state version + checksum, and placeholder capacity.
  Wrong-key or garbage signatures are embedded and only fail validation
  (proven empirically; see `bin/6-negative-cases.php`).

## Coexistence vs replacement

Both packages could technically coexist: PSR-4 prefixes `SignerPHP\` and
`SignerPHP\PdfSigner\` do not collide, and the PdfCore classes moved to a
namespace (`SignerPHP\PdfCore\`) the old package never used
(`SignerPHP\Infrastructure\PdfCore\`). Replacement is still the right move —
same engines, one codebase — but it is **not** forced by a technical
conflict, and no composer-level blocker exists.

## Does the migration need its own PR?

Yes. Two reasons:

1. The dependency swap changes the engine underneath existing synchronous
   signing for every user; it must be validated (unit + PKCS#7/PKCS#12
   integration suites) on its own, not hidden inside the #8354 feature PR.
2. The upstream dependency has no tagged release yet; the migration PR
   should either wait for a tag or land with the locked commit and a
   documented upgrade path.

The mechanical surface is small (namespace prefix on ~15 `use` statements in
two runtime files plus their tests), so the migration PR is small; it is not
part of the #8354 feature scope.
