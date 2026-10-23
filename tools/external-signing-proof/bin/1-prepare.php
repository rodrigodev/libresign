<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Stage 1 - PREPARE.
 *
 * Runs the real SignerPHP\PdfSigner prepare step. This stage loads ONLY:
 * - the input PDF;
 * - the public signer certificate;
 * - the public certificate chain.
 *
 * It never reads a private key: identity generation happens in stage 0, in a
 * separate process. The private key is never persisted into the prepared
 * state. Exports the cryptographic payload and the opaque prepared state for
 * the following stages.
 *
 * Usage: php bin/1-prepare.php <rsa|ec> [suffix] [inputPdfPath]
 * Exit codes: 0 = prepared, 1 = failure.
 */

require __DIR__ . '/lib/helpers.php';

require __DIR__ . '/../vendor/autoload.php';

$keyType = $argv[1] ?? 'rsa';
$suffix = $argv[2] ?? $keyType;
$inputPdfPath = $argv[3] ?? proof_path("{$keyType}-base.pdf");
if (! in_array($keyType, ['rsa', 'ec'], true)) {
	proof_fail("Key type must be 'rsa' or 'ec', got '{$keyType}'.");
}
if (! is_file(proof_path("{$keyType}-cert.pem"))) {
	proof_fail('Setup artifacts missing. Run: php bin/0-setup.php');
}

$certificatePem = (string)file_get_contents(proof_path("{$keyType}-cert.pem"));
$chainPem = [(string)file_get_contents(proof_path("{$keyType}-ca.pem"))];
$pdf = (string)file_get_contents($inputPdfPath);

$prepared = SignerPHP\PdfSigner\Presentation\Signer::externalSigner()
	->withPdfContent($pdf)
	->withCertificate($certificatePem, $chainPem)
	->withMetadata(new SignerPHP\PdfSigner\Application\DTO\SignatureMetadataDto(
		reason: 'LibreSign issue 8354 external-signing lifecycle proof',
		location: 'Isolated fork proof',
		actor: new SignerPHP\PdfSigner\Application\DTO\SignatureActorDto(
			name: 'Proof Signer',
			contactInfo: 'proof@invalid.example',
		),
	))
	->prepare();

proof_export_prepared($prepared, $suffix);

$payload = proof_read_payload($suffix);
$digestBytes = strlen((string)base64_decode($payload['inputBase64'], true));

echo "Stage 1 PREPARE ({$suffix}, key={$keyType}, input={$inputPdfPath})\n";
echo "  payload.inputType        = {$payload['inputType']}\n";
echo "  payload.digestAlgorithm  = {$payload['digestAlgorithm']}\n";
echo "  payload.signatureAlgorithm = {$payload['signatureAlgorithm']}\n";
echo "  payload.signatureEncoding  = {$payload['signatureEncoding']}\n";
echo "  payload input bytes      = {$digestBytes}\n";
echo '  state bytes              = ' . strlen($prepared->state) . "\n";
echo "  exported                 = {$suffix}-payload.json, {$suffix}-state.json\n";
exit(0);
