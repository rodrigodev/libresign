<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Stage 1 - PREPARE.
 *
 * Creates the synthetic identity and the base PDF, then runs the real
 * SignerPHP\PdfSigner prepare step using ONLY the public certificate (the
 * private key never touches this stage's inputs and is never persisted into
 * the prepared state). Exports the cryptographic payload and the opaque
 * prepared state for the following stages.
 *
 * Usage: php bin/1-prepare.php <rsa|ec> [suffix] [inputPdfPath]
 * Exit codes: 0 = prepared, 1 = failure.
 */

require __DIR__ . '/lib/helpers.php';

require __DIR__ . '/../vendor/autoload.php';

$keyType = $argv[1] ?? 'rsa';
$suffix = $argv[2] ?? $keyType;
$inputPdfPath = $argv[3] ?? null;
if (! in_array($keyType, ['rsa', 'ec'], true)) {
	proof_fail("Key type must be 'rsa' or 'ec', got '{$keyType}'.");
}

$identity = proof_generate_identity($keyType);
file_put_contents(proof_path("{$suffix}-ca.pem"), $identity['caPem']);
file_put_contents(proof_path("{$suffix}-cert.pem"), $identity['certPem']);
file_put_contents(proof_path("{$suffix}-key.pem"), $identity['keyPem']);

$pdf = $inputPdfPath !== null
	? (string)file_get_contents($inputPdfPath)
	: proof_make_pdf('BT /F1 24 Tf 72 700 Td (External signing proof - issue 8354) Tj ET');
file_put_contents(proof_path("{$suffix}-base.pdf"), $pdf);

$prepared = SignerPHP\PdfSigner\Presentation\Signer::externalSigner()
	->withPdfContent($pdf)
	->withCertificate($identity['certPem'], [$identity['caPem']])
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

echo "Stage 1 PREPARE ({$suffix}, key={$keyType})\n";
echo "  payload.inputType        = {$payload['inputType']}\n";
echo "  payload.digestAlgorithm  = {$payload['digestAlgorithm']}\n";
echo "  payload.signatureAlgorithm = {$payload['signatureAlgorithm']}\n";
echo "  payload.signatureEncoding  = {$payload['signatureEncoding']}\n";
echo "  payload input bytes      = {$digestBytes}\n";
echo '  state bytes              = ' . strlen($prepared->state) . "\n";
echo "  exported                 = {$suffix}-payload.json, {$suffix}-state.json\n";
exit(0);
