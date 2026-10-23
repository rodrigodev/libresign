<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Stage 2 - EXTERNAL SIGNER (the private-key operation).
 *
 * Stands in for an external signer (CSC/PSC/HSM/device bridge). It reads only
 * the exported payload - never the prepared state, never the PDF - performs
 * the private-key operation on the digest, and returns raw signature bytes.
 *
 * The digest is already computed by prepare(); this stage must NOT hash again.
 * - RSA: RSASSA-PKCS1-v1_5 over DER DigestInfo (openssl_private_encrypt).
 * - EC:  P-256 ECDSA over the digest, DER r||s encoding.
 *
 * Usage: php bin/2-external-sign.php <rsa|ec> [suffix]
 * Exit codes: 0 = signed, 1 = failure.
 */

require __DIR__ . '/lib/helpers.php';

$keyType = $argv[1] ?? 'rsa';
$suffix = $argv[2] ?? $keyType;

$payload = proof_read_payload($suffix);
$digest = base64_decode($payload['inputBase64'], true);
if (! is_string($digest) || $digest === '') {
	proof_fail('Exported payload contains no valid digest.');
}

$expectedType = $payload['inputType'] ?? '';
if ($expectedType !== 'digest') {
	proof_fail("Unexpected payload inputType '{$expectedType}' - the proof expects a pre-computed digest.");
}
$expectedDigestLength = match ($payload['digestAlgorithm'] ?? '') {
	'sha256' => 32,
	'sha384' => 48,
	'sha512' => 64,
	default => proof_fail("Unsupported digest algorithm '{$payload['digestAlgorithm']}'."),
};
if (strlen($digest) !== $expectedDigestLength) {
	proof_fail(sprintf('Digest length %d does not match %s (%d bytes).', strlen($digest), $payload['digestAlgorithm'], $expectedDigestLength));
}

$keyPem = (string)file_get_contents(proof_path("{$suffix}-key.pem"));
$signature = $keyType === 'ec'
	? proof_raw_sign_ecdsa($digest, $keyPem)
	: proof_raw_sign_rsa($digest, $keyPem, $payload['digestAlgorithm']);

file_put_contents(proof_path("{$suffix}-signature.bin"), $signature);

echo "Stage 2 EXTERNAL SIGN ({$suffix})\n";
echo "  performed                = {$payload['signatureAlgorithm']} over {$payload['digestAlgorithm']} digest (no re-hash)\n";
echo '  signature bytes          = ' . strlen($signature) . " ({$payload['signatureEncoding']})\n";
echo "  exported                 = {$suffix}-signature.bin\n";
exit(0);
