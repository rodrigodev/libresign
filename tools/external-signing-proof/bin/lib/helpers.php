<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

use SignerPHP\PdfSigner\Application\DTO\PreparedExternalSignature;

/**
 * Shared helpers for the #8354 external-signing lifecycle proof.
 *
 * This file is proof tooling only. It is NOT production code and must never be
 * wired into the LibreSign runtime.
 */

const PROOF_VAR_DIR = __DIR__ . '/../../var';

function proof_fail(string $message): never {
	fwrite(STDERR, "FAIL: {$message}\n");
	exit(1);
}

function proof_ok(string $message): void {
	echo "OK: {$message}\n";
}

function proof_var_dir(): string {
	if (! is_dir(PROOF_VAR_DIR) && ! mkdir(PROOF_VAR_DIR, 0777, true) && ! is_dir(PROOF_VAR_DIR)) {
		proof_fail('Could not create proof work directory: ' . PROOF_VAR_DIR);
	}

	return PROOF_VAR_DIR;
}

function proof_path(string $suffix): string {
	return proof_var_dir() . '/' . $suffix;
}

/**
 * Build a minimal but structurally valid one-page PDF with a computed xref table.
 */
function proof_make_pdf(string $textLine): string {
	$objects = [
		1 => '<< /Type /Catalog /Pages 2 0 R >>',
		2 => '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
		3 => '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] '
			. '/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
		4 => '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
		5 => '<< /Length ' . strlen($textLine) . " >>\nstream\n{$textLine}\nendstream",
	];

	$pdf = "%PDF-1.4\n";
	$offsets = [];
	foreach ($objects as $number => $body) {
		$offsets[$number] = strlen($pdf);
		$pdf .= "{$number} 0 obj\n{$body}\nendobj\n";
	}

	$xrefOffset = strlen($pdf);
	$pdf .= "xref\n0 " . (count($objects) + 1) . "\n0000000000 65535 f \n";
	foreach ($offsets as $offset) {
		$pdf .= sprintf("%010d 00000 n \n", $offset);
	}
	$pdf .= "trailer\n<< /Size " . (count($objects) + 1) . " /Root 1 0 R >>\n";
	$pdf .= "startxref\n{$xrefOffset}\n%%EOF\n";

	return $pdf;
}

/**
 * Generate a synthetic CA plus a leaf signing certificate and a private key.
 *
 * Everything is generated locally for the proof only: never use these
 * identities for anything real.
 *
 * @return array{caPem: string, certPem: string, keyPem: string}
 */
function proof_generate_identity(string $keyType): array {
	$dn = [
		'commonName' => 'LibreSign 8354 Proof Signer',
		'organizationName' => 'LibreSign External Signing Proof',
		'countryName' => 'PT',
	];
	$keyOptions = $keyType === 'ec'
		? ['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]
		: ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];

	$caKey = openssl_pkey_new($keyOptions);
	if ($caKey === false) {
		proof_fail('openssl_pkey_new (CA) failed: ' . openssl_error_string());
	}
	$caCsr = openssl_csr_new($dn, $caKey, ['digest_alg' => 'sha256']);
	if ($caCsr === false) {
		proof_fail('openssl_csr_new (CA) failed: ' . openssl_error_string());
	}
	$caCert = openssl_csr_sign($caCsr, null, $caKey, 2, ['digest_alg' => 'sha256'], rand(1, 0x7fffffff));
	if ($caCert === false) {
		proof_fail('openssl_csr_sign (CA self-sign) failed: ' . openssl_error_string());
	}
	openssl_x509_export($caCert, $caPem);

	$leafKey = openssl_pkey_new($keyOptions);
	if ($leafKey === false) {
		proof_fail('openssl_pkey_new (leaf) failed: ' . openssl_error_string());
	}
	$leafCsr = openssl_csr_new($dn, $leafKey, ['digest_alg' => 'sha256']);
	if ($leafCsr === false) {
		proof_fail('openssl_csr_new (leaf) failed: ' . openssl_error_string());
	}
	$leafCert = openssl_csr_sign($leafCsr, $caCert, $caKey, 2, ['digest_alg' => 'sha256'], rand(1, 0x7fffffff));
	if ($leafCert === false) {
		proof_fail('openssl_csr_sign (leaf by CA) failed: ' . openssl_error_string());
	}
	openssl_x509_export($leafCert, $certPem);
	if (! openssl_pkey_export($leafKey, $keyPem)) {
		proof_fail('openssl_pkey_export failed: ' . openssl_error_string());
	}

	return ['caPem' => $caPem, 'certPem' => $certPem, 'keyPem' => $keyPem];
}

/**
 * DER DigestInfo prefix + digest, the RSASSA-PKCS1-v1_5 input for a pre-hashed signature.
 */
function proof_digest_info(string $hashAlgorithm, string $digest): string {
	$prefixes = [
		'sha1' => '3021300906052b0e03021a05000414',
		'sha224' => '302d300d06096086480165030402040500041c',
		'sha256' => '3031300d060960864801650304020105000420',
		'sha384' => '3041300d060960864801650304020205000430',
		'sha512' => '3051300d060960864801650304020305000440',
	];
	if (! isset($prefixes[$hashAlgorithm])) {
		proof_fail("No DigestInfo prefix for algorithm {$hashAlgorithm}");
	}

	return hex2bin($prefixes[$hashAlgorithm]) . $digest;
}

/**
 * Private-key operation for RSA with an already-computed digest:
 * RSASSA-PKCS1-v1_5 over DigestInfo, no second hash applied.
 */
function proof_raw_sign_rsa(string $digest, string $keyPem, string $hashAlgorithm): string {
	$key = openssl_pkey_get_private($keyPem);
	if ($key === false) {
		proof_fail('Could not load the proof private key.');
	}
	$signature = '';
	if (! openssl_private_encrypt(proof_digest_info($hashAlgorithm, $digest), $signature, $key, OPENSSL_PKCS1_PADDING)) {
		proof_fail('openssl_private_encrypt failed: ' . openssl_error_string());
	}

	return $signature;
}

/**
 * Resolve the OpenSSL 3 CLI used for independent verification and for the
 * prehashed ECDSA signing operation.
 */
function proof_openssl_bin(): string {
	$openssl = '/opt/homebrew/opt/openssl@3/bin/openssl';
	if (is_executable($openssl)) {
		return $openssl;
	}

	return '/usr/bin/openssl';
}

/**
 * Private-key operation for ECDSA with an already-computed digest:
 * `openssl pkeyutl -sign` treats the input of an EC key as a pre-hashed
 * digest and signs it directly (DER r||s). No second hash is applied.
 */
function proof_raw_sign_ecdsa(string $digest, string $keyPem): string {
	$digestFile = tempnam(sys_get_temp_dir(), 'proof-digest-');
	file_put_contents($digestFile, $digest);
	$keyFile = tempnam(sys_get_temp_dir(), 'proof-key-');
	file_put_contents($keyFile, $keyPem);
	chmod($keyFile, 0600);
	$signatureFile = tempnam(sys_get_temp_dir(), 'proof-sig-');
	$command = sprintf(
		'%s pkeyutl -sign -inkey %s -in %s -out %s 2>&1',
		escapeshellarg(proof_openssl_bin()),
		escapeshellarg($keyFile),
		escapeshellarg($digestFile),
		escapeshellarg($signatureFile),
	);
	exec($command, $outputLines, $exitCode);
	$signature = (string)file_get_contents($signatureFile);
	unlink($digestFile);
	unlink($keyFile);
	unlink($signatureFile);
	if ($exitCode !== 0 || $signature === '') {
		proof_fail('openssl pkeyutl (prehashed ECDSA) failed: ' . implode("\n", $outputLines));
	}

	return $signature;
}

/**
 * Locate every PDF signature from its /ByteRange and /Contents entries.
 *
 * ByteRange [a b c d] covers [a, a+b) and [c, c+d); the gap [a+b, c) holds
 * "/Contents <hex>". Returns one entry per signature, in document order.
 *
 * @return array<int, array{cms: string, content: string, byteRange: array{int, int, int, int}}>
 */
function proof_extract_signatures(string $pdf): array {
	if (! preg_match_all(
		'/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/',
		$pdf,
		$matches,
		PREG_SET_ORDER,
	)) {
		proof_fail('No /ByteRange found in the PDF.');
	}

	$signatures = [];
	foreach ($matches as $match) {
		[$start, $length1, $start2, $length2] = array_map(intval(...), array_slice($match, 1, 4));
		$gap = substr($pdf, $start + $length1, $start2 - ($start + $length1));
		if (! preg_match('/<\s*([0-9A-Fa-f]*)\s*>/', $gap, $hexMatch)) {
			proof_fail('No /Contents placeholder inside a ByteRange gap.');
		}
		$hex = $hexMatch[1];
		if (strlen($hex) % 2 === 1) {
			$hex .= '0';
		}
		$signatures[] = [
			'cms' => strlen($hex) > 0 ? hex2bin($hex) : '',
			'content' => substr($pdf, $start, $length1) . substr($pdf, $start2, $length2),
			'byteRange' => [$start, $length1, $start2, $length2],
		];
	}

	return $signatures;
}

/**
 * Independent verification of one extracted signature with the openssl CLI.
 *
 * -noverify skips certificate-chain trust; it still checks the signature over
 * the signed attributes and the message digest over the covered bytes.
 *
 * @return array{ok: bool, output: string}
 */
function proof_openssl_cms_verify(string $cmsDer, string $coveredContent): array {
	$openssl = proof_openssl_bin();
	$cmsFile = tempnam(sys_get_temp_dir(), 'proof-cms-');
	$contentFile = tempnam(sys_get_temp_dir(), 'proof-content-');
	file_put_contents($cmsFile, $cmsDer);
	file_put_contents($contentFile, $coveredContent);
	$command = sprintf(
		'%s cms -verify -inform DER -in %s -content %s -out /dev/null -noverify -binary 2>&1',
		escapeshellarg($openssl),
		escapeshellarg($cmsFile),
		escapeshellarg($contentFile),
	);
	exec($command, $outputLines, $exitCode);
	unlink($cmsFile);
	unlink($contentFile);

	return ['ok' => $exitCode === 0, 'output' => implode("\n", $outputLines)];
}

/**
 * Export the full prepared result (payload + opaque state) to the proof var directory.
 */
function proof_export_prepared(PreparedExternalSignature $prepared, string $suffix): void {
	$payload = [
		'inputBase64' => $prepared->payload->inputBase64,
		'inputType' => $prepared->payload->inputType->value,
		'digestAlgorithm' => $prepared->payload->digestAlgorithm->value,
		'signatureAlgorithm' => $prepared->payload->signatureAlgorithm->value,
		'signatureEncoding' => $prepared->payload->signatureEncoding->value,
	];
	file_put_contents(
		proof_path("{$suffix}-payload.json"),
		json_encode($payload, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n",
	);
	file_put_contents(proof_path("{$suffix}-state.json"), $prepared->state);
}

function proof_read_payload(string $suffix): array {
	$raw = file_get_contents(proof_path("{$suffix}-payload.json"));
	$payload = json_decode((string)$raw, true);
	if (! is_array($payload)) {
		proof_fail("Could not read exported payload for suffix {$suffix}.");
	}

	return $payload;
}

function proof_read_state(string $suffix): string {
	$state = file_get_contents(proof_path("{$suffix}-state.json"));
	if ($state === false || $state === '') {
		proof_fail("Could not read exported prepared state for suffix {$suffix}.");
	}

	return $state;
}
