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
 * Private-key operation for ECDSA with an already-computed digest:
 * pure PHP P-256 ECDSA over the digest (no re-hash), DER r||s output.
 */
function proof_raw_sign_ecdsa(string $digest, string $keyPem): string {
	$key = openssl_pkey_get_private($keyPem);
	if ($key === false) {
		proof_fail('Could not load the proof EC private key.');
	}
	$details = openssl_pkey_get_details($key);
	if ($details === false || ($details['ec']['curve_name'] ?? '') !== 'prime256v1') {
		proof_fail('Proof ECDSA path requires a prime256v1 key.');
	}

	$p = gmp_init('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff', 16);
	$n = gmp_init('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16);
	$b = gmp_init('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b', 16);
	$gx = gmp_init('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 16);
	$gy = gmp_init('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 16);
	$d = gmp_init(bin2hex($details['ec']['d']), 16);

	$z = gmp_init(bin2hex($digest), 16);

	do {
		do {
			$k = gmp_random_range(gmp_init(1), gmp_sub($n, 1));
			$point = proof_ec_point_mul($gx, $gy, $k, $p, $b);
			$r = gmp_mod($point[0], $n);
		} while (gmp_cmp($r, 0) === 0);
		$kInverse = gmp_invert($k, $n);
		if ($kInverse === false) {
			proof_fail('gmp_invert(k, n) failed.');
		}
		$s = gmp_mod(gmp_mul($kInverse, gmp_add($z, gmp_mul($r, $d))), $n);
	} while (gmp_cmp($s, 0) === 0);

	return proof_der_sequence(proof_der_integer($r) . proof_der_integer($s));
}

function proof_ec_point_mul(GMP $x, GMP $y, GMP $k, GMP $p, GMP $b): array {
	$result = null;
	$addend = [$x, $y];
	while (gmp_cmp($k, 0) > 0) {
		if (gmp_testbit($k, 0)) {
			$result = $result === null ? $addend : proof_ec_point_add($result, $addend, $p, $b);
		}
		$addend = proof_ec_point_add($addend, $addend, $p, $b);
		$k = gmp_div_q($k, 2);
	}
	if ($result === null) {
		proof_fail('EC point multiplication by zero.');
	}

	return $result;
}

function proof_ec_point_add(array $a, array $b, GMP $p, GMP $bParam): array {
	[$x1, $y1] = $a;
	[$x2, $y2] = $b;
	if (gmp_cmp($x1, $x2) === 0) {
		if (gmp_cmp(gmp_mod(gmp_add($y1, $y2), $p), gmp_init(0)) === 0) {
			proof_fail('EC point at infinity during proof computation.');
		}
		// Doubling: slope = (3*x^2 + a) / (2*y) with a = p - 3 for P-256.
		$aCurve = gmp_sub($p, gmp_init(3));
		$numerator = gmp_mod(gmp_add(gmp_mul(gmp_init(3), gmp_mul($x1, $x1)), $aCurve), $p);
		$denominatorInverse = gmp_invert(gmp_mod(gmp_mul(gmp_init(2), $y1), $p), $p);
		if ($denominatorInverse === false) {
			proof_fail('EC doubling: no modular inverse for 2*y.');
		}
		$slope = gmp_mod(gmp_mul($numerator, $denominatorInverse), $p);
	} else {
		$denominatorInverse = gmp_invert(gmp_mod(gmp_sub($x2, $x1), $p), $p);
		if ($denominatorInverse === false) {
			proof_fail('EC addition: no modular inverse for x2 - x1.');
		}
		$slope = gmp_mod(gmp_mul(gmp_sub($y2, $y1), $denominatorInverse), $p);
	}
	$x3 = gmp_mod(gmp_sub(gmp_sub(gmp_mul($slope, $slope), $x1), $x2), $p);
	$y3 = gmp_mod(gmp_sub(gmp_mul($slope, gmp_sub($x1, $x3)), $y1), $p);

	return [$x3, $y3];
}

function proof_der_integer(GMP $value): string {
	$hex = gmp_strval($value, 16);
	if (strlen($hex) % 2 === 1) {
		$hex = '0' . $hex;
	}
	$bytes = hex2bin($hex);
	if ((ord($bytes[0]) & 0x80) !== 0) {
		$bytes = "\x00" . $bytes;
	}

	return "\x02" . proof_der_length(strlen($bytes)) . $bytes;
}

function proof_der_length(int $length): string {
	if ($length < 0x80) {
		return chr($length);
	}
	$bytes = ltrim(pack('N', $length), "\x00");

	return chr(0x80 | strlen($bytes)) . $bytes;
}

function proof_der_sequence(string $content): string {
	return "\x30" . proof_der_length(strlen($content)) . $content;
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
	$openssl = '/opt/homebrew/opt/openssl@3/bin/openssl';
	if (! is_executable($openssl)) {
		$openssl = '/usr/bin/openssl';
	}
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
