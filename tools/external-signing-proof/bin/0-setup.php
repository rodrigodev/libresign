<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Stage 0 - SETUP.
 *
 * Generates every synthetic artifact in its OWN process, before any
 * preparation runs:
 * - a CA certificate, a leaf signing certificate and the private key;
 * - an "other" private key (used by negative cases as the wrong key);
 * - two distinct base PDFs (used to prove deterministic cross-lifecycle
 *   separation of payloads).
 *
 * Later stages load artifacts from var/: preparation loads only the public
 * certificate, the chain and the input PDF; the external-signing stage loads
 * the private key and the exported payload; completion loads only the state
 * and the signature bytes.
 *
 * Usage: php bin/0-setup.php
 * Exit codes: 0 = artifacts generated, 1 = failure.
 */

require __DIR__ . '/lib/helpers.php';

foreach (['rsa', 'ec'] as $keyType) {
	$identity = proof_generate_identity($keyType);
	file_put_contents(proof_path("{$keyType}-ca.pem"), $identity['caPem']);
	file_put_contents(proof_path("{$keyType}-cert.pem"), $identity['certPem']);
	file_put_contents(proof_path("{$keyType}-key.pem"), $identity['keyPem']);

	$otherKey = openssl_pkey_new($keyType === 'ec'
		? ['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]
		: ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
	if ($otherKey === false || ! openssl_pkey_export($otherKey, $otherKeyPem)) {
		proof_fail("Could not generate the other {$keyType} key: " . openssl_error_string());
	}
	file_put_contents(proof_path("{$keyType}-other-key.pem"), $otherKeyPem);

	file_put_contents(
		proof_path("{$keyType}-base.pdf"),
		proof_make_pdf('BT /F1 24 Tf 72 700 Td (External signing proof - issue 8354) Tj ET'),
	);
	file_put_contents(
		proof_path("{$keyType}-alt.pdf"),
		proof_make_pdf('BT /F1 24 Tf 72 700 Td (Distinct document B for the cross-lifecycle case) Tj ET'),
	);
}

echo "Stage 0 SETUP\n";
echo '  generated                = ' . count(glob(proof_path('*'))) . " artifacts in var/ (keys, certs, PDFs)\n";
exit(0);
