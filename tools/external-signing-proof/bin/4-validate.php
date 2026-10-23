<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Stage 4 - VALIDATE.
 *
 * Two independent layers:
 *
 * 1. The library's own validation engine (cryptographic validity; trust-chain
 *    checking is off because the proof uses a self-made CA).
 * 2. An INDEPENDENT check with the openssl CLI: every /ByteRange is sliced,
 *    the CMS is extracted from /Contents, and `openssl cms -verify -noverify`
 *    checks the signature over the signed attributes and the message digest
 *    over the covered bytes. This layer shares no code with pdf-signer.
 *
 * Usage: php bin/4-validate.php <suffix> <pdfPath> <expectedSignatureCount>
 * Exit codes: 0 = all signatures valid, 1 = any check failed.
 */

require __DIR__ . '/lib/helpers.php';

require __DIR__ . '/../vendor/autoload.php';

$suffix = $argv[1] ?? 'rsa';
$pdfPath = $argv[2] ?? proof_path("{$suffix}-signed.pdf");
$expectedCount = (int)($argv[3] ?? 1);

$pdf = (string)file_get_contents($pdfPath);

$result = SignerPHP\PdfSigner\Presentation\Signer::validation()
	->withPdfContent($pdf)
	->validate();

echo "Stage 4 VALIDATE ({$suffix}) - {$pdfPath}\n";
$libraryValid = $result->hasSignatures && $result->allValid;
printf(
	"  library validation       = hasSignatures: %s, allValid: %s (%d entries)\n",
	$result->hasSignatures ? 'yes' : 'no',
	$result->allValid ? 'yes' : 'no',
	count($result->entries),
);
foreach ($result->entries as $entry) {
	printf(
		"    entry #%d: valid=%s cryptoValid=%s trustValid=%s reason=%s\n",
		$entry->index,
		var_export($entry->valid, true),
		var_export($entry->cryptoValid, true),
		var_export($entry->trustValid, true),
		var_export($entry->reason, true),
	);
}

$signatures = proof_extract_signatures($pdf);
printf("  extracted signatures     = %d (expected %d)\n", count($signatures), $expectedCount);
$countOk = count($signatures) === $expectedCount;

$independentOk = true;
foreach ($signatures as $index => $signature) {
	if ($signature['cms'] === '') {
		print "    openssl sig #{$index}: EMPTY CMS - rejected\n";
		$independentOk = false;
		continue;
	}
	$verification = proof_openssl_cms_verify($signature['cms'], $signature['content']);
	printf(
		"    openssl sig #%d (%s): %s\n",
		$index,
		implode(', ', $signature['byteRange']),
		$verification['ok'] ? 'VALID (detached CMS, signed attrs, message digest)' : 'INVALID',
	);
	if (! $verification['ok']) {
		$independentOk = false;
		print '      openssl output: ' . $verification['output'] . "\n";
	}
}

$pass = $libraryValid && $countOk && $independentOk;
print $pass
	? "  RESULT                   = PASS (library + independent openssl agree)\n"
	: "  RESULT                   = FAIL\n";
exit($pass ? 0 : 1);
