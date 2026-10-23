<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Stage 3 - COMPLETE (new PHP process).
 *
 * Restores the opaque prepared state exported by stage 1 and finalizes the PDF
 * with the raw signature bytes produced by stage 2. Only the state string and
 * the signature are passed in - no private key exists in this process.
 *
 * Usage: php bin/3-complete.php <rsa|ec> [suffix]
 * Exit codes: 0 = completed, 1 = failure.
 */

require __DIR__ . '/lib/helpers.php';

require __DIR__ . '/../vendor/autoload.php';

$keyType = $argv[1] ?? 'rsa';
$suffix = $argv[2] ?? $keyType;

$state = proof_read_state($suffix);
$signature = (string)file_get_contents(proof_path("{$suffix}-signature.bin"));

$pdf = SignerPHP\PdfSigner\Presentation\Signer::externalSigner()->complete($state, $signature);
if (! str_starts_with($pdf, '%PDF')) {
	proof_fail('complete() returned content that is not a PDF.');
}

file_put_contents(proof_path("{$suffix}-signed.pdf"), $pdf);

echo "Stage 3 COMPLETE ({$suffix})\n";
echo '  restored state bytes     = ' . strlen($state) . "\n";
echo '  signature bytes          = ' . strlen($signature) . "\n";
echo '  signed PDF bytes         = ' . strlen($pdf) . "\n";
echo "  exported                 = {$suffix}-signed.pdf\n";
exit(0);
