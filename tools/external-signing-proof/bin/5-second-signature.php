<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Stage 5 - SECOND SIGNATURE SURVIVAL.
 *
 * Runs the whole prepare -> external-sign -> complete lifecycle again, this
 * time on the already-signed PDF, producing a doubly signed document. Each
 * lifecycle stage runs in its own PHP process, as in stage 1-3. Then validates
 * that BOTH signatures remain valid (library + independent openssl check).
 *
 * Usage: php bin/5-second-signature.php [suffix] [inputPdfPath]
 * Exit codes: 0 = both signatures valid, 1 = failure.
 */

require __DIR__ . '/lib/helpers.php';

$suffix = $argv[1] ?? 'rsa';
$secondSuffix = $suffix . '-second';
$inputPdf = $argv[2] ?? proof_path("{$suffix}-signed.pdf");

$php = PHP_BINARY;
$stages = [
	['stage' => 'prepare',  'cmd' => [$php, __DIR__ . '/1-prepare.php', $suffix, $secondSuffix, $inputPdf]],
	['stage' => 'sign',     'cmd' => [$php, __DIR__ . '/2-external-sign.php', $suffix, $secondSuffix]],
	['stage' => 'complete', 'cmd' => [$php, __DIR__ . '/3-complete.php', $suffix, $secondSuffix]],
];

echo "Stage 5 SECOND SIGNATURE (input: {$inputPdf})\n";
foreach ($stages as $step) {
	$command = implode(' ', array_map(escapeshellarg(...), $step['cmd']));
	echo "  > {$step['stage']}\n";
	passthru($command, $exitCode);
	if ($exitCode !== 0) {
		proof_fail("Second-signature stage '{$step['stage']}' exited with {$exitCode}.");
	}
}

$doublySigned = proof_path("{$secondSuffix}-signed.pdf");
$validateCommand = implode(' ', array_map(escapeshellarg(...), [
	$php, __DIR__ . '/4-validate.php', $secondSuffix, $doublySigned, '2',
]));
echo "  > validate both signatures\n";
passthru($validateCommand, $validateExit);
if ($validateExit !== 0) {
	proof_fail('Validation of the doubly signed PDF exited with ' . $validateExit . '.');
}
proof_ok('Both signatures are valid in ' . $doublySigned);
exit(0);
