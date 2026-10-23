<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Negative cases - where is each failure actually rejected?
 *
 * Expectations follow from reading the pdf-signer source on the pinned commit
 * (DetachedCmsAssembler::complete embeds whatever non-empty bytes it receives
 * and only checks the key TYPE); the cases verify that behavior empirically.
 * Cases marked "validation" are NOT rejected during completion: complete()
 * produces a structurally valid PDF whose signature fails cryptographic
 * validation afterwards.
 *
 * All identities and PDFs come from stage 0 (bin/0-setup.php). The
 * cross-lifecycle case uses two DIFFERENT documents prepared in the same run
 * and asserts their payloads differ, so the case never depends on timestamp
 * granularity or sleeps.
 *
 * Usage: php bin/6-negative-cases.php
 * Exit codes: 0 = every case matched its expectation, 1 = any mismatch.
 */

require __DIR__ . '/lib/helpers.php';

require __DIR__ . '/../vendor/autoload.php';

use SignerPHP\PdfSigner\Application\DTO\PreparedExternalSignature;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Presentation\Signer;

if (! is_file(proof_path('rsa-cert.pem')) || ! is_file(proof_path('rsa-alt.pdf'))) {
	proof_fail('Setup artifacts missing. Run: php bin/0-setup.php');
}

$certificatePem = (string)file_get_contents(proof_path('rsa-cert.pem'));
$chainPem = [(string)file_get_contents(proof_path('rsa-ca.pem'))];
$signerKeyPem = (string)file_get_contents(proof_path('rsa-key.pem'));
$otherKeyPem = (string)file_get_contents(proof_path('rsa-other-key.pem'));
$basePdf = (string)file_get_contents(proof_path('rsa-base.pdf'));
$altPdf = (string)file_get_contents(proof_path('rsa-alt.pdf'));
if ($basePdf === $altPdf) {
	proof_fail('Setup produced identical documents; the cross-lifecycle case needs distinct inputs.');
}

function proof_prepare_fresh(string $pdf, string $certificatePem, array $chainPem): PreparedExternalSignature {
	return Signer::externalSigner()
		->withPdfContent($pdf)
		->withCertificate($certificatePem, $chainPem)
		->prepare();
}

function proof_sign_digest(string $digest, string $keyPem): string {
	return proof_raw_sign_rsa($digest, $keyPem, 'sha256');
}

/**
 * Library validation; a thrown exception also counts as "invalid".
 */
function proof_validate_pdf(string $pdf): array {
	try {
		$result = Signer::validation()->withPdfContent($pdf)->validate();

		return [
			'valid' => $result->hasSignatures && $result->allValid,
			'detail' => sprintf(
				'hasSignatures=%s allValid=%s entries=%d',
				$result->hasSignatures ? 'yes' : 'no',
				$result->allValid ? 'yes' : 'no',
				count($result->entries),
			),
		];
	} catch (Throwable $e) {
		return ['valid' => false, 'detail' => 'validation threw ' . get_class($e) . ': ' . $e->getMessage()];
	}
}

/**
 * Run one negative case and check where it was rejected.
 *
 * @param callable():string $attempt performs complete() and returns the PDF; must throw when rejected at completion
 * @param callable(array):array{bool, array<string,mixed>}|null $extraCheck optional deterministic assertions on the outcome
 */
function proof_case(
	string $name,
	string $expectation,
	callable $attempt,
	bool $expectRejectedAtCompletion,
	?callable $extraCheck = null,
): array {
	$outcome = ['case' => $name, 'expectation' => $expectation];
	try {
		$pdf = $attempt();
		$outcome['rejected_at_completion'] = false;
		$validation = proof_validate_pdf($pdf);
		$outcome['completion'] = 'OK (signature bytes embedded)';
		$outcome['library_validation_valid'] = $validation['valid'];
		$outcome['validation_detail'] = $validation['detail'];
		$outcome['validation'] = $validation['valid'] ? 'VALID' : 'INVALID (cryptographic check failed)';
		$outcome['rejected_at'] = $validation['valid'] ? 'NOWHERE (signature validated!)' : 'validation only';
	} catch (SignProcessException|SignerException $e) {
		$outcome['rejected_at_completion'] = true;
		$outcome['completion'] = 'REJECTED: ' . $e->getMessage();
		$outcome['rejected_at'] = 'completion';
	}

	$observed = $outcome['rejected_at_completion'] === $expectRejectedAtCompletion
		&& ($expectRejectedAtCompletion || $outcome['library_validation_valid'] === false);
	if ($extraCheck !== null) {
		[$extraOk, $extraData] = $extraCheck($outcome);
		$outcome = array_merge($outcome, $extraData);
		$observed = $observed && $extraOk;
	}
	$outcome['matched_expectation'] = $observed;

	printf(
		"  %-28s rejected at: %-16s %s\n",
		$name,
		$outcome['rejected_at'],
		$observed ? 'as expected' : 'UNEXPECTED',
	);
	if (! $observed) {
		print '    OBSERVED: ' . json_encode($outcome) . "\n";
	}

	return $outcome;
}

print "Stage 6 NEGATIVE CASES\n";
$cases = [];

$cases[] = proof_case(
	'wrong-key-signature',
	'complete() embeds it; invalid at validation only',
	function () use ($basePdf, $certificatePem, $chainPem, $otherKeyPem): string {
		$prepared = proof_prepare_fresh($basePdf, $certificatePem, $chainPem);

		return Signer::externalSigner()->complete(
			$prepared->state,
			proof_sign_digest($prepared->payload->input(), $otherKeyPem),
		);
	},
	false,
);

$cases[] = proof_case(
	'empty-signature',
	'rejected during completion',
	function () use ($basePdf, $certificatePem, $chainPem): string {
		$prepared = proof_prepare_fresh($basePdf, $certificatePem, $chainPem);

		return Signer::externalSigner()->complete($prepared->state, '');
	},
	true,
);

$cases[] = proof_case(
	'garbage-signature',
	'complete() embeds it; invalid at validation only',
	function () use ($basePdf, $certificatePem, $chainPem): string {
		$prepared = proof_prepare_fresh($basePdf, $certificatePem, $chainPem);

		return Signer::externalSigner()->complete($prepared->state, random_bytes(256));
	},
	false,
);

$cases[] = proof_case(
	'corrupted-state',
	'rejected during completion (checksum)',
	function () use ($basePdf, $certificatePem, $chainPem): string {
		$prepared = proof_prepare_fresh($basePdf, $certificatePem, $chainPem);
		$state = $prepared->state;
		// Corrupt inside the base64 unsignedPdf region so the JSON stays valid
		// and the checksum path (not JSON parsing) is what rejects it.
		$marker = strpos($state, 'unsignedPdf":"') + strlen('unsignedPdf":"');
		$char = $state[$marker];
		$state[$marker] = $char === 'A' ? 'B' : 'A';

		return Signer::externalSigner()->complete($state, random_bytes(256));
	},
	true,
);

$cases[] = proof_case(
	'tampered-state-rechecksum',
	'unkeyed checksum recompute passes complete(); invalid at validation only',
	function () use ($basePdf, $certificatePem, $chainPem, $signerKeyPem): string {
		$prepared = proof_prepare_fresh($basePdf, $certificatePem, $chainPem);
		$payload = json_decode($prepared->state, true);
		if (! is_array($payload)) {
			proof_fail('Prepared state is not JSON.');
		}
		$checksum = $payload['checksum'];
		unset($payload['checksum']);
		$attributes = base64_decode((string)$payload['signedAttributes'], true);
		$attributes[5] = $attributes[5] === "\x00" ? "\x01" : "\x00";
		$payload['signedAttributes'] = base64_encode($attributes);
		$payload['checksum'] = hash('sha256', json_encode($payload));
		if (! hash_equals($checksum, $payload['checksum'])) {
			print "    (attacker recomputed the unkeyed checksum, as expected)\n";
		}
		$tamperedState = json_encode($payload);

		return Signer::externalSigner()->complete(
			$tamperedState,
			proof_sign_digest($prepared->payload->input(), $signerKeyPem),
		);
	},
	false,
);

$cases[] = proof_case(
	'cross-lifecycle-signature',
	'signature from document A completed against document B; embeds, invalid at validation',
	function () use ($basePdf, $altPdf, $certificatePem, $chainPem, $signerKeyPem): string {
		$preparedA = proof_prepare_fresh($basePdf, $certificatePem, $chainPem);
		$preparedB = proof_prepare_fresh($altPdf, $certificatePem, $chainPem);
		$signatureForA = proof_sign_digest($preparedA->payload->input(), $signerKeyPem);

		return Signer::externalSigner()->complete($preparedB->state, $signatureForA);
	},
	false,
	function (array $outcome): array {
		// Re-run the two preparations deterministically and assert the payloads
		// differ, independent of timestamps: the documents themselves differ.
		$preparedA = proof_prepare_fresh(
			(string)file_get_contents(proof_path('rsa-base.pdf')),
			(string)file_get_contents(proof_path('rsa-cert.pem')),
			[(string)file_get_contents(proof_path('rsa-ca.pem'))],
		);
		$preparedB = proof_prepare_fresh(
			(string)file_get_contents(proof_path('rsa-alt.pdf')),
			(string)file_get_contents(proof_path('rsa-cert.pem')),
			[(string)file_get_contents(proof_path('rsa-ca.pem'))],
		);
		$distinct = $preparedA->payload->inputBase64 !== $preparedB->payload->inputBase64;

		return [
			$distinct,
			[
				'payload_a_sha256' => hash('sha256', $preparedA->payload->input()),
				'payload_b_sha256' => hash('sha256', $preparedB->payload->input()),
				'payloads_distinct' => $distinct ? 'yes (deliberately different documents)' : 'NO - case is not deterministic',
			],
		];
	},
);

$allMatched = ! in_array(false, array_column($cases, 'matched_expectation'), true);

print "\n";
foreach ($cases as $case) {
	printf(
		"  %-28s rejected_at=%-16s matched=%s\n",
		$case['case'],
		$case['rejected_at'],
		$case['matched_expectation'] ? 'yes' : 'NO',
	);
	printf(
		"    completion: %-44s validation: %s\n",
		$case['completion'],
		$case['validation'] ?? '(not reached - completion rejected)',
	);
}
print $allMatched
	? "  RESULT = PASS (all negative cases matched expectations)\n"
	: "  RESULT = FAIL\n";

exit($allMatched ? 0 : 1);
