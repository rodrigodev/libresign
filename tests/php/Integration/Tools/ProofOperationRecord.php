<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Libresign\Tests\Integration\Tools;

use LibreSign\Tools\LocalCardSigningProof\SignerErrorException;
use LibreSign\Tools\LocalCardSigningProof\SignerProtocolException;
use LibreSign\Tools\LocalCardSigningProof\SignerResponse;
use LibreSign\Tools\LocalCardSigningProof\SignerTimeoutException;

/**
 * TEST-ONLY operation coordinator for the #8356 local-card-signing proof.
 *
 * The proof protocol's operation identifier is correlation data, not
 * authentication and not provider-side idempotency, so duplicate and
 * uncertainty handling lives in this harness coordinator — NOT in
 * production persistence.
 *
 * States and the conservative transitions the coordinator applies
 * AUTOMATICALLY (tests never mark outcomes by hand):
 *
 * - PREPARED → SENT: the request was submitted to the signer process.
 * - Explicit simulated PRE-SIGN rejection (the signer's documented
 *   validation runs entirely BEFORE key access, so these codes prove no
 *   signature was produced): → REJECTED. The operation is closed.
 * - Everything else observed after submission — unusable response, crash,
 *   timeout or correlation failure — is a POTENTIALLY UNCERTAIN outcome
 *   (the signer may have used the key): → UNCERTAIN. Never resent.
 *   Diagnostics in those errors are useful but are NOT proof that signing
 *   did not occur.
 * - SENT → COMPLETED only through completeWith(): the completion callback
 *   is invoked at most once per operation, and a second completion is
 *   refused BEFORE the callback is invoked.
 * - A completion callback failure → FAILED (the operation is closed; its
 *   bytes were never validated, so nothing is returned or published).
 */
final class ProofOperationRecord {
	public const STATE_PREPARED = 'prepared';
	public const STATE_SENT = 'sent';
	public const STATE_COMPLETED = 'completed';
	public const STATE_UNCERTAIN = 'uncertain';
	public const STATE_REJECTED = 'rejected';
	public const STATE_FAILED = 'failed';

	/**
	 * Signer error codes whose DOCUMENTED simulator behavior rejects the
	 * request entirely before any key access. Anything else observed
	 * after submission is treated as potentially uncertain.
	 */
	private const PRE_SIGN_REJECTION_CODES = [
		'no-reader',
		'cancelled',
		'pin-rejected',
		'pin-blocked',
		'credential-not-found',
		'fingerprint-mismatch',
		'invalid-request',
		'invalid-digest',
		'unsupported-protocol',
		'unsupported-input-type',
		'unsupported-algorithm',
		'unsupported-encoding',
		'unexpected-parameter',
		'oversized-request',
	];

	private string $state = self::STATE_PREPARED;
	private int $completionInvocations = 0;

	public function __construct(
		public readonly string $operationId,
		public readonly string $credentialRef,
	) {
	}

	public function getState(): string {
		return $this->state;
	}

	public function getCompletionInvocations(): int {
		return $this->completionInvocations;
	}

	/**
	 * Submit one signing request through the given callable and apply the
	 * conservative outcome transitions automatically. The callable must
	 * invoke the signer process exactly once.
	 *
	 * @param callable(): SignerResponse $submit
	 * @throws SignerErrorException on a documented pre-sign rejection
	 * @throws SignerProtocolException on an uncertain outcome after submission
	 */
	public function submit(callable $submit): SignerResponse {
		if ($this->state !== self::STATE_PREPARED) {
			throw new \LogicException(sprintf(
				'operation %s is in state %s; it must not be submitted again',
				$this->operationId,
				$this->state,
			));
		}
		$this->state = self::STATE_SENT;
		try {
			return $submit();
		} catch (SignerErrorException $error) {
			if (in_array($error->errorCode, self::PRE_SIGN_REJECTION_CODES, true)) {
				// Documented pre-sign rejection: the simulator validated the
				// request before any key access, so no signature can exist.
				$this->state = self::STATE_REJECTED;
			} else {
				// Unknown error code after submission: potentially uncertain.
				$this->state = self::STATE_UNCERTAIN;
			}
			throw $error;
		} catch (SignerTimeoutException|SignerProtocolException $protocolFailure) {
			// Unusable response, crash or correlation failure after
			// submission: the signer may already have used the key.
			// Potentially uncertain; never resent.
			$this->state = self::STATE_UNCERTAIN;
			throw $protocolFailure;
		}
	}

	/**
	 * Complete through the given callable (the real completion service).
	 * The callback is invoked at most once per operation; a second
	 * completion attempt is refused BEFORE the callback runs. A callback
	 * failure marks the operation FAILED: its bytes were never validated.
	 *
	 * @param callable(): string $complete
	 * @return string the validated completed PDF bytes
	 */
	public function completeWith(callable $complete): string {
		if ($this->state !== self::STATE_SENT) {
			throw new \LogicException(sprintf(
				'operation %s is in state %s; completion is only permitted for a submitted operation'
				. ' whose signature was accepted by the protocol',
				$this->operationId,
				$this->state,
			));
		}
		$this->completionInvocations++;
		try {
			$completed = $complete();
		} catch (\Throwable $failure) {
			// Completion rejected the bytes (or failed): the operation is
			// closed. Its result is never returned or published.
			$this->state = self::STATE_FAILED;
			throw $failure;
		}
		$this->state = self::STATE_COMPLETED;

		return $completed;
	}
}
