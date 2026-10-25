<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Libresign\Tests\Integration\Tools;

/**
 * TEST-ONLY operation record for the #8356 local-card-signing proof.
 *
 * The proof protocol's operation identifier is correlation data, not
 * authentication and not provider-side idempotency, so duplicate
 * handling lives in this harness record — NOT in production persistence.
 *
 * Guarantees implemented here:
 * - an operation that already completed is never completed again;
 * - an operation with an UNCERTAIN outcome (signer timeout or process
 *   death while a signature may exist) is never retried automatically.
 */
final class ProofOperationRecord {
	public const STATE_PREPARED = 'prepared';
	public const STATE_SENT = 'sent';
	public const STATE_COMPLETED = 'completed';
	public const STATE_UNCERTAIN = 'uncertain';

	private string $state = self::STATE_PREPARED;

	public function __construct(
		public readonly string $operationId,
		public readonly string $credentialRef,
	) {
	}

	public function getState(): string {
		return $this->state;
	}

	public function markSent(): void {
		if ($this->state !== self::STATE_PREPARED) {
			throw new \LogicException("operation {$this->operationId} is in state {$this->state}; it must not be sent again");
		}
		$this->state = self::STATE_SENT;
	}

	public function markCompleted(): void {
		if ($this->state !== self::STATE_SENT) {
			throw new \LogicException("operation {$this->operationId} is in state {$this->state}");
		}
		$this->state = self::STATE_COMPLETED;
	}

	public function markUncertain(): void {
		if ($this->state !== self::STATE_SENT) {
			throw new \LogicException("operation {$this->operationId} is in state {$this->state}");
		}
		$this->state = self::STATE_UNCERTAIN;
	}
}
