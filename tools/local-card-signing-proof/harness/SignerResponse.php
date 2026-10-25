<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace LibreSign\Tools\LocalCardSigningProof;

/**
 * TEST-ONLY: one validated signer result. Carries the operation and
 * credential correlation data echoed by the signer plus the raw
 * signature bytes in the encoding the completion service expects.
 */
final class SignerResponse {
	public function __construct(
		public readonly string $operationId,
		public readonly string $credentialRef,
		public readonly string $signature,
		public readonly string $signatureEncoding,
	) {
	}
}
