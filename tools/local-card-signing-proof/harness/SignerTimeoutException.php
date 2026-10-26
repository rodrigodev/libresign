<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace LibreSign\Tools\LocalCardSigningProof;

/**
 * TEST-ONLY: the local signer process exceeded its timeout. Its outcome
 * is UNKNOWN — the signature may or may not have been produced. Callers
 * must never automatically retry such an operation.
 */
final class SignerTimeoutException extends SignerProtocolException {
	public function __construct(string $message) {
		parent::__construct($message, LocalSignerClient::REASON_TIMEOUT);
	}
}
