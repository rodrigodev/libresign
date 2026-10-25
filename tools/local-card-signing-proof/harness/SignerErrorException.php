<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace LibreSign\Tools\LocalCardSigningProof;

/**
 * TEST-ONLY: the local signer reported a protocol-level error (missing
 * reader, user cancellation, PIN rejection, blocked credential, invalid
 * request, fingerprint mismatch, ...). No signature was produced.
 */
final class SignerErrorException extends SignerProtocolException {
	public function __construct(
		public readonly string $errorCode,
		string $message,
	) {
		parent::__construct(sprintf('[%s] %s', $errorCode, $message));
	}
}
