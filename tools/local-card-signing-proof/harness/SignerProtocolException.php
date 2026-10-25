<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace LibreSign\Tools\LocalCardSigningProof;

/**
 * TEST-ONLY protocol-level failure of the local synthetic-card signer
 * (issue #8356 local-signing proof). The signer rejected the request
 * before producing a signature, or the harness rejected its response.
 */
class SignerProtocolException extends \RuntimeException {
}
