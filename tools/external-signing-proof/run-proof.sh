#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 rodrigodev
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs the full #8354 external-signing lifecycle proof:
#   RSA lifecycle across separate processes -> validate (library + openssl)
#   -> second signature on the signed PDF -> both valid
#   -> EC P-256 lifecycle -> validate
#   -> negative-case matrix
#
# Requirements: PHP >= 8.3 with ext-openssl + ext-gmp, Composer, openssl CLI.
# All artifacts are written to var/ (git-ignored). Exit code 0 = proof passed.

set -euo pipefail
cd "$(dirname "$0")"

if ! command -v php >/dev/null 2>&1; then
    echo "ERROR: php not found in PATH." >&2
    exit 1
fi

if [ ! -f vendor/autoload.php ]; then
    echo "== composer install (first run) =="
    composer install --no-interaction --no-progress
fi

echo "== Stage A: RSA lifecycle across separate processes =="
php bin/1-prepare.php rsa
php bin/2-external-sign.php rsa
php bin/3-complete.php rsa
php bin/4-validate.php rsa var/rsa-signed.pdf 1

echo
echo "== Stage B: second signature on the signed PDF, both must stay valid =="
php bin/5-second-signature.php rsa

echo
echo "== Stage C: EC P-256 lifecycle across separate processes =="
php bin/1-prepare.php ec
php bin/2-external-sign.php ec
php bin/3-complete.php ec
php bin/4-validate.php ec var/ec-signed.pdf 1

echo
echo "== Stage D: negative cases =="
php bin/6-negative-cases.php

echo
echo "PROOF PASSED: external prepare/complete lifecycle proven on RSA and EC,"
echo "double signatures survive, negative cases behave as documented."
