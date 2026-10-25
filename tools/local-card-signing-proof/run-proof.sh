#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 rodrigodev
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Reproduce the issue #8356 local-signing proof end to end.
# Usage: ./run-proof.sh <nextcloud-server-checkout-root>
set -euo pipefail

TOOL_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_ROOT="${1:?usage: run-proof.sh <nextcloud-server-checkout-root>}"
APP_DIR="$SERVER_ROOT/apps/libresign"

if [ ! -d "$APP_DIR" ]; then
	echo "No LibreSign app checkout at $APP_DIR" >&2
	exit 1
fi

# 1. Python environment
if [ ! -x "$TOOL_DIR/.venv/bin/python" ]; then
	python3 -m venv "$TOOL_DIR/.venv"
	"$TOOL_DIR/.venv/bin/pip" install 'cryptography>=42,<46'
fi

# 2. Synthetic fixtures (explicit init; keys stay in the git-ignored dir)
"$TOOL_DIR/.venv/bin/python" "$TOOL_DIR/signer/local_signer.py" init

# 3. The proof
cd "$APP_DIR"
CI=1 php -d memory_limit=1G vendor/bin/phpunit --do-not-cache-result \
	-c tests/php/phpunit.xml --testsuite integration \
	--filter LocalCardSigningProofTest
