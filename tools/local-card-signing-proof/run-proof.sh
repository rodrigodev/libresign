#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 rodrigodev
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Reproduce the issue #8356 local-signing proof end to end.
#
# Usage:
#   ./run-proof.sh <nextcloud-server-checkout-root> [apps-subdir]
#   ./run-proof.sh <path-to-libresign-app-checkout>
#
# The script resolves ONE authoritative application directory, prepares
# the Python environment and synthetic fixtures for THAT app, and runs
# the focused proof there. It fails on: wrong checkout selection, missing
# prerequisites, skipped tests, zero executed tests and PHPUnit failures.
set -euo pipefail

fail() { echo "run-proof: $*" >&2; exit 1; }

[ "$#" -ge 1 ] || fail "usage: run-proof.sh <nextcloud-server-root> [apps-subdir] | <libresign-app-path>"

CANDIDATE="$1"
APP_DIR=""

if [ -f "$CANDIDATE/lib/Service/Signature/ExternalPdfSigningService.php" ]; then
	# The argument is already the LibreSign app checkout.
	APP_DIR="$CANDIDATE"
elif [ -d "$CANDIDATE" ]; then
	# The argument is a Nextcloud server checkout; the app lives under apps/.
	SUBDIR="${2:-apps/libresign}"
	APP_DIR="$CANDIDATE/$SUBDIR"
fi

# Normalize to an ABSOLUTE PHYSICAL path BEFORE anything else is derived
# from it (tools dir, python, fixtures, exported env), and before the
# script changes directory. Relative arguments and paths with spaces are
# safe from here on; nothing depends on the caller's working directory.
[ -n "$APP_DIR" ] || fail "could not locate a LibreSign checkout at '$CANDIDATE'"
APP_DIR="$(cd "$APP_DIR" 2>/dev/null && pwd -P)" \
	|| fail "cannot resolve the app directory '$APP_DIR' to a physical path"
[ -d "$APP_DIR" ] || fail "no app directory at $APP_DIR"
[ -f "$APP_DIR/tools/local-card-signing-proof/signer/local_signer.py" ] \
	|| fail "$APP_DIR does not contain the proof (missing tools/local-card-signing-proof/signer/local_signer.py); wrong checkout?"
[ -f "$APP_DIR/lib/Service/Signature/ExternalPdfSigningService.php" ] \
	|| fail "$APP_DIR does not contain ExternalPdfSigningService.php; wrong checkout?"
[ -f "$APP_DIR/tests/php/Integration/Tools/LocalCardSigningProofTest.php" ] \
	|| fail "$APP_DIR does not contain the proof test; wrong checkout?"
[ -f "$APP_DIR/vendor/bin/phpunit" ] || fail "$APP_DIR has no vendor/bin/phpunit; run composer install first"

TOOL_DIR="$APP_DIR/tools/local-card-signing-proof"

# 1. Python environment (for THIS app checkout), from the committed
#    requirements file — no duplicated constraints.
if [ ! -x "$TOOL_DIR/.venv/bin/python" ]; then
	python3 -m venv "$TOOL_DIR/.venv"
fi
"$TOOL_DIR/.venv/bin/pip" install -q -r "$TOOL_DIR/signer/requirements.txt"

# 2. Synthetic fixtures for THIS app checkout, and export the EXACT
#    python binary the test harness must use.
"$TOOL_DIR/.venv/bin/python" "$TOOL_DIR/signer/local_signer.py" init
export LOCAL_CARD_SIGNER_PYTHON="$TOOL_DIR/.venv/bin/python"

# 3. The proof, with a machine-readable report so skips and zero-run
#    cases are detected reliably (console colors are never parsed).
REPORT="$(mktemp -t junit-8356-XXXXXX).xml"
trap 'rm -f "$REPORT"' EXIT
# Exported for test doubles (a fake phpunit can write to it); harmless
# for the real PHPUnit invocation, which receives the path explicitly.
export JUNIT_REPORT_FILE="$REPORT"

cd "$APP_DIR"
set +e
CI=1 php -d memory_limit=1G vendor/bin/phpunit \
	--do-not-cache-result \
	--no-coverage \
	-c tests/php/phpunit.xml \
	--testsuite integration \
	--filter LocalCardSigningProofTest \
	--log-junit "$REPORT"
PHPUNIT_EXIT=$?
set -e

# A dedicated proof run requires a SUCCESSFUL PHPUnit exit (0). Coverage
# collection is explicitly disabled (--no-coverage) so the local "no code
# coverage driver" warning cannot turn a green run into a nonzero exit;
# unrelated warnings and risky-test failures are NOT suppressed. The
# JUnit report below remains the gate for failures, errors, skipped
# tests and zero executed tests.
[ "$PHPUNIT_EXIT" -eq 0 ] || fail "phpunit failed with exit code $PHPUNIT_EXIT"

# The report is written locally by our own PHPUnit run, not untrusted
# input; the stdlib parser never expands external entities and this file
# contains no entity definitions, so the default parser is safe here.
python3 - "$REPORT" <<'EOF'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
tests = sum(int(s.get("tests", "0")) for s in suites)
skipped = sum(int(s.get("skipped", "0")) for s in suites)
failures = sum(int(s.get("failures", "0")) for s in suites)
errors = sum(int(s.get("errors", "0")) for s in suites)
print(f"junit: tests={tests} skipped={skipped} failures={failures} errors={errors}")
if tests == 0:
    sys.exit("FAIL: the focused proof executed zero tests (wrong checkout or filter?)")
if skipped:
    sys.exit(f"FAIL: {skipped} proof test(s) were skipped; the dedicated proof run must execute everything")
if failures or errors:
    sys.exit("FAIL: proof tests reported failures/errors")
EOF

echo "run-proof: OK"
