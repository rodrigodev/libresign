#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 rodrigodev
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Adversarial process fixtures for the #8356 proof tests.

Each script is a deterministic misbehaving child. They are TEST-ONLY and
are wired in through the harness client's test-only command override.
Each child writes a behavior tag to stderr so a test can confirm the
right child ran, and a unique run id is passed as argv for cleanup
verification.

Behaviors that emit a valid response read the request from stdin first
and ECHO its operationId/credentialRef, so the response passes the
harness correlation checks — the misbehavior under test is the process
behavior, not the payload. `never_reads` deliberately never reads stdin
(pipe-backpressure fixture); `ignores_sigterm` blocks immediately.
"""

import json
import os
import signal
import sys
import time

KEEP_ALIVE = {"never_reads", "ignores_sigterm", "valid_then_hangs", "continuous_stdout"}


def name():
    return os.path.basename(sys.argv[0]).replace(".py", "")


def tag(behavior):
    sys.stderr.write("adversarial-child: %s\n" % behavior)
    sys.stderr.flush()


def ignore_sigterm():
    signal.signal(signal.SIGTERM, signal.SIG_IGN)


def echo_ok():
    """Read the request and answer with a correlated valid response."""
    request = json.loads(sys.stdin.read())
    response = {
        "protocolVersion": "1",
        "operationId": request["operationId"],
        "credentialRef": request["credentialRef"],
        "signatureBase64": "AAAA",
        "signatureEncoding": "rsa-pkcs1",
    }
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


def _fill_pipes_then_valid():
    """Fill the STDERR pipe before reading the request, then complete.

    Exercises true concurrent I/O: the client must drain stderr while it
    is still transmitting a large request. 1 MiB of stderr noise is far
    above the 64 KiB pipe buffers. stdout stays reserved for the single
    protocol line, which the strict one-line contract requires.
    """
    noise = "e" * (1024 * 1024)
    sys.stderr.write(noise)
    sys.stderr.flush()
    echo_ok()


def _continuous_stderr():
    while True:
        sys.stderr.write("e" * 4096)
        sys.stderr.flush()
        time.sleep(0.02)


def _continuous():
    while True:
        sys.stdout.write("y" * 4096)
        sys.stdout.flush()
        time.sleep(0.05)


def _heavy_stderr():
    for _ in range(2000):
        sys.stderr.write("e" * 4096)
    sys.stderr.flush()
    echo_ok()


def _flood_after_response():
    echo_ok()
    sys.stdout.write("x" * (2 * 1024 * 1024))
    sys.stdout.flush()


def _delayed_second_line():
    echo_ok()
    time.sleep(1.0)
    sys.stdout.write("{}\n")
    sys.stdout.flush()


HANDLERS = {
    # Never reads stdin; sleeps forever. Used with an oversized request to
    # exercise pipe backpressure on the write side.
    "never_reads": lambda: time.sleep(3600),
    # Ignores SIGTERM; only SIGKILL can stop it.
    "ignores_sigterm": lambda: (ignore_sigterm(), time.sleep(3600)),
    # Valid correlated response line, then hangs without exiting.
    "valid_then_hangs": echo_ok,
    # Exits immediately without reading the request or writing anything.
    "exits_early": lambda: sys.exit(0),
    # Valid correlated response line, then exits nonzero.
    "nonzero_after_output": lambda: (echo_ok(), sys.exit(3)),
    # Valid response line, then a delayed second protocol line.
    "delayed_second_line": _delayed_second_line,
    # Valid response line, then floods stdout past the response limit.
    "floods_after_response": _flood_after_response,
    # Continuous stdout WITHOUT any newline, forever.
    "continuous_stdout": _continuous,
    # Continuous stderr forever (deadline checks inside the drain path).
    "continuous_stderr": _continuous_stderr,
    # Fills both pipe buffers before reading a large request, then
    # completes validly — concurrent-I/O regression fixture.
    "fills_pipes_then_valid": _fill_pipes_then_valid,
    # Heavy stderr traffic around a valid correlated response.
    "heavy_stderr": _heavy_stderr,
    # Valid correlated response and a clean exit (control case).
    "clean_exit": echo_ok,
}


def main():
    behavior = sys.argv[1] if len(sys.argv) > 1 else name()
    handler = HANDLERS.get(behavior)
    if handler is None:
        sys.stderr.write("unknown behavior %r\n" % behavior)
        sys.exit(9)
    tag(behavior)
    # Precise process-identity tracking (watchdog cleanup): the child
    # records its OWN pid in a per-run pidfile passed as argv[3]. The
    # harness uses this file instead of broad command-line matching,
    # which famously matches the checking shell itself.
    if len(sys.argv) > 3:
        with open(sys.argv[3], "w", encoding="ascii") as handle:
            handle.write(str(os.getpid()) + "\n")
    handler()
    if behavior in KEEP_ALIVE:
        time.sleep(3600)  # these behaviors must never exit on their own


if __name__ == "__main__":
    main()
