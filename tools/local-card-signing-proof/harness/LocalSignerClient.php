<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace LibreSign\Tools\LocalCardSigningProof;

use SignerPHP\PdfSigner\Application\DTO\ExternalSigningPayload;

/**
 * Harness-side client for the local synthetic-card signer process
 * (issue #8356 local-signing proof — TEST ONLY).
 *
 * Runs the Python signer as a separate operating-system process and
 * speaks the bounded JSON request/response protocol over stdin/stdout.
 *
 * Time: ALL deadline arithmetic uses `hrtime(true)` (monotonic
 * nanoseconds). Two independently documented bounded periods exist:
 *
 * - operation timeout (`$timeoutSeconds`): covers process launch,
 *   request transmission, response collection and child shutdown. The
 *   launch call itself is not interruptible from PHP; the deadline is
 *   enforced from the first point PHP regains control.
 * - termination grace (`TERMINATION_GRACE_SECONDS`): a SECOND bounded
 *   period, used only during cleanup, between SIGTERM and SIGKILL
 *   escalation, followed by `KILL_CONFIRM_SECONDS` to confirm exit.
 *
 * I/O: ONE event loop interleaves request writes (stdin writable) and
 * output drains (stdout/stderr readable). Per-stream work is capped per
 * iteration so a continuous producer cannot starve the deadline checks
 * or the other streams. `stream_select()` errors are retried with a
 * short bounded sleep until the deadline — never a busy loop.
 *
 * The stdout contract is strict: exactly one JSON protocol line, no
 * trailing content (including delayed output), a cumulative size cap on
 * stdout and a bounded retained tail on stderr.
 *
 * Termination: required capabilities (`posix_kill`) are checked BEFORE
 * any child is launched. Cleanup is bounded and CONFIRMED: SIGTERM, a
 * bounded grace period polling for exit, SIGKILL escalation, then a
 * final bounded confirmation poll. `proc_close()` runs only after exit
 * is OBSERVED; the FIRST captured terminal status is preserved and not
 * replaced by `proc_close()`'s return. If termination cannot be
 * confirmed, this client THROWS (`REASON_TERMINATION_UNCONFIRMED`)
 * instead of blocking or claiming guaranteed cleanup; the child may
 * leak in that case and the operation stays uncertain. Limitation:
 * cleanup covers the DIRECT child only; descendants are not tracked.
 * The proof fixtures never spawn any.
 *
 * Correlation of the operation identifier and credential reference is
 * correlation data only — NOT authentication, NOT idempotency.
 *
 * This is a proof-protocol client, not a secure browser-facing service.
 * Private keys never leave the signer's git-ignored fixture directory.
 */
final class LocalSignerClient {
	public const PROTOCOL_VERSION = '1';
	public const MAX_REQUEST_BYTES = 65536;
	public const MAX_RESPONSE_BYTES = 1048576;
	public const MAX_STDERR_TAIL_BYTES = 8192;
	/** Bounded grace period between SIGTERM and SIGKILL escalation. */
	public const TERMINATION_GRACE_SECONDS = 2.0;
	/** Bounded final confirmation period after SIGKILL. */
	public const KILL_CONFIRM_SECONDS = 2.0;

	/** Stable rejection reasons for test discrimination. */
	public const REASON_REQUEST_SIZE = 'request-size';
	public const REASON_SPAWN = 'spawn';
	public const REASON_TERMINATION_UNSUPPORTED = 'termination-unsupported';
	public const REASON_TERMINATION_UNCONFIRMED = 'termination-unconfirmed';
	public const REASON_TIMEOUT = 'timeout';
	public const REASON_RESPONSE_SIZE = 'response-size';
	public const REASON_TRAILING_CONTENT = 'trailing-content';
	public const REASON_INVALID_JSON = 'invalid-json';
	public const REASON_NONZERO_EXIT = 'nonzero-exit';
	public const REASON_NO_OUTPUT = 'no-output';
	public const REASON_PROTOCOL = 'protocol';

	/** Nanoseconds per second, for hrtime(true) arithmetic. */
	private const NANOSECONDS = 1_000_000_000;
	/** Max bytes read per stream per loop iteration (starvation guard). */
	private const MAX_READ_PER_STREAM_PER_ITERATION = 262144;
	/** Max bytes written to stdin per loop iteration. */
	private const MAX_WRITE_PER_ITERATION = 262144;

	public function __construct(
		private string $pythonBinary,
		private string $signerScript,
		private ?string $fixturesDirectory = null,
		private float $timeoutSeconds = 10.0,
		/** TEST-ONLY: raised in backpressure fixtures to reach the write path. */
		private int $requestLimit = self::MAX_REQUEST_BYTES,
		/** TEST-ONLY: replaces the whole argv for adversarial child fixtures. */
		private ?\Closure $commandOverride = null,
		/** TEST-ONLY: force the termination-capability probe (null = auto-detect). */
		private ?bool $terminationSupport = null,
	) {
	}

	/**
	 * @return list<array{credentialRef: string, algorithm: string, certificatePem: string, chainPem: list<string>, certificateSha256: string}>
	 */
	public function discover(): array {
		$response = $this->exchange([], null, 'discover');
		if (! isset($response['credentials']) || ! is_array($response['credentials'])) {
			throw new SignerProtocolException('discovery response carries no credential list', self::REASON_PROTOCOL);
		}
		$credentials = [];
		foreach ($response['credentials'] as $entry) {
			if (! is_array($entry)
				|| ! isset(
					$entry['credentialRef'], $entry['algorithm'],
					$entry['certificatePem'], $entry['chainPem'],
					$entry['certificateSha256'],
				)
				|| ! is_string($entry['credentialRef'])
				|| ! is_string($entry['algorithm'])
				|| ! is_string($entry['certificatePem'])
				|| ! is_string($entry['certificateSha256'])
				|| ! is_array($entry['chainPem'])) {
				throw new SignerProtocolException('malformed credential in discovery response', self::REASON_PROTOCOL);
			}
			$chain = [];
			foreach ($entry['chainPem'] as $link) {
				if (! is_string($link)) {
					throw new SignerProtocolException('malformed chain entry in discovery response', self::REASON_PROTOCOL);
				}
				$chain[] = $link;
			}
			$credentials[] = [
				'credentialRef' => $entry['credentialRef'],
				'algorithm' => $entry['algorithm'],
				'certificatePem' => $entry['certificatePem'],
				'chainPem' => $chain,
				'certificateSha256' => $entry['certificateSha256'],
			];
		}

		return $credentials;
	}

	/**
	 * Sign one prepared operation through the separate process.
	 *
	 * @param array{scenario: string}|null $simulation
	 * @throws SignerTimeoutException when the process exceeds the deadline
	 * @throws SignerProtocolException on any protocol-level rejection
	 */
	public function signPreparedOperation(
		string $operationId,
		string $credentialRef,
		string $expectedCertificateSha256,
		ExternalSigningPayload $payload,
		?array $simulation = null,
	): SignerResponse {
		$request = [
			'protocolVersion' => self::PROTOCOL_VERSION,
			'operationId' => $operationId,
			'credentialRef' => $credentialRef,
			'expectedCertificateFingerprint' => $expectedCertificateSha256,
			'payload' => [
				'inputBase64' => $payload->inputBase64,
				'inputType' => $payload->inputType->value,
				'digestAlgorithm' => $payload->digestAlgorithm->value,
				'signatureAlgorithm' => $payload->signatureAlgorithm->value,
				'signatureEncoding' => $payload->signatureEncoding->value,
			],
		];
		if ($simulation !== null) {
			$request['simulation'] = $simulation;
		}

		$response = $this->exchange($request, $operationId, 'sign');

		if (isset($response['error'])) {
			$error = $response['error'];
			if (! is_array($error)
				|| ! isset($error['code'], $error['message'])
				|| ! is_string($error['code'])
				|| ! is_string($error['message'])) {
				throw new SignerProtocolException('malformed error object in signer response', self::REASON_PROTOCOL);
			}
			throw new SignerErrorException($error['code'], $error['message']);
		}

		if (! isset($response['signatureBase64'], $response['signatureEncoding'])
			|| ! is_string($response['signatureBase64'])
			|| ! is_string($response['signatureEncoding'])) {
			throw new SignerProtocolException('signer response carries no signature', self::REASON_PROTOCOL);
		}

		$signature = base64_decode($response['signatureBase64'], true);
		if ($signature === false || $signature === '') {
			throw new SignerProtocolException('signer response signature is not valid Base64', self::REASON_PROTOCOL);
		}

		$expectedEncoding = $payload->signatureEncoding->value;
		$encoding = $response['signatureEncoding'];
		if ($encoding === 'ecdsa-raw' && $expectedEncoding === 'ecdsa-der') {
			// The simulated middleware reports fixed-width r||s; normalize
			// to DER exactly like the future adapter must. This models an
			// ENCODING BOUNDARY only — real middleware output still needs
			// verification against the physical Citizen Card.
			$signature = self::normalizeEcdsaFixedWidthToDer($signature);
			$encoding = 'ecdsa-der';
		}
		if ($encoding !== $expectedEncoding) {
			throw new SignerProtocolException(sprintf(
				'signer returned encoding %s, prepared operation expects %s',
				$encoding,
				$expectedEncoding,
			), self::REASON_PROTOCOL);
		}

		return new SignerResponse(
			(string)$response['operationId'],
			(string)$response['credentialRef'],
			$signature,
			$encoding,
		);
	}

	/**
	 * Encode a fixed-width r||s ECDSA result as a DER SEQUENCE of two
	 * INTEGERs. Only the P-256 width (64 bytes) is accepted and a zero
	 * r or s is rejected — anything else is not a plausible signature
	 * from the simulated middleware.
	 */
	public static function normalizeEcdsaFixedWidthToDer(string $raw): string {
		if (strlen($raw) !== 64) {
			throw new SignerProtocolException(sprintf(
				'fixed-width r||s must be 64 bytes for P-256, got %d',
				strlen($raw),
			), self::REASON_PROTOCOL);
		}
		$r = self::derInteger(substr($raw, 0, 32));
		$s = self::derInteger(substr($raw, 32));
		if ($r === "\x02\x01\x00" || $s === "\x02\x01\x00") {
			throw new SignerProtocolException('fixed-width r||s carries a zero component', self::REASON_PROTOCOL);
		}

		return "\x30" . chr(strlen($r) + strlen($s)) . $r . $s;
	}

	private static function derInteger(string $value): string {
		$value = ltrim($value, "\x00");
		if ($value === '') {
			$value = "\x00";
		}
		if (ord($value[0]) >= 0x80) {
			$value = "\x00" . $value;
		}

		return "\x02" . chr(strlen($value)) . $value;
	}

	/**
	 * Termination requires a reliable SIGKILL. The capability is verified
	 * BEFORE any child is launched, so a missing facility is a clear
	 * pre-spawn rejection instead of an unbounded cleanup.
	 */
	private function terminationSupported(): bool {
		return $this->terminationSupport ?? function_exists('posix_kill');
	}

	/**
	 * Run one bounded protocol exchange.
	 *
	 * @return array<string, mixed>
	 */
	private function exchange(array $request, ?string $expectedOperationId, string $subcommand): array {
		$encoded = json_encode($request, JSON_THROW_ON_ERROR);
		if (strlen($encoded) > $this->requestLimit) {
			throw new SignerProtocolException(sprintf(
				'request is %d bytes, protocol limit is %d',
				strlen($encoded),
				$this->requestLimit,
			), self::REASON_REQUEST_SIZE);
		}

		if (! $this->terminationSupported()) {
			throw new SignerProtocolException(
				'this platform cannot provide CONFIRMED child termination'
				. ' (posix_kill unavailable); the proof refuses to launch a signer process',
				self::REASON_TERMINATION_UNSUPPORTED,
			);
		}

		// Monotonic deadline in nanoseconds, starting BEFORE launch.
		$deadlineNs = hrtime(true) + (int)round($this->timeoutSeconds * self::NANOSECONDS);

		if ($this->commandOverride !== null) {
			$command = ($this->commandOverride)($subcommand);
		} else {
			$command = array_filter([
				$this->pythonBinary,
				'-B',
				$this->signerScript,
				$this->fixturesDirectory !== null ? '--fixtures' : null,
				$this->fixturesDirectory,
				$subcommand,
			], static fn ($part): bool => $part !== null);
		}

		$process = proc_open($command, [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
		if (! is_resource($process)) {
			throw new SignerProtocolException('could not start the local signer process', self::REASON_SPAWN);
		}
		[$stdin, $stdout, $stderrPipe] = $pipes;
		stream_set_blocking($stdin, false);
		stream_set_blocking($stdout, false);
		stream_set_blocking($stderrPipe, false);

		$raw = '';
		$stderrTail = '';
		$stdinOpen = true;
		$stdinBroken = false;
		$stdinOffset = 0;
		$requestLength = strlen($encoded);
		$stdoutOpen = true;
		$stderrOpen = true;
		$exitCode = null;
		$timedOut = false;

		try {
			// ONE event loop: write request chunks when stdin is writable,
			// drain stdout/stderr while the request is still transmitting.
			// Per-stream work is capped per iteration; the monotonic
			// deadline is checked on EVERY iteration.
			while (true) {
				$status = proc_get_status($process);
				if ($status['running'] === false && $exitCode === null) {
					// The real exit code is reported only on the first
					// proc_get_status call after exit; capture it once.
					$exitCode = $status['exitcode'];
				}

				// Settle check FIRST: the empty-streams poll below must
				// never skip deadline or termination evaluation.
				$stdinSettled = ! $stdinOpen || $stdinBroken;
				if ($stdinSettled && ! $stdoutOpen && $exitCode !== null) {
					break;
				}

				$read = [];
				if ($stdoutOpen) {
					$read[] = $stdout;
				}
				if ($stderrOpen) {
					$read[] = $stderrPipe;
				}
				$write = [];
				if ($stdinOpen && ! $stdinBroken) {
					$write[] = $stdin;
				}

				if ($read === [] && $write === []) {
					// All streams settled but the child's exit has not been
					// observed yet: poll the status on a bounded sleep. The
					// monotonic deadline still applies here.
					if (hrtime(true) >= $deadlineNs) {
						$timedOut = true;
						break;
					}
					usleep(10000);
					continue;
				}

				$remainingNs = $deadlineNs - hrtime(true);
				if ($remainingNs <= 0) {
					$timedOut = true;
					break;
				}
				$selectUs = (int)min($remainingNs / 1000, 200000);
				$except = null;
				$selected = @stream_select($read, $write, $except, 0, $selectUs);
				if ($selected === false) {
					// Select error (e.g. interrupted by a signal): a short
					// bounded sleep and retry. The deadline check above
					// still applies on every iteration — never a busy loop.
					usleep(10000);
					continue;
				}

				// WRITE side: one bounded chunk per iteration. A broken
				// pipe means the child exited before consuming the
				// request; stop writing and let the drain/classification
				// below report the outcome.
				if ($write !== []) {
					$chunk = substr($encoded, $stdinOffset, self::MAX_WRITE_PER_ITERATION);
					$written = @fwrite($stdin, $chunk);
					if ($written === false || ($written === 0 && $chunk !== '')) {
						$stdinBroken = true;
						fclose($stdin);
						$stdinOpen = false;
					} else {
						$stdinOffset += $written;
						if ($stdinOffset >= $requestLength) {
							fclose($stdin);
							$stdinOpen = false;
						}
					}
				}

				// READ side: bounded work per stream per iteration.
				foreach ($read as $stream) {
					$bytesThisStream = 0;
					while ($bytesThisStream < self::MAX_READ_PER_STREAM_PER_ITERATION) {
						$chunk = @fread($stream, 65536);
						if ($chunk === false || $chunk === '') {
							break;
						}
						$bytesThisStream += strlen($chunk);
						if ($stream === $stdout) {
							$raw .= $chunk;
							if (strlen($raw) > self::MAX_RESPONSE_BYTES) {
								throw new SignerProtocolException(sprintf(
									'signer response exceeds %d cumulative bytes',
									self::MAX_RESPONSE_BYTES,
								), self::REASON_RESPONSE_SIZE);
							}
						} else {
							// Bounded diagnostic tail: keep draining,
							// retain only the documented tail length.
							$stderrTail = substr($stderrTail . $chunk, -self::MAX_STDERR_TAIL_BYTES);
						}
					}
					if (feof($stream)) {
						if ($stream === $stdout) {
							$stdoutOpen = false;
						} else {
							$stderrOpen = false;
						}
					}
				}

				$stdinSettled = ! $stdinOpen || $stdinBroken;
				if ($stdinSettled && ! $stdoutOpen && $exitCode !== null) {
					// Drain any buffered stderr remainder (bounded), then
					// settle: stdout reached EOF and the child exited.
					while ($stderrOpen) {
						$chunk = @fread($stderrPipe, 65536);
						if ($chunk === false || $chunk === '') {
							break;
						}
						$stderrTail = substr($stderrTail . $chunk, -self::MAX_STDERR_TAIL_BYTES);
						if (feof($stderrPipe)) {
							break;
						}
					}
					break;
				}
			}

			if ($stdinOpen) {
				fclose($stdin);
				$stdinOpen = false;
			}
			fclose($stdout);
			fclose($stderrPipe);

			if ($timedOut) {
				$this->terminateConfirmed($process);
				throw new SignerTimeoutException(sprintf(
					'local signer exceeded the %.1fs deadline; its outcome is UNKNOWN and the'
					. ' operation must never be retried automatically. stderr tail: %s',
					$this->timeoutSeconds,
					$this->stderrTail($stderrTail),
				));
			}

			// Reap a child whose exit was OBSERVED above. The FIRST
			// captured terminal exit code is preserved: proc_close()'s own
			// return value is unreliable once proc_get_status has consumed
			// the status, and is deliberately not used.
			proc_close($process);

			if (trim($raw) === '') {
				throw new SignerProtocolException(sprintf(
					'local signer exited with code %d and no protocol output. stderr tail: %s',
					$exitCode,
					$this->stderrTail($stderrTail),
				), self::REASON_NO_OUTPUT);
			}

			$decoded = $this->decodeSingleJsonLine($raw);

			if ($exitCode !== 0 && ! isset($decoded['error'])) {
				throw new SignerProtocolException(sprintf(
					'local signer exited with code %d after emitting a non-error protocol line'
					. '. stderr tail: %s',
					$exitCode,
					$this->stderrTail($stderrTail),
				), self::REASON_NONZERO_EXIT);
			}

			if (($decoded['protocolVersion'] ?? null) !== self::PROTOCOL_VERSION) {
				throw new SignerProtocolException('unsupported protocolVersion in signer response', self::REASON_PROTOCOL);
			}
			if ($expectedOperationId !== null) {
				$echoedOperationId = $decoded['operationId'] ?? null;
				$echoedCredentialRef = $decoded['credentialRef'] ?? null;
				if (! is_string($echoedOperationId) || ! hash_equals($expectedOperationId, $echoedOperationId)) {
					throw new SignerProtocolException(sprintf(
						'signer response correlates with operation %s, expected %s',
						var_export($echoedOperationId, true),
						var_export($expectedOperationId, true),
					), self::REASON_PROTOCOL);
				}
				if (! is_string($echoedCredentialRef) || ! hash_equals($request['credentialRef'], $echoedCredentialRef)) {
					throw new SignerProtocolException(sprintf(
						'signer response correlates with credential %s, expected %s',
						var_export($echoedCredentialRef, true),
						var_export($request['credentialRef'], true),
					), self::REASON_PROTOCOL);
				}
			}

			return $decoded;
		} catch (\Throwable $exception) {
			// Cleanup must also happen after exceptions.
			if ($stdinOpen && is_resource($stdin)) {
				fclose($stdin);
				$stdinOpen = false;
			}
			if (isset($stdout) && is_resource($stdout)) {
				fclose($stdout);
			}
			if (isset($stderrPipe) && is_resource($stderrPipe)) {
				fclose($stderrPipe);
			}
			if (is_resource($process)) {
				$this->terminateConfirmed($process);
			}
			throw $exception;
		}
	}

	/**
	 * Bounded, CONFIRMED termination of a still-running child: SIGTERM, a
	 * bounded grace period polling for exit, SIGKILL escalation, then a
	 * final bounded confirmation poll. Signal-call results are checked.
	 * proc_close() runs only after exit is OBSERVED; if exit cannot be
	 * confirmed within the bounded periods this method THROWS — it never
	 * falls back to an unbounded wait and never presents cleanup as
	 * guaranteed. Requires posix_kill (checked before launch).
	 */
	private function terminateConfirmed($process): void {
		$status = proc_get_status($process);
		if ($status['running'] === false) {
			proc_close($process);

			return;
		}
		$pid = $status['pid'];
		$graceDeadlineNs = hrtime(true) + (int)round(self::TERMINATION_GRACE_SECONDS * self::NANOSECONDS);
		$sigtermSent = @posix_kill($pid, 15); // SIGTERM
		if ($sigtermSent) {
			do {
				usleep(20000);
				$status = proc_get_status($process);
			} while ($status['running'] && hrtime(true) < $graceDeadlineNs);
		}

		if ($status['running']) {
			$killDeadlineNs = hrtime(true) + (int)round(self::KILL_CONFIRM_SECONDS * self::NANOSECONDS);
			$sigkillSent = @posix_kill($pid, 9); // SIGKILL
			if ($sigkillSent) {
				do {
					usleep(20000);
					$status = proc_get_status($process);
				} while ($status['running'] && hrtime(true) < $killDeadlineNs);
			}
		}

		if ($status['running']) {
			// Defined behavior: give up LOUDLY instead of blocking or
			// presenting cleanup as guaranteed. The child may leak; the
			// operation remains uncertain either way. The reap is still
			// attempted because PHP requires it to free the handle; the
			// thrown error documents that exit was NOT confirmed.
			proc_close($process);
			throw new SignerProtocolException(
				'could not CONFIRM the termination of the local signer child within the bounded'
				. ' grace and kill periods; the child may still be running. This is a hard'
				. ' environment failure, not a bounded cleanup guarantee.',
				self::REASON_TERMINATION_UNCONFIRMED,
			);
		}

		// Exit observed: safe to reap.
		proc_close($process);
	}

	private function stderrTail(string $stderr): string {
		$trimmed = trim($stderr);

		return $trimmed === '' ? '(empty)' : $trimmed;
	}

	/**
	 * Exactly one JSON protocol line. Additional protocol lines or
	 * trailing non-whitespace content — including content emitted after a
	 * delay — are rejected.
	 *
	 * @return array<string, mixed>
	 */
	private function decodeSingleJsonLine(string $raw): array {
		$raw = ltrim($raw, "\r\n");
		$newline = strpos($raw, "\n");
		if ($newline === false) {
			throw new SignerProtocolException(
				'signer stdout carried no complete protocol line',
				self::REASON_INVALID_JSON,
			);
		}
		$line = substr($raw, 0, $newline);
		$trailing = substr($raw, $newline + 1);
		if (trim($trailing, " \t\r\n\0") !== '') {
			throw new SignerProtocolException(
				'signer emitted content beyond the single protocol line',
				self::REASON_TRAILING_CONTENT,
			);
		}
		try {
			$decoded = json_decode($line, true, 16, JSON_THROW_ON_ERROR);
		} catch (\JsonException $exception) {
			throw new SignerProtocolException(
				'signer stdout is not valid JSON: ' . $exception->getMessage(),
				self::REASON_INVALID_JSON,
			);
		}
		if (! is_array($decoded)) {
			throw new SignerProtocolException('signer response must be a JSON object', self::REASON_INVALID_JSON);
		}

		return $decoded;
	}
}
