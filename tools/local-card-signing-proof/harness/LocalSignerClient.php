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
 * Runs the Python signer as a separate operating-system process, speaks
 * the bounded JSON request/response protocol over stdin/stdout and
 * enforces, on the harness side:
 *
 * - a monotonic deadline that starts before process launch and governs
 *   request transmission, response collection and child shutdown. The
 *   launch call itself is not interruptible by PHP; the deadline is
 *   enforced from the first point PHP regains control;
 * - nonblocking stdin/stdout/stderr with partial-write handling and
 *   concurrent draining (no pipe-buffer deadlocks);
 * - request-size and cumulative response-size limits;
 * - a strict stdout contract: exactly one JSON protocol line, no
 *   trailing content, including content emitted after a delay;
 * - bounded stderr retention (diagnostic tail only) while draining;
 * - explicit handling of EOF, early child exit and broken pipes;
 * - bounded cleanup: stdin closed, SIGTERM, bounded grace period while
 *   draining, escalation to SIGKILL when the platform supports it, then
 *   reap. proc_close() is only called once the child is confirmed
 *   exited or SIGKILLed, so it cannot wait indefinitely. Cleanup also
 *   runs after exceptions.
 *
 * Limitation: cleanup guarantees cover the direct child only. If a child
 * spawns descendants that outlive it, this client does not track or kill
 * them. The proof's fixtures never spawn descendants.
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

	/** Stable rejection reasons for test discrimination. */
	public const REASON_REQUEST_SIZE = 'request-size';
	public const REASON_SPAWN = 'spawn';
	public const REASON_TIMEOUT = 'timeout';
	public const REASON_RESPONSE_SIZE = 'response-size';
	public const REASON_TRAILING_CONTENT = 'trailing-content';
	public const REASON_INVALID_JSON = 'invalid-json';
	public const REASON_NONZERO_EXIT = 'nonzero-exit';
	public const REASON_NO_OUTPUT = 'no-output';
	public const REASON_PROTOCOL = 'protocol';

	public function __construct(
		private string $pythonBinary,
		private string $signerScript,
		private ?string $fixturesDirectory = null,
		private float $timeoutSeconds = 10.0,
		/** TEST-ONLY: raised in backpressure fixtures to reach the write path. */
		private int $requestLimit = self::MAX_REQUEST_BYTES,
		/** TEST-ONLY: replaces the whole argv for adversarial child fixtures. */
		private ?\Closure $commandOverride = null,
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

		// Monotonic deadline. It starts BEFORE launch and covers request
		// transmission, response collection and child shutdown. proc_open
		// itself is not interruptible from PHP; no claim is made otherwise.
		$deadline = microtime(true) + $this->timeoutSeconds;

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

		try {
			// Write the request fully before closing stdin. Partial writes
			// are retried against the deadline; a broken pipe (child exited
			// before consuming the request) is tolerated here and the
			// resulting EOF/exit is classified below.
			$this->writeAll($stdin, $encoded, $deadline);
			fclose($stdin);
			$stdinOpen = false;

			// Drain stdout AND stderr concurrently until stdout reaches EOF
			// and the child exits. This avoids pipe-buffer deadlocks even
			// when a child floods stderr or keeps writing after responding.
			$stdoutOpen = true;
			$stderrOpen = true;
			$exitCode = null;
			$timedOut = false;
			while (true) {
				$status = proc_get_status($process);
				if ($status['running'] === false && $exitCode === null) {
					// The real exit code is reported only on the first
					// proc_get_status call after exit; capture it once.
					$exitCode = $status['exitcode'];
				}

				$read = [];
				if ($stdoutOpen) {
					$read[] = $stdout;
				}
				if ($stderrOpen) {
					$read[] = $stderrPipe;
				}
				if ($read !== []) {
					$remainingUs = (int)max(0, ($deadline - microtime(true)) * 1e6);
					$except = null;
					$write = null;
					$selected = @stream_select($read, $write, $except, 0, min($remainingUs, 200000));
					if ($selected === false) {
						// Interrupted (e.g. by a signal): retry until deadline.
					} elseif ($selected > 0) {
						foreach ($read as $stream) {
							while (true) {
								$chunk = @fread($stream, 65536);
								if ($chunk === false || $chunk === '') {
									break;
								}
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
					}
				}

				if (! $stdoutOpen && $exitCode !== null) {
					// stdout at EOF and child exited: drain any buffered
					// remainder of stderr, then settle.
					if ($stderrOpen) {
						while (true) {
							$chunk = @fread($stderrPipe, 65536);
							if ($chunk === false || $chunk === '') {
								break;
							}
							$stderrTail = substr($stderrTail . $chunk, -self::MAX_STDERR_TAIL_BYTES);
						}
					}
					break;
				}
				if (microtime(true) >= $deadline) {
					$timedOut = true;
					break;
				}
			}

			if ($stdinOpen) {
				fclose($stdin);
			}
			fclose($stdout);
			fclose($stderrPipe);

			if ($timedOut) {
				$this->terminateBounded($process);
				throw new SignerTimeoutException(sprintf(
					'local signer exceeded the %.1fs deadline; its outcome is UNKNOWN and the'
					. ' operation must never be retried automatically. stderr tail: %s',
					$this->timeoutSeconds,
					$this->stderrTail($stderrTail),
				));
			}

			// Reap a confirmed-exited child: proc_close cannot block here.
			$exitCode = proc_close($process);

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
			if ($stdinOpen) {
				fclose($stdin);
			}
			if (is_resource($stdout)) {
				fclose($stdout);
			}
			if (is_resource($stderrPipe)) {
				fclose($stderrPipe);
			}
			if (is_resource($process)) {
				$this->terminateBounded($process);
			}
			throw $exception;
		}
	}

	/**
	 * Write the whole buffer to a nonblocking pipe, handling partial
	 * writes, until the deadline. A broken pipe (the child exited before
	 * reading everything) returns silently; the child's exit is classified
	 * by the drain loop.
	 */
	private function writeAll($stream, string $buffer, float $deadline): void {
		$offset = 0;
		$length = strlen($buffer);
		while ($offset < $length) {
			$written = @fwrite($stream, substr($buffer, $offset));
			if ($written === false || $written === 0) {
				if (microtime(true) >= $deadline) {
					throw new SignerTimeoutException(sprintf(
						'could not transmit the request within the %.1fs deadline (pipe backpressure);'
						. ' its outcome is UNKNOWN and the operation must never be retried automatically',
						$this->timeoutSeconds,
					));
				}
				usleep(10000);
				continue;
			}
			$offset += $written;
		}
	}

	/**
	 * Bounded termination: request termination, allow a short bounded
	 * grace period, escalate to SIGKILL when the platform supports it,
	 * then reap. Never calls proc_close() while the child may still run
	 * unbounded.
	 */
	private function terminateBounded($process): void {
		$status = proc_get_status($process);
		if ($status['running'] === false) {
			proc_close($process);

			return;
		}
		proc_terminate($process);
		$graceEnd = microtime(true) + self::TERMINATION_GRACE_SECONDS;
		do {
			usleep(50000);
			$status = proc_get_status($process);
		} while ($status['running'] && microtime(true) < $graceEnd);
		if ($status['running']) {
			if (function_exists('posix_kill')) {
				posix_kill($status['pid'], 9); // SIGKILL — unconditional
				usleep(100000);
			} else {
				// Platform without SIGKILL support: one further bounded
				// wait, then give up on liveness confirmation. proc_close
				// may still block in that unsupported environment; the
				// proof targets macOS/Linux where posix_kill exists.
				$hardEnd = microtime(true) + self::TERMINATION_GRACE_SECONDS;
				do {
					usleep(50000);
					$status = proc_get_status($process);
				} while ($status['running'] && microtime(true) < $hardEnd);
			}
		}
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
