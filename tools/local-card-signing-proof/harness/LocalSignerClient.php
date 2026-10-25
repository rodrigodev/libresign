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
 * - request-size and response-size limits;
 * - per-invocation process timeouts (the child is killed on expiry);
 * - strict response shape validation;
 * - correlation of the operation identifier and credential reference
 *   (correlation data only — NOT authentication, NOT idempotency);
 * - normalization of the simulated fixed-width r||s ECDSA output to DER.
 *
 * This is a proof-protocol client, not a secure browser-facing service.
 * Private keys never leave the signer's git-ignored fixture directory.
 */
final class LocalSignerClient {
	public const PROTOCOL_VERSION = '1';
	public const MAX_REQUEST_BYTES = 65536;
	public const MAX_RESPONSE_BYTES = 1048576;

	public function __construct(
		private string $pythonBinary,
		private string $signerScript,
		private ?string $fixturesDirectory = null,
		private float $timeoutSeconds = 10.0,
	) {
	}

	/**
	 * @return list<array{credentialRef: string, algorithm: string, certificatePem: string, chainPem: list<string>, certificateSha256: string}>
	 */
	public function discover(): array {
		$response = $this->exchange([], null, 'discover');
		if (! isset($response['credentials']) || ! is_array($response['credentials'])) {
			throw new SignerProtocolException('discovery response carries no credential list');
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
				throw new SignerProtocolException('malformed credential in discovery response');
			}
			$chain = [];
			foreach ($entry['chainPem'] as $link) {
				if (! is_string($link)) {
					throw new SignerProtocolException('malformed chain entry in discovery response');
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
	 * @throws SignerTimeoutException when the process exceeds the timeout
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
				throw new SignerProtocolException('malformed error object in signer response');
			}
			throw new SignerErrorException($error['code'], $error['message']);
		}

		if (! isset($response['signatureBase64'], $response['signatureEncoding'])
			|| ! is_string($response['signatureBase64'])
			|| ! is_string($response['signatureEncoding'])) {
			throw new SignerProtocolException('signer response carries no signature');
		}

		$signature = base64_decode($response['signatureBase64'], true);
		if ($signature === false || $signature === '') {
			throw new SignerProtocolException('signer response signature is not valid Base64');
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
			));
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
			));
		}
		$r = self::derInteger(substr($raw, 0, 32));
		$s = self::derInteger(substr($raw, 32));
		if (preg_match('/^\x02\x01\x00$/', $r) || preg_match('/^\x02\x01\x00$/', $s)) {
			throw new SignerProtocolException('fixed-width r||s carries a zero component');
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
	 * Run one protocol exchange: bounded request on stdin, bounded single
	 * JSON object on stdout, diagnostics on stderr, hard timeout.
	 *
	 * @return array<string, mixed>
	 */
	private function exchange(array $request, ?string $expectedOperationId, string $subcommand): array {
		$encoded = json_encode($request, JSON_THROW_ON_ERROR);
		if (strlen($encoded) > self::MAX_REQUEST_BYTES) {
			throw new SignerProtocolException(sprintf(
				'request is %d bytes, protocol limit is %d',
				strlen($encoded),
				self::MAX_REQUEST_BYTES,
			));
		}

		$command = array_filter([
			$this->pythonBinary,
			'-B',
			$this->signerScript,
			$this->fixturesDirectory !== null ? '--fixtures' : null,
			$this->fixturesDirectory,
			$subcommand,
		], static fn ($part): bool => $part !== null);

		$process = proc_open(
			$command,
			[['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']],
			$pipes,
		);
		if (! is_resource($process)) {
			throw new SignerProtocolException('could not start the local signer process');
		}
		fwrite($pipes[0], $encoded);
		fclose($pipes[0]);
		stream_set_blocking($pipes[1], false);
		stream_set_blocking($pipes[2], false);

		$start = microtime(true);
		$raw = '';
		$stderr = '';
		$timedOut = false;
		while (true) {
			$status = proc_get_status($process);
			$chunk = fread($pipes[1], 8192);
			if ($chunk === false || $chunk === '') {
				$stderrChunk = fread($pipes[2], 8192);
				if (is_string($stderrChunk) && $stderrChunk !== '') {
					$stderr .= $stderrChunk;
				}
				if (! $status['running']) {
					break;
				}
				if ((microtime(true) - $start) > $this->timeoutSeconds) {
					$timedOut = true;
					break;
				}
				usleep(10000);
				continue;
			}
			$raw .= $chunk;
			if (strlen($raw) > self::MAX_RESPONSE_BYTES) {
				fclose($pipes[1]);
				$this->terminateProcess($process, $pipes);
				throw new SignerProtocolException(sprintf(
					'signer response exceeds %d bytes',
					self::MAX_RESPONSE_BYTES,
				));
			}
			if (str_contains($raw, "\n")) {
				break;
			}
		}

		// The timeout holds until the process has EXITED, not just until
		// output arrived: a child that emits a response line and then
		// refuses to exit is still an uncertain outcome.
		if (! $timedOut) {
			while (true) {
				$status = proc_get_status($process);
				if (! $status['running']) {
					break;
				}
				if ((microtime(true) - $start) > $this->timeoutSeconds) {
					$timedOut = true;
					break;
				}
				$stderrChunk = fread($pipes[2], 8192);
				if (is_string($stderrChunk) && $stderrChunk !== '') {
					$stderr .= $stderrChunk;
				}
				usleep(10000);
			}
		}

		fclose($pipes[1]);
		$remainingStderr = stream_get_contents($pipes[2]);
		if (is_string($remainingStderr)) {
			$stderr .= $remainingStderr;
		}
		fclose($pipes[2]);

		if ($timedOut) {
			proc_terminate($process);
			proc_close($process);
			throw new SignerTimeoutException(sprintf(
				'local signer exceeded the %.1fs timeout; its outcome is UNKNOWN and the'
				. ' operation must never be retried automatically. stderr: %s',
				$this->timeoutSeconds,
				$this->stderrTail($stderr),
			));
		}
		$exitCode = proc_close($process);
		if ($exitCode !== 0 && $raw === '') {
			throw new SignerProtocolException(sprintf(
				'local signer exited with code %d and no protocol output. stderr: %s',
				$exitCode,
				$this->stderrTail($stderr),
			));
		}
		$decoded = $this->decodeSingleJsonLine($raw);
		if ($exitCode !== 0 && ! isset($decoded['error'])) {
			throw new SignerProtocolException(sprintf(
				'local signer exited with code %d after emitting a non-error protocol line',
				$exitCode,
			));
		}

		if (($decoded['protocolVersion'] ?? null) !== self::PROTOCOL_VERSION) {
			throw new SignerProtocolException('unsupported protocolVersion in signer response');
		}
		if ($expectedOperationId !== null) {
			$echoedOperationId = $decoded['operationId'] ?? null;
			$echoedCredentialRef = $decoded['credentialRef'] ?? null;
			if (! is_string($echoedOperationId) || ! hash_equals($expectedOperationId, $echoedOperationId)) {
				throw new SignerProtocolException(sprintf(
					'signer response correlates with operation %s, expected %s',
					var_export($echoedOperationId, true),
					var_export($expectedOperationId, true),
				));
			}
			if (! is_string($echoedCredentialRef) || ! hash_equals($request['credentialRef'], $echoedCredentialRef)) {
				throw new SignerProtocolException(sprintf(
					'signer response correlates with credential %s, expected %s',
					var_export($echoedCredentialRef, true),
					var_export($request['credentialRef'], true),
				));
			}
		}

		return $decoded;
	}

	/**
	 * Last-chance cleanup for an unresponsive child: close every pipe and
	 * wait for proc_close without an unbounded block.
	 *
	 * @param array<int, resource> $pipes
	 */
	private function terminateProcess($process, array $pipes): void {
		foreach ($pipes as $pipe) {
			if (is_resource($pipe)) {
				fclose($pipe);
			}
		}
		proc_terminate($process);
		proc_close($process);
	}

	private function stderrTail(string $stderr): string {
		$trimmed = trim($stderr);

		return $trimmed === '' ? '(empty)' : substr($trimmed, -400);
	}

	/**
	 * @return array<string, mixed>
	 */
	private function decodeSingleJsonLine(string $raw): array {
		$lines = explode("\n", trim($raw));
		if (count($lines) !== 1 || $lines[0] === '') {
			throw new SignerProtocolException(sprintf(
				'expected exactly one protocol line on stdout, got %d',
				count($lines),
			));
		}
		try {
			$decoded = json_decode($lines[0], true, 16, JSON_THROW_ON_ERROR);
		} catch (\JsonException $exception) {
			throw new SignerProtocolException('signer stdout is not valid JSON: ' . $exception->getMessage());
		}
		if (! is_array($decoded)) {
			throw new SignerProtocolException('signer response must be a JSON object');
		}

		return $decoded;
	}
}
