<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Libresign\Tests\Integration\Tools;

use LibreSign\Tools\LocalCardSigningProof\LocalSignerClient;
use LibreSign\Tools\LocalCardSigningProof\SignerErrorException;
use LibreSign\Tools\LocalCardSigningProof\SignerProtocolException;
use LibreSign\Tools\LocalCardSigningProof\SignerTimeoutException;
use OCA\Libresign\Handler\DocMdpHandler;
use OCA\Libresign\Service\Signature\Exception\ExternalSigningException;
use OCA\Libresign\Service\Signature\ExternalPdfSigningService;
use OCA\Libresign\Service\Signature\PdfSignatureValidationService;
use OCA\Libresign\Tests\Integration\TestCase;
use OCP\ITempManager;
use Psr\Log\LoggerInterface;
use SignerPHP\PdfSigner\Application\DTO\ExternalSigningPayload;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\PdfContentDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureActorDto;
use SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureEncoding;
use SignerPHP\PdfSigner\Application\DTO\SignatureMetadataDto;
use SignerPHP\PdfSigner\Application\DTO\SigningCertificateDto;
use SignerPHP\PdfSigner\Application\DTO\SigningContextDto;
use SignerPHP\PdfSigner\Application\DTO\SigningInputType;
use SignerPHP\PdfSigner\Application\DTO\SigningOptionsDto;

/**
 * Local-signing proof for issue #8356: a synthetic "Citizen Card" as a
 * separate local signer process.
 *
 * WHAT IS REAL: LibreSign's ExternalPdfSigningService (prepare AND
 * complete, including its validation layer), the signerphp/pdf-signer
 * payload (a pre-hashed SHA-256 digest of CMS signed attributes), real
 * RSA PKCS#1 v1.5 and ECDSA P-256 signatures produced with prehashed
 * APIs in a separate operating-system process, independent OpenSSL CMS
 * verification, and completion in a fresh PHP process.
 *
 * WHAT IS SIMULATED: the Portuguese Citizen Card itself, its reader, its
 * dialogs and the Autenticacao.gov middleware. The synthetic certificates
 * are TEST identities, not Portuguese government certificates. This proof
 * does NOT establish compatibility with the physical Citizen Card.
 *
 * Outcome classification (applied automatically by ProofOperationRecord):
 * - a documented PRE-SIGN rejection (validated before key access) closes
 *   the operation as REJECTED — no signature can exist;
 * - ANY unusable response, crash, timeout or correlation failure observed
 *   AFTER submission is UNCERTAIN: the signer may have used the key. The
 *   operation is never resent. Protocol diagnostics do not prove that
 *   signing did not occur;
 * - cryptographic validation failure at completion closes the operation
 *   as FAILED: no bytes are returned or published.
 *
 * The makePdf/extractSignatures/openssl-verification helpers are
 * deliberately copied from ExternalPdfSigningServiceTest so that the
 * existing test's behavior stays untouched.
 *
 * @group tools
 */
final class LocalCardSigningProofTest extends TestCase {
	private ExternalPdfSigningService $service;
	private ITempManager $tempManager;
	private string $toolsDirectory;
	private string $fixturesDirectory;
	private string $adversarialScript;
	private ?array $credentials = null;
	/** Independent outer timeout (seconds) for adversarial process tests. */
	private const OUTER_TIMEOUT_SECONDS = 20;

	#[\Override]
	public function setUp(): void {
		$appConfig = $this->getMockAppConfigWithReset();
		$l10n = \OCP\Server::get(\OCP\L10N\IFactory::class)->get(\OCA\LibreSign\AppInfo\Application::APP_ID);
		$this->service = new ExternalPdfSigningService(
			new PdfSignatureValidationService(
				$appConfig,
				$l10n,
				\OCP\Server::get(LoggerInterface::class),
			),
			new DocMdpHandler($l10n),
		);
		$this->tempManager = \OCP\Server::get(ITempManager::class);
		$this->toolsDirectory = dirname(__DIR__, 4) . '/tools/local-card-signing-proof';
		$this->fixturesDirectory = $this->toolsDirectory . '/fixtures';
		$this->adversarialScript = $this->toolsDirectory . '/signer/adversarial_children.py';

		// The proof harness lives under tools/ by design (isolation from
		// production code); it is NOT part of the composer autoload map,
		// so load it explicitly and read-only.
		foreach ([
			'SignerProtocolException',
			'SignerTimeoutException',
			'SignerErrorException',
			'SignerResponse',
			'LocalSignerClient',
		] as $harnessClass) {
			require_once $this->toolsDirectory . '/harness/' . $harnessClass . '.php';
		}

		$this->requirePythonEnvironment();
	}

	/**
	 * Skip explicitly (reported as skips) when the Python environment is
	 * unavailable. Fixtures are created per run through the explicit init
	 * step; private keys stay in the git-ignored fixtures directory and
	 * never enter this harness.
	 */
	private function requirePythonEnvironment(): void {
		if (! is_file($this->toolsDirectory . '/signer/local_signer.py')) {
			$this->markTestSkipped('Local signer script not found under tools/.');
		}
		if (! is_file($this->pythonBinary())) {
			$this->markTestSkipped(
				'Python environment for the local signer not found. Run:'
				. ' python3 -m venv .venv && .venv/bin/pip install -r signer/requirements.txt'
				. ' inside tools/local-card-signing-proof/',
			);
		}
	}

	private function pythonBinary(): string {
		$configured = getenv('LOCAL_CARD_SIGNER_PYTHON');
		if ($configured !== false && $configured !== '') {
			return $configured;
		}

		return $this->toolsDirectory . '/.venv/bin/python';
	}

	private function client(float $timeoutSeconds = 10.0): LocalSignerClient {
		return new LocalSignerClient(
			$this->pythonBinary(),
			$this->toolsDirectory . '/signer/local_signer.py',
			$this->fixturesDirectory,
			$timeoutSeconds,
		);
	}

	/**
	 * Explicit fixture initialization step: the signer generates the
	 * synthetic CA and leaves. Re-running it replaces the "card".
	 */
	private function initFixtures(): void {
		exec(
			escapeshellarg($this->pythonBinary()) . ' -B '
			. escapeshellarg($this->toolsDirectory . '/signer/local_signer.py')
			. ' --fixtures ' . escapeshellarg($this->fixturesDirectory) . ' init 2>&1',
			$outputLines,
			$exitCode,
		);
		$this->assertSame(0, $exitCode, "signer init failed:\n" . implode("\n", $outputLines));
		$this->credentials = null;
	}

	private function ensureFixtures(): void {
		if (! is_file($this->fixturesDirectory . '/credentials.json')) {
			$this->initFixtures();
		}
	}

	/**
	 * @return list<array{credentialRef: string, algorithm: string, certificatePem: string, chainPem: list<string>, certificateSha256: string}>
	 */
	private function discover(): array {
		$this->ensureFixtures();
		if ($this->credentials === null) {
			$this->credentials = $this->client()->discover();
			$this->assertCount(2, $this->credentials, 'expected the RSA and the EC synthetic credential');
		}

		return $this->credentials;
	}

	private function credentialByRef(string $credentialRef): array {
		foreach ($this->discover() as $credential) {
			if ($credential['credentialRef'] === $credentialRef) {
				return $credential;
			}
		}
		throw new \RuntimeException('unknown credential ' . $credentialRef);
	}

	/**
	 * Full positive lifecycle through REAL services and a REAL subprocess:
	 * discovery -> prepare -> external signature (via the coordinator,
	 * which applies outcome transitions automatically) -> correlation.
	 *
	 * @return array{record: ProofOperationRecord, prepared: \OCA\Libresign\Service\Signature\PreparedExternalOperation, credential: array, signedBySigner: \LibreSign\Tools\LocalCardSigningProof\SignerResponse}
	 */
	private function runLifecycle(string $credentialRef, string $pdf, ?array $simulation = null): array {
		$client = $this->client();
		$credential = $this->credentialByRef($credentialRef);

		$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
		$record = new ProofOperationRecord('proof-op-' . uniqid(), $credentialRef);

		$signedBySigner = $record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
			$record->operationId,
			$credentialRef,
			$credential['certificateSha256'],
			$prepared->upstream->payload,
			$simulation,
		));
		$this->assertSame($record->operationId, $signedBySigner->operationId);
		$this->assertSame($credentialRef, $signedBySigner->credentialRef);

		return [
			'record' => $record,
			'prepared' => $prepared,
			'credential' => $credential,
			'signedBySigner' => $signedBySigner,
		];
	}

	/**
	 * Guarded completion through the coordinator: the real completion
	 * service runs inside completeWith(), so a second attempt is refused
	 * BEFORE the service is invoked again.
	 */
	private function completeGuarded(array $lifecycle, string $pdf): string {
		return $lifecycle['record']->completeWith(fn (): string => $this->service->complete(
			$lifecycle['prepared'],
			$lifecycle['signedBySigner']->signature,
			$pdf,
			$lifecycle['credential']['certificatePem'],
		));
	}

	public function testRsaLifecycleThroughLocalSignerProcess(): void {
		$pdf = $this->makePdf('Local card proof, RSA lifecycle');
		$lifecycle = $this->runLifecycle('synthetic-rsa-leaf', $pdf);
		$this->assertSame('rsa-pkcs1', $lifecycle['signedBySigner']->signatureEncoding);

		$completed = $this->completeGuarded($lifecycle, $pdf);
		$this->assertSame(ProofOperationRecord::STATE_COMPLETED, $lifecycle['record']->getState());
		$this->assertSame(1, $lifecycle['record']->getCompletionInvocations());

		$signatures = $this->extractSignatures($completed);
		$this->assertCount(1, $signatures);
		$this->assertTrue(
			$this->independentOpensslVerify($signatures[0]['cms'], $signatures[0]['content']),
			'the completed document must carry a cryptographically valid CMS signature',
		);
	}

	public function testEcLifecycleWithFixedWidthRsNormalization(): void {
		$pdf = $this->makePdf('Local card proof, EC P-256 lifecycle');
		$lifecycle = $this->runLifecycle('synthetic-ec-leaf', $pdf);

		// The signer reports the simulated card output (fixed-width r||s).
		$this->assertSame('ecdsa-der', $lifecycle['signedBySigner']->signatureEncoding);
		$der = $lifecycle['signedBySigner']->signature;
		$this->assertSame(0x30, ord($der[0]), 'the harness must normalize r||s to DER before completion');

		$completed = $this->completeGuarded($lifecycle, $pdf);
		$this->assertSame(ProofOperationRecord::STATE_COMPLETED, $lifecycle['record']->getState());

		$signatures = $this->extractSignatures($completed);
		$this->assertCount(1, $signatures);
		$this->assertTrue(
			$this->independentOpensslVerify($signatures[0]['cms'], $signatures[0]['content']),
			'the EC signature must validate after the encoding-boundary normalization',
		);
	}

	/**
	 * Completion runs in a fresh PHP process through LibreSign's real
	 * service: the prepared operation survives process termination.
	 */
	public function testCompletionAcrossSeparatePhpProcess(): void {
		$pdf = $this->makePdf('Local card proof, resumable across processes');
		$lifecycle = $this->runLifecycle('synthetic-rsa-leaf', $pdf);

		$stateFile = $this->tempManager->getTemporaryFile();
		file_put_contents($stateFile, serialize($lifecycle['prepared']));
		$signatureFile = $this->tempManager->getTemporaryFile();
		file_put_contents($signatureFile, $lifecycle['signedBySigner']->signature);
		$originalFile = $this->tempManager->getTemporaryFile();
		file_put_contents($originalFile, $pdf);
		$certificateFile = $this->tempManager->getTemporaryFile();
		file_put_contents($certificateFile, $lifecycle['credential']['certificatePem']);
		$outputFile = $this->tempManager->getTemporaryFile();
		$completerScript = $this->tempManager->getTemporaryFile('.php');
		file_put_contents($completerScript, <<<'PHP'
			<?php
			declare(strict_types=1);
			[, $vendorAutoload, $appRoot, $stateFile, $signatureFile, $originalFile, $certificateFile, $outputFile] = $argv;
			require $vendorAutoload;
			if (! interface_exists('OCP\\IAppConfig')) {
				require_once dirname($appRoot, 2) . '/lib/composer/autoload.php';
				require_once dirname($appRoot, 2) . '/3rdparty/autoload.php';
			}
			require_once $appRoot . '/tests/php/Integration/Service/Signature/SubprocessInfrastructure.php';
			use OCA\LibreSign\Tests\Integration\Service\Signature\SubprocessAppConfig;
			use OCA\LibreSign\Tests\Integration\Service\Signature\SubprocessL10n;
			use OCA\LibreSign\Tests\Integration\Service\Signature\SubprocessLogger;
			$l10n = new SubprocessL10n();
			$service = new OCA\Libresign\Service\Signature\ExternalPdfSigningService(
				new OCA\Libresign\Service\Signature\PdfSignatureValidationService(
					new SubprocessAppConfig(),
					$l10n,
					new SubprocessLogger(),
				),
				new OCA\Libresign\Handler\DocMdpHandler($l10n),
			);
			$prepared = unserialize(file_get_contents($stateFile));
			if (! $prepared instanceof OCA\Libresign\Service\Signature\PreparedExternalOperation) {
				throw new RuntimeException('Could not reconstruct the prepared operation.');
			}
			file_put_contents(
				$outputFile,
				$service->complete(
					$prepared,
					file_get_contents($signatureFile),
					file_get_contents($originalFile),
					file_get_contents($certificateFile),
				),
			);
			PHP);

		exec(
			sprintf(
				'%s %s %s %s %s %s %s %s %s 2>&1',
				escapeshellarg(PHP_BINARY),
				escapeshellarg($completerScript),
				escapeshellarg(dirname(__DIR__, 4) . '/vendor/autoload.php'),
				escapeshellarg(dirname(__DIR__, 4)),
				escapeshellarg($stateFile),
				escapeshellarg($signatureFile),
				escapeshellarg($originalFile),
				escapeshellarg($certificateFile),
				escapeshellarg($outputFile),
			),
			$outputLines,
			$exitCode,
		);
		$this->assertSame(0, $exitCode, "Separate-process completion failed:\n" . implode("\n", $outputLines));

		$completed = (string)file_get_contents($outputFile);
		$signatures = $this->extractSignatures($completed);
		$this->assertCount(1, $signatures);
		$this->assertTrue(
			$this->independentOpensslVerify($signatures[0]['cms'], $signatures[0]['content']),
			'the cross-process completed document must carry a valid signature',
		);
	}

	public function testSecondSignaturePreservesFirstSignature(): void {
		$pdf = $this->makePdf('Local card proof, two signatures');

		$first = $this->runLifecycle('synthetic-rsa-leaf', $pdf);
		$signedOnce = $this->completeGuarded($first, $pdf);

		$second = $this->runLifecycle('synthetic-rsa-leaf', $signedOnce);
		$signedTwice = $this->completeGuarded($second, $signedOnce);

		$firstSignatures = $this->extractSignatures($signedOnce);
		$both = $this->extractSignatures($signedTwice);
		$this->assertCount(2, $both);
		$this->assertSame($firstSignatures[0]['cms'], $both[0]['cms'], 'the first signature must be preserved byte-identical');
		foreach ($both as $index => $entry) {
			$this->assertTrue(
				$this->independentOpensslVerify($entry['cms'], $entry['content']),
				"signature #$index must remain valid",
			);
		}
	}

	/**
	 * Reader/card absence, user cancellation and PIN scenarios are
	 * DOCUMENTED PRE-SIGN rejections (validated before key access): the
	 * coordinator closes them as REJECTED automatically. No PIN value is
	 * ever set, stored or transmitted — the scenarios are named codes.
	 */
	public function testReaderCancellationAndPinScenariosCloseAsRejected(): void {
		$pdf = $this->makePdf('Local card proof, reader failures');
		foreach (['no-reader', 'cancelled', 'pin-rejected', 'pin-blocked'] as $scenario) {
			$client = $this->client();
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . uniqid(), $credential['credentialRef']);

			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
					['scenario' => $scenario],
				));
				$this->fail("scenario $scenario must be rejected by the protocol");
			} catch (SignerErrorException $exception) {
				$this->assertSame($scenario, $exception->errorCode);
			}
			$this->assertSame(
				ProofOperationRecord::STATE_REJECTED,
				$record->getState(),
				"a documented pre-sign rejection ($scenario) must close the operation automatically",
			);
			try {
				$record->completeWith(fn (): string => 'never');
				$this->fail('a rejected operation must not be completable');
			} catch (\LogicException) {
				$this->addToAssertionCount(1);
			}
			$this->assertSame(0, $record->getCompletionInvocations());
		}
	}

	/**
	 * Card/credential replacement after discovery: re-initializing the
	 * fixtures models a card swap. The fingerprint discovered earlier no
	 * longer matches and the signer refuses before key access.
	 */
	public function testCredentialReplacementAfterDiscoveryIsRejected(): void {
		$credential = $this->credentialByRef('synthetic-ec-leaf');
		$pdf = $this->makePdf('Local card proof, card replaced');

		$this->initFixtures();
		$freshCredential = $this->credentialByRef('synthetic-ec-leaf');
		$this->assertNotSame(
			$credential['certificateSha256'],
			$freshCredential['certificateSha256'],
			'fixture re-initialization must produce a fresh synthetic card',
		);

		$prepared = $this->service->prepare($this->buildContext($pdf, $freshCredential));
		$record = new ProofOperationRecord('proof-op-replaced', $freshCredential['credentialRef']);
		try {
			$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $this->client()->signPreparedOperation(
				$record->operationId,
				$freshCredential['credentialRef'],
				$credential['certificateSha256'],
				$prepared->upstream->payload,
			));
			$this->fail('a replaced credential must be rejected by fingerprint');
		} catch (SignerErrorException $exception) {
			$this->assertSame('fingerprint-mismatch', $exception->errorCode);
		}
		$this->assertSame(ProofOperationRecord::STATE_REJECTED, $record->getState());
	}

	/**
	 * TIMEOUT SHAPES: a silent hang, an answer-then-hang and an ignored
	 * SIGTERM all end as UNCERTAIN within the deadline, the child is
	 * actually reaped, and the coordinator refuses any resend.
	 */
	public function testTimeoutShapesTerminateBoundedAndAreUncertain(): void {
		foreach (['never_reads', 'valid_then_hangs'] as $behavior) {
			$this->adversarialScenario($behavior, function (LocalSignerClient $client, string $runId): void {
				$credential = $this->credentialByRef('synthetic-rsa-leaf');
				$pdf = $this->makePdf('Local card proof, hung signer ' . $runId);
				$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
				$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
				$started = microtime(true);
				try {
					$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
						$record->operationId,
						$credential['credentialRef'],
						$credential['certificateSha256'],
						$prepared->upstream->payload,
					));
					$this->fail('an unresponsive signer must hit the deadline');
				} catch (SignerTimeoutException $exception) {
					$this->assertStringContainsString('never be retried', $exception->getMessage());
				}
				$elapsed = microtime(true) - $started;
				$this->assertLessThan(
					self::OUTER_TIMEOUT_SECONDS,
					$elapsed,
					'the bounded exchange must finish well inside the outer timeout',
				);
				$this->assertSame(ProofOperationRecord::STATE_UNCERTAIN, $record->getState());
				try {
					$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => throw new \AssertionError('resent'));
					$this->fail('an uncertain operation must never be resent');
				} catch (\LogicException) {
					$this->addToAssertionCount(1);
				}
				try {
					$record->completeWith(fn (): string => 'never');
					$this->fail('an uncertain operation must not be completable');
				} catch (\LogicException) {
					$this->addToAssertionCount(1);
				}
			}, clientTimeoutSeconds: 1.5);
		}
	}

	/**
	 * The adversarial child IGNORES SIGTERM: bounded cleanup must escalate
	 * to SIGKILL, stay inside the deadline and leave no child behind.
	 */
	public function testSigtermIgnoringChildIsForceKilledBounded(): void {
		$this->adversarialScenario('ignores_sigterm', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('Local card proof, sigterm ignored ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			$started = microtime(true);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
				));
				$this->fail('a child that ignores SIGTERM must still be bounded');
			} catch (SignerTimeoutException) {
				$this->addToAssertionCount(1);
			}
			$this->assertLessThan(self::OUTER_TIMEOUT_SECONDS, microtime(true) - $started);
			$this->assertSame(ProofOperationRecord::STATE_UNCERTAIN, $record->getState());
		}, clientTimeoutSeconds: 1.5);
	}

	/**
	 * A child that never reads stdin with a request large enough to fill
	 * the pipe: the write path must give up at the deadline (uncertain,
	 * never resent) and cleanup must reap the child.
	 */
	public function testOversizedRequestToNonReadingChildIsBoundedAndUncertain(): void {
		$this->adversarialScenario('never_reads', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('Local card proof, backpressure ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			// ~900 KiB payload: far above the 64 KiB pipe buffer.
			$payload = $this->craftPayload(
				base64_encode(str_repeat('d', 660000)),
				SigningInputType::Digest,
				SignatureAlgorithm::RsaPkcs1V15,
				SignatureEncoding::RsaPkcs1,
			);
			$started = microtime(true);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$payload,
				));
				$this->fail('an unread request must hit the deadline');
			} catch (SignerTimeoutException) {
				$this->addToAssertionCount(1);
			}
			$this->assertLessThan(self::OUTER_TIMEOUT_SECONDS, microtime(true) - $started);
			$this->assertSame(ProofOperationRecord::STATE_UNCERTAIN, $record->getState());
		}, clientTimeoutSeconds: 1.5, requestLimit: 1048576);
	}

	/**
	 * A child that exits before consuming the request: EOF with no output
	 * is an explicit protocol rejection (nonzero-exit path), classified
	 * as uncertain because the child ran after submission.
	 */
	public function testChildExitingBeforeConsumingRequestIsRejected(): void {
		$this->adversarialScenario('exits_early', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('Local card proof, early exit ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			$started = microtime(true);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
				));
				$this->fail('a child that exits early must be rejected');
			} catch (SignerProtocolException $exception) {
				$this->assertSame(LocalSignerClient::REASON_NO_OUTPUT, $exception->reason);
			}
			$this->assertLessThan(self::OUTER_TIMEOUT_SECONDS, microtime(true) - $started);
			$this->assertSame(ProofOperationRecord::STATE_UNCERTAIN, $record->getState());
		}, clientTimeoutSeconds: 4.0);
	}

	/**
	 * A nonzero exit after otherwise valid output is rejected with the
	 * specific reason, not swallowed as success.
	 */
	public function testNonzeroExitAfterValidOutputIsRejected(): void {
		$this->adversarialScenario('nonzero_after_output', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('Local card proof, nonzero exit ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
				));
				$this->fail('a nonzero exit after valid output must be rejected');
			} catch (SignerProtocolException $exception) {
				$this->assertSame(LocalSignerClient::REASON_NONZERO_EXIT, $exception->reason);
			}
			$this->assertSame(ProofOperationRecord::STATE_UNCERTAIN, $record->getState());
		}, clientTimeoutSeconds: 4.0);
	}

	/**
	 * The stdout contract: a delayed second protocol line after a valid
	 * response is rejected as trailing content.
	 */
	public function testDelayedSecondProtocolLineIsRejected(): void {
		$this->adversarialScenario('delayed_second_line', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('Local card proof, second line ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
				));
				$this->fail('content beyond the single protocol line must be rejected');
			} catch (SignerProtocolException $exception) {
				$this->assertSame(LocalSignerClient::REASON_TRAILING_CONTENT, $exception->reason);
			}
			$this->assertSame(ProofOperationRecord::STATE_UNCERTAIN, $record->getState());
		}, clientTimeoutSeconds: 4.0);
	}

	/**
	 * Output flooding past the cumulative response cap after a valid
	 * response is rejected with the response-size reason, and leaves no
	 * child running.
	 */
	public function testFloodingOutputAfterResponseIsRejectedBySize(): void {
		$this->adversarialScenario('floods_after_response', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('Local card proof, flood ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			$started = microtime(true);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
				));
				$this->fail('output beyond the response cap must be rejected');
			} catch (SignerProtocolException $exception) {
				$this->assertSame(LocalSignerClient::REASON_RESPONSE_SIZE, $exception->reason);
			}
			$this->assertLessThan(self::OUTER_TIMEOUT_SECONDS, microtime(true) - $started);
			$this->assertSame(ProofOperationRecord::STATE_UNCERTAIN, $record->getState());
		}, clientTimeoutSeconds: 4.0);
	}

	/**
	 * Continuous stdout WITHOUT any newline: the deadline must fire while
	 * output is arriving, bounding the exchange.
	 */
	public function testContinuousStdoutWithoutNewlineHitsDeadline(): void {
		$this->adversarialScenario('continuous_stdout', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('Local card proof, continuous ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			$started = microtime(true);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
				));
				$this->fail('continuous stdout without a newline must hit the deadline');
			} catch (SignerProtocolException|SignerTimeoutException $exception) {
				$this->assertContains(
					$exception->reason,
					[LocalSignerClient::REASON_TIMEOUT, LocalSignerClient::REASON_RESPONSE_SIZE, LocalSignerClient::REASON_INVALID_JSON],
					'continual output must end in a bounded rejection',
				);
			}
			$this->assertLessThan(self::OUTER_TIMEOUT_SECONDS, microtime(true) - $started);
			$this->assertSame(ProofOperationRecord::STATE_UNCERTAIN, $record->getState());
		}, clientTimeoutSeconds: 1.5);
	}

	/**
	 * Heavy stderr traffic must be drained (bounded tail retained) without
	 * deadlocking, while the valid one-line response still works.
	 */
	public function testHeavyStderrDoesNotDeadlockAndValidResponseWorks(): void {
		$this->adversarialScenario('heavy_stderr', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('Local card proof, heavy stderr ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			$started = microtime(true);
			$response = $record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
				$record->operationId,
				$credential['credentialRef'],
				$credential['certificateSha256'],
				$prepared->upstream->payload,
			));
			$this->assertLessThan(self::OUTER_TIMEOUT_SECONDS, microtime(true) - $started);
			$this->assertSame('rsa-pkcs1', $response->signatureEncoding, 'the valid one-response path must keep working');
		}, clientTimeoutSeconds: 8.0);
	}

	/**
	 * Run one adversarial child fixture under an INDEPENDENT outer
	 * timeout (separate process) so a client regression cannot hang the
	 * suite, and verify afterwards that no child process survived.
	 *
	 * The callable receives a client wired to the adversarial script with
	 * a unique run id; pgrep -f <runId> proves the cleanup.
	 */
	private function adversarialScenario(
		string $behavior,
		callable $scenario,
		float $clientTimeoutSeconds = 4.0,
		int $requestLimit = LocalSignerClient::MAX_REQUEST_BYTES,
		?\Closure $statusProbe = null,
	): void {
		$result = $this->runIsolatedScenario($behavior, $scenario, $clientTimeoutSeconds, $requestLimit, $statusProbe);
		$this->assertSame(
			0,
			$result['exitcode'],
			"the $behavior scenario failed inside its isolated process: " . $result['detail'],
		);
		$this->assertFalse(
			$result['signaled'],
			"the $behavior scenario was killed by signal " . ($result['signal'] ?? '?'),
		);
		$this->assertFalse(
			$result['timedOut'],
			"the $behavior scenario exceeded the independent outer timeout",
		);
		$this->assertFalse(
			$result['waitError'],
			"the $behavior scenario hit a wait failure",
		);
		$this->assertSame(
			[],
			$result['cleanupErrors'],
			"the $behavior scenario must clean up without errors",
		);
		$this->assertFalse(
			$result['survivors'],
			"child processes survived cleanup for run {$result['runId']} (null = unknown, also a failure)",
		);
	}

	/**
	 * Run one scenario closure in a FORKED process under an independent
	 * monotonic outer watchdog, and return its terminal outcome WITHOUT
	 * asserting — so both the adversarial tests and the watchdog
	 * meta-regression tests can use the same machinery.
	 *
	 * The terminal result of pcntl_waitpid() is captured exactly once;
	 * waitpid is never called again after a successful reap. Running,
	 * exited, signaled and wait-error results are distinguished, and
	 * pcntl_wexitstatus() is used only after pcntl_wifexited().
	 *
	 * Cleanup runs in `finally`: the isolated test child AND any signer
	 * process it launched (matched by the narrowly scoped unique run id)
	 * are killed, and temporary diagnostic files are removed after the
	 * parent has read them.
	 *
	 * @return array{exitcode: int, signaled: bool, signal: ?int, timedOut: bool, survivors: bool, runId: string, detail: string, waitError: bool}
	 */
	private function runIsolatedScenario(
		string $behavior,
		callable $scenario,
		float $clientTimeoutSeconds = 4.0,
		int $requestLimit = LocalSignerClient::MAX_REQUEST_BYTES,
		?\Closure $statusProbe = null,
		array $faults = [],
	): array {
		if (! function_exists('pcntl_fork')) {
			$this->markTestSkipped('pcntl is unavailable; the independent outer timeout cannot be provided.');
		}
		$runId = 'adv-' . uniqid();
		$adversarialScript = $this->adversarialScript;
		$pythonBinary = $this->pythonBinary();
		// Precise process-identity tracking: the child records its own pid
		// in this per-run file (see adversarial_children.py). Cleanup and
		// survivor checks use ONLY these recorded pids plus an identity
		// check that requires BOTH the script filename AND THIS run's
		// unique token in the live command line — so PID reuse and another
		// run of the same script can never be signalled.
		$runDirectory = sys_get_temp_dir() . '/lcs-proof-' . $runId;
		mkdir($runDirectory, 0700, true);
		$pidfilePath = $runDirectory . '/signer.pids';
		$buildClient = function () use ($pythonBinary, $adversarialScript, $clientTimeoutSeconds, $requestLimit, $behavior, $runId, $pidfilePath, $statusProbe): LocalSignerClient {
			$client = new LocalSignerClient(
				$pythonBinary,
				$adversarialScript,
				null,
				$clientTimeoutSeconds,
				$requestLimit,
				commandOverride: static fn (string $subcommand): array => [
					$pythonBinary,
					'-B',
					$adversarialScript,
					$behavior,
					$runId,
					$pidfilePath,
				],
				statusProbe: $statusProbe,
			);

			return $client;
		};

		$diagnosticFile = sys_get_temp_dir() . '/adv-child-' . $runId . '.err';
		$childPid = pcntl_fork();
		if ($childPid === -1) {
			$this->markTestSkipped('pcntl_fork failed; the independent outer timeout cannot be provided.');
		}
		if ($childPid === 0) {
			// Child process: run the scenario; exit 0 on success, 1 on any
			// failure or exception (assertion failures included). The
			// failure detail goes to a file the parent can report.
			try {
				$scenario($buildClient(), $runId);
				exit(0);
			} catch (\Throwable $childFailure) {
				file_put_contents($diagnosticFile, (string)$childFailure);
				exit(1);
			}
		}

		// Parent: bounded wait on a monotonic clock, independent of the
		// client under test. The waitpid result is consumed EXACTLY ONCE.
		$cleanupErrors = [];
		$detail = '';
		$survivorsFinal = null;
		$outerDeadlineNs = hrtime(true) + self::OUTER_TIMEOUT_SECONDS * 1_000_000_000;
		$childStatus = 0;
		$reaped = false;
		$waitError = false;
		$watchdogFired = false;
		$childKnownRunning = false;
		try {
			while (hrtime(true) < $outerDeadlineNs) {
				$waited = pcntl_waitpid($childPid, $childStatus, \WNOHANG);
				if ($waited === $childPid) {
					$reaped = true;
					break;
				}
				if ($waited === -1) {
					$childKnownRunning = false;
					$waitError = true;
					break;
				}
				$childKnownRunning = true;
				if (! empty($faults['wait-fails'])) {
					// INJECTED wait failure: behave exactly as if waitpid
					// had returned -1, then prove cleanup still runs and
					// the failure is reported.
					$waitError = true;
					break;
				}
				usleep(50000);
			}
			if (! $reaped && (! $waitError || $childKnownRunning)) {
				// On timeout or an injected wait failure with a known live child,
				// terminate and reap without blocking. A real waitpid error does
				// not establish ownership, so it must not trigger a blind kill.
				// Outer watchdog fired: kill recorded signer processes, then
				// the isolated test child, then reap with a BOUNDED
				// nonblocking poll. No unbounded wait anywhere.
				$watchdogFired = ! $waitError;
				$this->killRunProcesses($runId, $faults, $cleanupErrors);
				$this->signalProcess($childPid, 9, $faults, $cleanupErrors, 'isolated test child');
				$reapDeadlineNs = hrtime(true) + 5_000_000_000;
				do {
					$waited = pcntl_waitpid($childPid, $childStatus, \WNOHANG);
					if ($waited === $childPid) {
						$reaped = true;
						break;
					}
					if ($waited === -1) {
						$waitError = true;
						break;
					}
					usleep(50000);
				} while (hrtime(true) < $reapDeadlineNs);
				if (! $reaped) {
					$cleanupErrors[] = 'the isolated test child could not be reaped within the bounded cleanup window';
				}
			}
		} finally {
			// Runs on success, assertion failure, child crash, watchdog
			// firing and wait errors: signer cleanup + record removal.
			$this->killRunProcesses($runId, $faults, $cleanupErrors);
			// Survivor status MUST be decided while the run's records are
			// still in place — after deletion the answer would be a
			// vacuous false.
			$survivorsFinal = $this->runHasSurvivors($runId, $faults, $cleanupErrors);
			if (is_file($diagnosticFile)) {
				$detail = (string)file_get_contents($diagnosticFile);
				@unlink($diagnosticFile);
				if ($detail !== '') {
					$cleanupErrors[] = 'the isolated scenario reported: ' . $detail;
				}
			}
			foreach (glob($runDirectory . '/*.pids') ?: [] as $pidfile) {
				@unlink($pidfile);
			}
			@rmdir($runDirectory);
		}

		if ($waitError) {
			if (! $reaped) {
				$cleanupErrors[] = 'isolated child ownership or termination could not be confirmed after wait failure';
			}
			return [
				'exitcode' => -1, 'signaled' => false, 'signal' => null,
				'timedOut' => false, 'survivors' => $survivorsFinal, 'runId' => $runId,
				'detail' => 'pcntl_waitpid failed', 'waitError' => true,
				'cleanupErrors' => $cleanupErrors, 'childReaped' => $reaped,
			];
		}

		if (pcntl_wifsignaled($childStatus)) {
			$signal = pcntl_wtermsig($childStatus);
			if ($watchdogFired && $signal === 9) {
				// Our OWN watchdog SIGKILLed the hung test child: that is
				// the timeout path, not an unexpected signal death.
				return [
					'exitcode' => -1, 'signaled' => false, 'signal' => $signal,
					'timedOut' => true, 'survivors' => $survivorsFinal,
					'runId' => $runId, 'detail' => $detail, 'waitError' => false,
					'cleanupErrors' => $cleanupErrors,
				];
			}

			return [
				'exitcode' => -1, 'signaled' => true, 'signal' => $signal,
				'timedOut' => false, 'survivors' => $survivorsFinal, 'runId' => $runId,
				'detail' => $detail, 'waitError' => false,
				'cleanupErrors' => $cleanupErrors,
			];
		}

		$exitcode = pcntl_wifexited($childStatus) ? pcntl_wexitstatus($childStatus) : -1;

		return [
			'exitcode' => $exitcode,
			'signaled' => false,
			'signal' => null,
			'timedOut' => $watchdogFired,
			'survivors' => $survivorsFinal,
			'runId' => $runId,
			'detail' => $detail,
			'waitError' => false,
			'cleanupErrors' => $cleanupErrors,
		];
	}

	/**
	 * Narrowly scoped cleanup from PRECISE process records. Reads the pids
	 * the child itself wrote to its per-run pidfile, verifies each pid's
	 * identity (script filename AND this run's unique token in the live
	 * command line — protecting against PID reuse and cross-run
	 * signalling), then SIGKILLs. Collects EVERY error and keeps going:
	 * an earlier failure never cancels the remaining cleanup attempts.
	 * Process-inspection and signal failures land in $errors — they are
	 * errors, never evidence of success.
	 */
	private function killRunProcesses(string $runId, array $faults, array &$errors): void {
		foreach ($this->recordedRunPids($runId, $errors) as $pid) {
			if ($pid === getmypid()) {
				// A substituted record pointing at the CHECKER itself: the
				// one process this harness must never signal.
				$errors[] = sprintf(
					'recorded pid %d (run %s) is the checking process itself; it was deliberately NOT signalled',
					$pid,
					$runId,
				);
				continue;
			}
			$identity = $this->processIdentity($pid, $runId, $faults, $errors);
			if ($identity === null) {
				continue; // already gone
			}
			if ($identity === true) {
				$this->signalProcess($pid, 9, $faults, $errors, 'recorded signer ' . $pid);
			}
			// identity === false: the pid exists but is NOT our child (PID
			// reuse or a substituted record). Never signalled; reported.
			if ($identity === false) {
				$errors[] = sprintf(
					'recorded pid %d (run %s) is alive but its command line does not match this run;'
					. ' it was deliberately NOT signalled',
					$pid,
					$runId,
				);
			}
		}
	}

	/**
	 * True when a recorded, identity-verified signer process is STILL
	 * alive. false means every recorded pid is confirmed gone. When
	 * inspection or liveness probing fails, the error is appended to
	 * $errors and the answer is 'unknown' — NEVER a clean false. An alive
	 * pid whose command line does NOT match this run is reported as a
	 * mismatch error AND as a survivor (it is alive, but must never be
	 * signalled).
	 *
	 * @return bool|null true = survivor, false = none, null = unknown
	 */
	private function runHasSurvivors(string $runId, array $faults, array &$errors): ?bool {
		foreach ($this->recordedRunPids($runId, $errors) as $pid) {
			if ($pid === getmypid()) {
				// The checking process itself: alive, but never signalled.
				$errors[] = sprintf(
					'recorded pid %d (run %s) is the checking process itself; the record was substituted',
					$pid,
					$runId,
				);

				return true;
			}
			// Liveness probe: signal 0. ESRCH means gone; success or EPERM
			// means the process exists.
			$alive = posix_kill($pid, 0);
			if ($alive) {
				return true;
			}
			$lastError = posix_get_last_error();
			if ($lastError !== 3) { // 3 = ESRCH (no such process)
				$errors[] = sprintf(
					'process inspection failed for pid %d (run %s): %s',
					$pid,
					$runId,
					posix_strerror($lastError),
				);

				return null;
			}
			// Gone from the signal perspective; confirm identity via ps to
			// catch transient states.
			$identity = $this->processIdentity($pid, $runId, $faults, $errors);
			if ($identity === true) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @return list<int>
	 */
	private function recordedRunPids(string $runId, array &$errors): array {
		$runDirectory = sys_get_temp_dir() . '/lcs-proof-' . $runId;
		if (! is_dir($runDirectory)) {
			return [];
		}
		$pids = [];
		foreach (glob($runDirectory . '/*.pids') ?: [] as $pidfile) {
			$lines = file($pidfile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			if ($lines === false) {
				$errors[] = "could not read process record {$pidfile}";
				continue;
			}
			foreach ($lines as $line) {
				if (preg_match('/^[0-9]+$/', $line) !== 1) {
					$errors[] = "malformed process record '{$line}' in {$pidfile}";
					continue;
				}
				$pids[] = (int)$line;
			}
		}

		return $pids;
	}

	/**
	 * Identity of one recorded pid, with a fault seam.
	 *
	 * Returns true  — the process is alive and its command line contains
	 *                 BOTH the proof's script filename AND this run's
	 *                 unique token (so PID reuse and other runs of the
	 *                 same script are excluded);
	 *         false — the process is alive but is NOT this run's child
	 *                 (never signalled), or it is already gone;
	 *         null  — the process is already gone (same as false for
	 *                 signalling decisions, distinct for reporting).
	 *
	 * faults['inspection-fails'] forces an inspection failure (injected).
	 * Inspection failures append to $errors; they are never reported as a
	 * clean identity answer.
	 */
	private function processIdentity(int $pid, string $runId, array $faults, array &$errors): ?bool {
		if (! empty($faults['inspection-fails'])) {
			$errors[] = sprintf('injected inspection failure for pid %d (run %s)', $pid, $runId);

			return null;
		}
		if (isset($faults['identity-cmdline'])) {
			// Controlled test double for PID reuse / another run: the
			// recorded pid appears alive but with a FOREIGN command line.
			return str_contains((string)$faults['identity-cmdline'], $runId);
		}
		exec(sprintf('ps -p %d -o command=', $pid), $lines, $exitCode);
		if ($exitCode > 1) {
			$errors[] = sprintf('process inspection failed for pid %d (ps exit %d)', $pid, $exitCode);

			return null;
		}
		$commandLine = $lines[0] ?? null;
		if ($commandLine === null) {
			return null; // process does not exist
		}

		return str_contains($commandLine, 'adversarial_children.py')
			&& str_contains($commandLine, $runId);
	}

	/**
	 * Send a signal with a fault seam. Returns true when the signal was
	 * delivered; false when the target had ALREADY exited (ESRCH — not an
	 * error); a genuine signal failure is appended to $errors and returns
	 * false. faults['signal-fails'] forces a genuine-looking failure
	 * (injected).
	 */
	private function signalProcess(int $pid, int $signalNumber, array $faults, array &$errors, string $label): bool {
		if (! empty($faults['signal-fails'])) {
			$errors[] = sprintf('injected signal failure for %s (pid %d, signal %d)', $label, $pid, $signalNumber);

			return false;
		}
		$sent = posix_kill($pid, $signalNumber);
		if ($sent) {
			return true;
		}
		$lastError = posix_get_last_error();
		if ($lastError === 3) { // ESRCH: already exited — not an error
			return false;
		}
		$errors[] = sprintf(
			'signal %d to %s (pid %d) failed: %s',
			$signalNumber,
			$label,
			$pid,
			posix_strerror($lastError),
		);

		return false;
	}

	/**
	 * CONCURRENT I/O REGRESSION: a child that fills the stderr pipe
	 * before reading a large request must complete successfully — the
	 * client has to drain stderr while it is still transmitting.
	 * (stdout noise would violate the strict one-line contract, so the
	 * pipe-filling happens on stderr.)
	 */
	public function testConcurrentWriteAndDrainUnderBackpressureSucceeds(): void {
		$this->adversarialScenario('fills_pipes_then_valid', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('Local card proof, backpressure interleave ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			$payload = $this->craftPayload(
				base64_encode(str_repeat('d', 660000)),
				SigningInputType::Digest,
				SignatureAlgorithm::RsaPkcs1V15,
				SignatureEncoding::RsaPkcs1,
			);
			$started = microtime(true);
			$response = $record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
				$record->operationId,
				$credential['credentialRef'],
				$credential['certificateSha256'],
				$payload,
			));
			$this->assertLessThan(self::OUTER_TIMEOUT_SECONDS, microtime(true) - $started);
			$this->assertSame($record->operationId, $response->operationId, 'a valid response behind filled pipes must still be correlated and accepted');
		}, clientTimeoutSeconds: 8.0, requestLimit: 1048576);
	}

	/**
	 * Sustained continuous STDERR exercises deadline checks inside the
	 * drain path: the exchange must end at the deadline, bounded.
	 */
	public function testContinuousStderrHitsDeadlineInsideDrain(): void {
		$this->adversarialScenario('continuous_stderr', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('Local card proof, continuous stderr ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			$started = microtime(true);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
				));
				$this->fail('continuous stderr without a response must hit the deadline');
			} catch (SignerTimeoutException) {
				$this->addToAssertionCount(1);
			}
			$this->assertLessThan(self::OUTER_TIMEOUT_SECONDS, microtime(true) - $started);
			$this->assertSame(ProofOperationRecord::STATE_UNCERTAIN, $record->getState());
		}, clientTimeoutSeconds: 1.5);
	}

	/**
	 * Explicit pre-spawn behavior when confirmed termination facilities
	 * are unavailable: the client refuses to launch a signer process at
	 * all. No child is ever spawned.
	 */
	public function testMissingTerminationFacilitiesRefuseToLaunch(): void {
		$runId = 'adv-noposix-' . uniqid();
		$adversarialScript = $this->adversarialScript;
		$pythonBinary = $this->pythonBinary();
		$client = new LocalSignerClient(
			$pythonBinary,
			$adversarialScript,
			null,
			1.0,
			commandOverride: static fn (string $subcommand): array => [
				$pythonBinary,
				'-B',
				$adversarialScript,
				'clean_exit',
				$runId,
			],
			terminationSupport: false,
		);
		$rsa = $this->credentialByRef('synthetic-rsa-leaf');
		try {
			$client->discover();
			$this->fail('a client without confirmed-termination facilities must refuse to launch a child');
		} catch (SignerProtocolException $exception) {
			$this->assertSame(LocalSignerClient::REASON_TERMINATION_UNSUPPORTED, $exception->reason);
		}
		$errors = [];
		$this->assertFalse($this->runHasSurvivors($runId, [], $errors), 'no child may be spawned when termination facilities are unavailable');
		$this->assertSame([], $errors);
	}

	/**
	 * FAULT-INJECTION REGRESSION for the unconfirmed-termination path.
	 *
	 * Uses the SHARED isolation machinery (runIsolatedScenario, with its
	 * finally-guaranteed cleanup) and only injects a status probe that
	 * NEVER observes exit — an INJECTED confirmation failure. The real
	 * SIGTERM/SIGKILL still reach the real child pid. Expected:
	 * `termination-unconfirmed` is thrown, the scenario stays bounded
	 * inside the independent outer watchdog, cleanup is not retried, and
	 * no signer survivor remains.
	 *
	 * This establishes: the client gives up after ONE bounded attempt and
	 * reports the failure instead of retrying or claiming success. It
	 * does NOT establish prompt error delivery on the unconfirmed path:
	 * PHP resource destruction can still wait for the kernel. A REAL OS
	 * refusal to terminate (SIGKILL not acting) is outside what this
	 * proof can simulate or contain; the outer watchdog is the
	 * containment for that environmental condition.
	 */
	public function testInjectedTerminationConfirmationFailureIsReportedBounded(): void {
		$realPid = 0;
		$this->adversarialScenario('never_reads', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('fault injection, unconfirmed ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			$started = microtime(true);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
				));
				$this->fail('an unconfirmable termination must be reported');
			} catch (SignerProtocolException $exception) {
				$this->assertSame(LocalSignerClient::REASON_TERMINATION_UNCONFIRMED, $exception->reason);
			}
			$elapsed = microtime(true) - $started;
			$this->assertLessThan(self::OUTER_TIMEOUT_SECONDS, $elapsed, 'the injected failure must surface inside a bounded window');
			$this->assertSame(ProofOperationRecord::STATE_UNCERTAIN, $record->getState());
			try {
				$record->completeWith(fn (): string => 'never');
				$this->fail('an uncertain operation must not be completable');
			} catch (\LogicException) {
				$this->addToAssertionCount(1);
			}
		}, clientTimeoutSeconds: 0.5, statusProbe: static function ($proc) use (&$realPid): array {
			// INJECTED confirmation failure: the probe never observes exit.
			// The first call captures the REAL pid (from one genuine
			// proc_get_status) so the SIGTERM/SIGKILL still hit the actual
			// child.
			$real = proc_get_status($proc);
			if ($real['running']) {
				$realPid = $real['pid'];
			}

			return ['running' => true, 'pid' => $realPid ?: 999999];
		});
	}

	/**
	 * WATCHDOG META-REGRESSION: the isolation machinery itself must not
	 * produce false results. All four cases run through the SAME
	 * runIsolatedScenario() machinery the adversarial tests use, inside
	 * this test, so the suite still finishes successfully when the
	 * watchdog behaves correctly.
	 */
	public function testWatchdogCannotProduceFalseResults(): void {
		// 1. A normal successful scenario is accepted (exit 0, no signal,
		//    no timeout, no survivors).
		$success = $this->runIsolatedScenario('clean_exit', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('watchdog meta, success ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
				$record->operationId,
				$credential['credentialRef'],
				$credential['certificateSha256'],
				$prepared->upstream->payload,
			));
		}, 8.0);
		$this->assertSame(0, $success['exitcode'], $success['detail']);
		$this->assertFalse($success['signaled']);
		$this->assertFalse($success['timedOut']);
		$this->assertFalse($success['survivors']);

		// 2. A scenario ASSERTION failure reaches the parent as failure.
		$assertionFailure = $this->runIsolatedScenario('clean_exit', function (LocalSignerClient $client, string $runId): void {
			$this->fail('deliberate assertion failure for the watchdog meta-regression');
		}, 8.0);
		$this->assertNotSame(0, $assertionFailure['exitcode'], 'an assertion failure inside the isolated process must not look like success');
		$this->assertStringContainsString('deliberate assertion failure', $assertionFailure['detail']);

		// 3. A SIGNAL-KILLED test child cannot be mistaken for success.
		$signaled = $this->runIsolatedScenario('never_reads', function (LocalSignerClient $client, string $runId): void {
			// Simulate a test child killed by a signal: kill OUR OWN
			// isolated process. The unique run id is in its argv, so the
			// scoped kill finds it.
			exec('pkill -9 -f ' . escapeshellarg($runId));
			// Give the signal a moment to land; never return normally.
			usleep(500000);
			posix_kill(getmypid(), 9); // SIGKILL self: hard signal exit
		}, 8.0);
		$this->assertTrue($signaled['signaled'], 'a signal-killed test child must be classified as signaled');
		$this->assertNotNull($signaled['signal']);
		$this->assertNotSame(0, $signaled['exitcode']);

		// 4. A deliberately HUNG scenario trips the outer watchdog and
		//    leaves no signer survivor.
		$hung = $this->runIsolatedScenario('never_reads', function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('watchdog meta, hung ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			// A scenario that ignores every failure and waits forever:
			// only the outer watchdog can end it.
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
				));
			} catch (\Throwable) {
				// Swallow: the scenario pretends everything is fine.
			}
			sleep(3600);
		}, 1.0);
		$this->assertTrue($hung['timedOut'], 'a hung scenario must trip the outer watchdog: ' . var_export($hung, true));
		$this->assertFalse($hung['survivors'], 'after the watchdog fired, no signer process may survive');
	}

	/**
	 * SURVIVOR DETECTION: an EMPTY process-record set must be reported as
	 * clean — with no inspection errors and no false positives from
	 * command-line matching.
	 */
	public function testSurvivorDetectionWithNoRecordedProcessesIsClean(): void {
		$runId = 'adv-empty-' . uniqid();
		mkdir(sys_get_temp_dir() . '/lcs-proof-' . $runId, 0700, true);
		$errors = [];
		$this->assertFalse($this->runHasSurvivors($runId, [], $errors), 'an empty process set has no survivors');
		$this->assertSame([], $errors);
		$this->killRunProcesses($runId, [], $errors);
		$this->assertSame([], $errors, 'cleanup over an empty process set must succeed');
		$this->assertFalse($this->runHasSurvivors($runId, [], $errors));
	}

	/**
	 * SURVIVOR DETECTION: a deliberately LIVE signer recorded in the run
	 * pidfile must be detected, cleaned up, and gone afterwards. This
	 * proves the pidfile/identity machinery finds real survivors — the
	 * reviewer reproduced false negatives and shell self-matches with
	 * broad `pgrep -f` matching, which this machinery no longer uses.
	 */
	public function testDeliberatelyLiveSignerIsDetectedAndCleaned(): void {
		$runId = 'adv-live-' . uniqid();
		$runDirectory = sys_get_temp_dir() . '/lcs-proof-' . $runId;
		mkdir($runDirectory, 0700, true);
		$pidfilePath = $runDirectory . '/signer.pids';
		$adversarialScript = $this->adversarialScript;
		$pythonBinary = $this->pythonBinary();
		$process = proc_open(
			[$pythonBinary, '-B', $adversarialScript, 'never_reads', $runId, $pidfilePath],
			[['pipe', 'r'], ['pipe', 'w'], ['file', '/dev/null', 'w']],
			$pipes,
		);
		$this->assertIsResource($process);
		fclose($pipes[0]);
		fclose($pipes[1]);

		// Wait until the child has recorded its pid.
		$deadlineNs = hrtime(true) + 5_000_000_000;
		while (! is_file($pidfilePath) && hrtime(true) < $deadlineNs) {
			usleep(50000);
		}
		$this->assertFileExists($pidfilePath, 'the child must record its pid');
		$errors = [];
		$this->assertTrue($this->runHasSurvivors($runId, [], $errors), 'a deliberately live signer must be detected');
		$this->assertSame([], $errors);

		// The pidfile pid must be confirmed as OUR adversarial script —
		// precise identity, not a reused or unrelated pid.
		$identityErrors = [];
		foreach ($this->recordedRunPids($runId, $identityErrors) as $pid) {
			$identity = $this->processIdentity($pid, $runId, [], $identityErrors);
			$this->assertTrue($identity, 'the recorded pid must be identified as OUR adversarial child');
			$this->assertSame([], $identityErrors);
		}

		// Bounded cleanup, then gone. The test owns the process handle, so
		// it must REAP the SIGKILLed child (otherwise it stays a zombie,
		// which a signal-0 liveness probe legitimately still sees).
		$cleanupErrors = [];
		$this->killRunProcesses($runId, [], $cleanupErrors);
		$this->assertSame([], $cleanupErrors);
		usleep(200000);
		proc_close($process);
		$deadlineNs = hrtime(true) + 5_000_000_000;
		do {
			$gone = $this->runHasSurvivors($runId, [], $cleanupErrors) === false;
			if ($gone && $cleanupErrors === []) {
				break;
			}
			usleep(100000);
		} while (hrtime(true) < $deadlineNs);
		$this->assertFalse($this->runHasSurvivors($runId, [], $cleanupErrors), 'cleanup must leave no signer survivor');
		$this->assertSame([], $cleanupErrors);
		@rmdir($runDirectory);
	}

	/**
	 * FAULT-INJECTION META-REGRESSIONS: cleanup and inspection failures
	 * must be REPORTED and must never produce a passing result. Each case
	 * runs through runIsolatedScenario with an injected fault seam and a
	 * scenario that otherwise succeeds — so the ONLY reason a result is
	 * "not clean" is the reported fault.
	 */
	public function testCleanupFaultsAreReportedAndNeverPassSilently(): void {
		$successScenario = function (LocalSignerClient $client, string $runId): void {
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$pdf = $this->makePdf('cleanup fault meta ' . $runId);
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $runId, $credential['credentialRef']);
			$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
				$record->operationId,
				$credential['credentialRef'],
				$credential['certificateSha256'],
				$prepared->upstream->payload,
			));
		};

		// 1. INJECTED INSPECTION FAILURE: cleanup errors are reported even
		//    though the scenario itself succeeded. Never a clean result.
		$inspection = $this->runIsolatedScenario('clean_exit', $successScenario, 8.0, faults: ['inspection-fails' => true]);
		$this->assertSame(0, $inspection['exitcode'], 'the scenario itself must succeed');
		$this->assertNotSame([], $inspection['cleanupErrors'], 'an injected inspection failure must be reported');
		$this->assertStringContainsString(
			'injected inspection failure',
			(string)$inspection['cleanupErrors'][0],
		);

		// 2. INJECTED SIGNAL FAILURE: the scenario spawns an EXTRA live
		//    signer recorded in the SAME run pidfile, so cleanup faces a
		//    live recorded pid; the injected fault must then be REPORTED
		//    (never a silent clean result), and the leaked signer is
		//    cleaned up below without the fault.
		$signal = $this->runIsolatedScenario('clean_exit', function (LocalSignerClient $client, string $runId) use ($successScenario): void {
			$successScenario($client, $runId);
			// Extra live signer recorded into the run's own pidfile dir.
			$runDirectory = sys_get_temp_dir() . '/lcs-proof-' . $runId;
			$process = proc_open(
				[$this->pythonBinary(), '-B', $this->adversarialScript, 'never_reads', $runId, $runDirectory . '/extra.pids'],
				[['pipe', 'r'], ['pipe', 'w'], ['file', '/dev/null', 'w']],
				$pipes,
			);
			$this->assertIsResource($process);
			fclose($pipes[0]);
			fclose($pipes[1]);
			$deadlineNs = hrtime(true) + 5_000_000_000;
			while (! is_file($runDirectory . '/extra.pids') && hrtime(true) < $deadlineNs) {
				usleep(50000);
			}
			$this->assertFileExists($runDirectory . '/extra.pids');
			// Merge the extra pid into the run's OWN record, so cleanup
			// and survivor detection see it — otherwise the leaked-signer
			// assertions below would be vacuous.
			$extraPid = trim((string)file_get_contents($runDirectory . '/extra.pids'));
			$this->assertNotSame('', $extraPid);
			file_put_contents($runDirectory . '/signer.pids', $extraPid . "\n", FILE_APPEND);
			// OUTSIDE the run dir: the finally path deletes run records,
			// but the parent must still learn this pid to clean the leak.
			file_put_contents(sys_get_temp_dir() . '/lcs-meta-extra-' . $runId . '.pid', $extraPid);
			// The signer stays alive; cleanup (with the injected signal
			// fault) must report the failure AND still SIGKILL the extra
			// signer on the second, fault-free attempt in the parent.
		}, 8.0, faults: ['signal-fails' => true]);
		$this->assertSame(0, $signal['exitcode'], 'signal meta: ' . implode(' | ', $signal['cleanupErrors']));
		$this->assertNotSame([], $signal['cleanupErrors'], 'an injected signal failure must be reported');
		$this->assertStringContainsString('injected signal failure', (string)$signal['cleanupErrors'][0]);
		// The leak is real: verify the extra signer's identity, kill it by
		// exact pid (fault-free), and prove it is gone.
		$errorsAfter = [];
		$extraPid = (int)trim((string)file_get_contents(sys_get_temp_dir() . '/lcs-meta-extra-' . $signal['runId'] . '.pid'));
		$this->assertNotSame(0, $extraPid);
		$this->assertTrue(
			$this->processIdentity($extraPid, $signal['runId'], [], $errorsAfter),
			'the leaked signer must still be identified before the parent kills it',
		);
		$this->assertSame([], $errorsAfter);
		$this->assertTrue(posix_kill($extraPid, SIGKILL), 'the leaked signer must accept SIGKILL');
		$deadlineNs = hrtime(true) + 5_000_000_000;
		do {
			$gone = ! posix_kill($extraPid, 0) && posix_get_last_error() === 3;
			if ($gone) {
				break;
			}
			usleep(100000);
		} while (hrtime(true) < $deadlineNs);
		$this->assertTrue($gone, 'the leaked signer must be dead after the parent cleanup');
		@unlink(sys_get_temp_dir() . '/lcs-meta-extra-' . $signal['runId'] . '.pid');


		// 4. INJECTED PID REUSE / ANOTHER RUN: a recorded pid whose live
		//    command line carries a DIFFERENT run token must never be
		//    signalled, and the mismatch must be reported.
		$reuse = $this->runIsolatedScenario('clean_exit', $successScenario, 8.0, faults: [
			'identity-cmdline' => 'adversarial_children.py some-OTHER-run-token',
		]);
		$this->assertSame(0, $reuse['exitcode']);
		$this->assertNotSame([], $reuse['cleanupErrors'], 'a foreign-command-line pid must be reported, never signalled');
		$this->assertStringContainsString('deliberately NOT signalled', (string)$reuse['cleanupErrors'][0]);
	}

	/** A wait failure must not leave the known-live isolated child behind. */
	public function testWaitFailureTerminatesAndReapsKnownChild(): void {
		$wait = $this->runIsolatedScenario('clean_exit', static function (): void {
			sleep(3600);
		}, 8.0, faults: ['wait-fails' => true]);
		$this->assertTrue($wait['waitError']);
		$this->assertTrue($wait['childReaped'], 'the live isolated child must be terminated and reaped');
		$this->assertSame([], $wait['cleanupErrors']);
		$this->assertFalse($wait['survivors']);
	}

	/**
	 * Two SIMULTANEOUS runs: cleanup of run A must not affect run B, and
	 * B must remain a detected, separately cleanable survivor.
	 */
	public function testCleanupOnlyAffectsItsOwnRun(): void {
		$spawn = function (string $runId) use (&$handles): int {
			$runDirectory = sys_get_temp_dir() . '/lcs-proof-' . $runId;
			mkdir($runDirectory, 0700, true);
			$pidfilePath = $runDirectory . '/signer.pids';
			$process = proc_open(
				[$this->pythonBinary(), '-B', $this->adversarialScript, 'never_reads', $runId, $pidfilePath],
				[['pipe', 'r'], ['pipe', 'w'], ['file', '/dev/null', 'w']],
				$pipes,
			);
			fclose($pipes[0]);
			fclose($pipes[1]);
			$handles[$runId] = $process;
			$deadlineNs = hrtime(true) + 5_000_000_000;
			while (! is_file($pidfilePath) && hrtime(true) < $deadlineNs) {
				usleep(50000);
			}
			$this->assertFileExists($pidfilePath);

			return 0;
		};
		$handles = [];
		$runA = 'adv-runA-' . uniqid();
		$runB = 'adv-runB-' . uniqid();
		$spawn($runA);
		$spawn($runB);
		$errorsA = [];
		$errorsB = [];
		$this->assertTrue($this->runHasSurvivors($runA, [], $errorsA));
		$this->assertTrue($this->runHasSurvivors($runB, [], $errorsB));

		$this->killRunProcesses($runA, [], $errorsA);
		$this->assertSame([], $errorsA);
		proc_close($handles[$runA]); // reap the SIGKILLed child
		$deadlineNs = hrtime(true) + 5_000_000_000;
		do {
			$aGone = $this->runHasSurvivors($runA, [], $errorsA) === false;
			if ($aGone && $errorsA === []) {
				break;
			}
			usleep(100000);
		} while (hrtime(true) < $deadlineNs);
		$this->assertFalse($this->runHasSurvivors($runA, [], $errorsA), 'run A must be cleaned');
		$this->assertSame([], $errorsA);
		$this->assertTrue($this->runHasSurvivors($runB, [], $errorsB), 'run B must be unaffected by run A cleanup');

		$this->killRunProcesses($runB, [], $errorsB);
		$this->assertSame([], $errorsB);
		proc_close($handles[$runB]);
		$this->assertFalse($this->runHasSurvivors($runA, [], $errorsA));
		$this->assertFalse($this->runHasSurvivors($runB, [], $errorsB));
	}

	/**
	 * SUBSTITUTED RECORD: a pidfile that records OUR OWN pid (the
	 * checking process) must be reported as a mismatch and must NEVER be
	 * signalled — the checker cannot kill itself via its own records.
	 */
	public function testSubstitutedRecordIsReportedAndNeverSignalled(): void {
		$runId = 'adv-subst-' . uniqid();
		$runDirectory = sys_get_temp_dir() . '/lcs-proof-' . $runId;
		mkdir($runDirectory, 0700, true);
		file_put_contents($runDirectory . '/signer.pids', (string)getmypid() . "\n");
		$errors = [];
		$this->assertNotFalse($this->runHasSurvivors($runId, [], $errors) ?? true);
		$this->assertNotSame([], $errors, 'a substituted record must be reported');
		$this->killRunProcesses($runId, [], $errors);
		$this->assertNotSame([], $errors, 'the mismatch must be reported by cleanup as well');
		$this->assertTrue(
			posix_kill(getmypid(), 0),
			'the checking process must never be signalled, even via a substituted record',
		);
		@unlink($runDirectory . '/signer.pids');
		@rmdir($runDirectory);
	}

	public function testMalformedAndOversizedResponsesAreDistinguishedRejections(): void {
		$pdf = $this->makePdf('Local card proof, malformed responses');
		$cases = [
			// Malformed JSON: the 2 MiB line is one line of garbage.
			'malformed-response' => LocalSignerClient::REASON_INVALID_JSON,
			// Oversized output: now truly above the 1 MiB cumulative cap.
			'oversized-response' => LocalSignerClient::REASON_RESPONSE_SIZE,
		];
		foreach ($cases as $scenario => $expectedReason) {
			$client = $this->client();
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $scenario, $credential['credentialRef']);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
					['scenario' => $scenario],
				));
				$this->fail("scenario $scenario must be rejected by the protocol");
			} catch (SignerProtocolException $exception) {
				$this->assertNotInstanceOf(SignerErrorException::class, $exception);
				$this->assertSame(
					$expectedReason,
					$exception->reason,
					"scenario $scenario must be rejected for the specific reason",
				);
			}
			$this->assertSame(ProofOperationRecord::STATE_UNCERTAIN, $record->getState());
		}
	}

	public function testWrongOperationAndCredentialCorrelationIsRejected(): void {
		$pdf = $this->makePdf('Local card proof, correlation');
		foreach (['wrong-operation-id', 'wrong-credential-ref'] as $scenario) {
			$client = $this->client();
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . $scenario, $credential['credentialRef']);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
					['scenario' => $scenario],
				));
				$this->fail("scenario $scenario must fail correlation");
			} catch (SignerProtocolException $exception) {
				$this->assertStringContainsStringIgnoringCase('correlates', $exception->getMessage());
			}
			// A correlation failure after submission is potentially
			// uncertain: the signer may have signed.
			$this->assertSame(ProofOperationRecord::STATE_UNCERTAIN, $record->getState());
		}
	}

	/**
	 * The complete supported combination is validated BEFORE key access:
	 * wrong signature algorithm for the credential, an input that is not a
	 * digest, an unexpected signature encoding and unexpected parameters
	 * are all rejected by the protocol.
	 */
	public function testUnsupportedCombinationsAreRejectedBeforeKeyAccess(): void {
		$pdf = $this->makePdf('Local card proof, unsupported combinations');
		$rsa = $this->credentialByRef('synthetic-rsa-leaf');
		$prepared = $this->service->prepare($this->buildContext($pdf, $rsa));
		$client = $this->client();

		$cases = [
			'ecdsa payload against the RSA credential' => $this->craftPayload(
				$prepared->upstream->payload->inputBase64,
				SigningInputType::Digest,
				SignatureAlgorithm::Ecdsa,
				SignatureEncoding::EcdsaDer,
			),
			'data input instead of a digest' => $this->craftPayload(
				base64_encode('not a digest at all'),
				SigningInputType::Data,
				SignatureAlgorithm::RsaPkcs1V15,
				SignatureEncoding::RsaPkcs1,
			),
			'rsa-pkcs1 signature encoding on an ECDSA payload' => $this->craftPayload(
				$prepared->upstream->payload->inputBase64,
				SigningInputType::Digest,
				SignatureAlgorithm::Ecdsa,
				SignatureEncoding::RsaPkcs1,
			),
		];

		foreach ($cases as $label => $payload) {
			$record = new ProofOperationRecord('proof-op-unsupported', $rsa['credentialRef']);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$rsa['credentialRef'],
					$rsa['certificateSha256'],
					$payload,
				));
				$this->fail($label . ' must be rejected');
			} catch (SignerErrorException $exception) {
				$this->assertContains($exception->errorCode, ['unsupported-algorithm', 'unsupported-input-type', 'unsupported-encoding']);
			}
			$this->assertSame(ProofOperationRecord::STATE_REJECTED, $record->getState(), $label);
		}
	}

	public function testInvalidDigestEncodingAndLengthAreRejected(): void {
		$rsa = $this->credentialByRef('synthetic-rsa-leaf');
		$client = $this->client();
		$cases = [
			'not valid Base64' => '!!!not-base64!!!',
			'31-byte sha256 digest' => base64_encode(str_repeat('x', 31)),
			'empty input' => '',
		];
		foreach ($cases as $label => $inputBase64) {
			$record = new ProofOperationRecord('proof-op-digest', $rsa['credentialRef']);
			try {
				$record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
					$record->operationId,
					$rsa['credentialRef'],
					$rsa['certificateSha256'],
					$this->craftPayload(
						$inputBase64,
						SigningInputType::Digest,
						SignatureAlgorithm::RsaPkcs1V15,
						SignatureEncoding::RsaPkcs1,
					),
				));
				$this->fail($label . ' must be rejected');
			} catch (SignerErrorException $exception) {
				$this->assertSame('invalid-digest', $exception->errorCode);
			}
			$this->assertSame(ProofOperationRecord::STATE_REJECTED, $record->getState(), $label);
		}
	}

	/**
	 * Unexpected payload parameters are rejected by the raw-protocol test
	 * above: a hostile client bypasses the PHP DTOs, so that is the only
	 * path where unknown parameters can appear.
	 */
	public function testUnexpectedParameterIsRejected(): void {
		$rsa = $this->credentialByRef('synthetic-rsa-leaf');
		$base = [
			'protocolVersion' => LocalSignerClient::PROTOCOL_VERSION,
			'operationId' => 'proof-op-unexpected',
			'credentialRef' => $rsa['credentialRef'],
			'expectedCertificateFingerprint' => $rsa['certificateSha256'],
		];
		$request = $base + ['simulation' => ['scenario' => 'ok', 'extra' => true]];
		$rawOutputLines = [];
		exec(
			sprintf(
				'echo %s | %s -B %s --fixtures %s sign 2>/dev/null',
				escapeshellarg(json_encode($request)),
				escapeshellarg($this->pythonBinary()),
				escapeshellarg($this->toolsDirectory . '/signer/local_signer.py'),
				escapeshellarg($this->fixturesDirectory),
			),
			$rawOutputLines,
			$exitCode,
		);
		$response = json_decode(implode("\n", $rawOutputLines), true);
		$this->assertSame('unexpected-parameter', $response['error']['code'] ?? null);
	}

	/**
	 * A hostile client can bypass the PHP DTOs and send arbitrary labels
	 * and unknown parameters over the raw protocol. The signer must
	 * reject them before any key access.
	 */
	public function testRawProtocolRejectsUnsupportedAlgorithmLabels(): void {
		$rsa = $this->credentialByRef('synthetic-rsa-leaf');
		$base = [
			'protocolVersion' => LocalSignerClient::PROTOCOL_VERSION,
			'operationId' => 'proof-op-raw',
			'credentialRef' => $rsa['credentialRef'],
			'expectedCertificateFingerprint' => $rsa['certificateSha256'],
		];
		$digest = base64_encode(str_repeat('a', 32));
		$cases = [
			'rsa-pss is not supported' => ['signatureAlgorithm' => 'rsa-pss', 'signatureEncoding' => 'rsa-pkcs1', 'inputBase64' => $digest],
			'sha512 is not a supported digest algorithm' => ['signatureAlgorithm' => 'rsa-pkcs1-v1_5', 'signatureEncoding' => 'rsa-pkcs1', 'inputBase64' => $digest, 'digestAlgorithm' => 'sha512'],
			'unknown payload parameters are rejected' => ['signatureAlgorithm' => 'rsa-pkcs1-v1_5', 'signatureEncoding' => 'rsa-pkcs1', 'inputBase64' => $digest, 'surpriseParameter' => 'value'],
		];
		foreach ($cases as $label => $payload) {
			$request = $base + ['payload' => $payload + ['inputType' => 'digest', 'digestAlgorithm' => 'sha256']];
			$rawOutputLines = [];
			exec(
				sprintf(
					'echo %s | %s -B %s --fixtures %s sign 2>/dev/null',
					escapeshellarg(json_encode($request)),
					escapeshellarg($this->pythonBinary()),
					escapeshellarg($this->toolsDirectory . '/signer/local_signer.py'),
					escapeshellarg($this->fixturesDirectory),
				),
				$rawOutputLines,
				$exitCode,
			);
			$response = json_decode(implode("\n", $rawOutputLines), true);
			$this->assertContains(
				$response['error']['code'] ?? null,
				['unsupported-algorithm', 'unexpected-parameter'],
				$label,
			);
		}
	}

	/**
	 * A signature produced by a DIFFERENT credential (simulated card
	 * swap) is accepted by the protocol but rejected during completion:
	 * the coordinator marks the operation FAILED and the completion
	 * callback ran exactly once.
	 */
	public function testWrongKeySignatureIsRejectedAtCompletion(): void {
		$pdf = $this->makePdf('Local card proof, wrong key');
		$lifecycle = $this->runLifecycle('synthetic-rsa-leaf', $pdf, ['scenario' => 'wrong-key']);

		try {
			$this->completeGuarded($lifecycle, $pdf);
			$this->fail('a wrong-key signature must be rejected at completion');
		} catch (ExternalSigningException) {
			$this->addToAssertionCount(1);
		}
		$this->assertSame(ProofOperationRecord::STATE_FAILED, $lifecycle['record']->getState());
		$this->assertSame(1, $lifecycle['record']->getCompletionInvocations());
		try {
			$lifecycle['record']->completeWith(fn (): string => 'never');
			$this->fail('a failed operation must not be completed again');
		} catch (\LogicException) {
			$this->addToAssertionCount(1);
		}
		$this->assertSame(1, $lifecycle['record']->getCompletionInvocations(), 'the completion callback must run exactly once ever');
	}

	/**
	 * Hashing the prepared digest AGAIN (the classic double-hash bug)
	 * yields a protocol-valid signature of the wrong value; completion
	 * rejects it cryptographically.
	 */
	public function testDoubleHashedInputIsRejectedAtCompletion(): void {
		$pdf = $this->makePdf('Local card proof, double hash');
		$client = $this->client();
		$credential = $this->credentialByRef('synthetic-rsa-leaf');
		$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
		$record = new ProofOperationRecord('proof-op-double-hash', $credential['credentialRef']);

		$doubleHashed = base64_encode(hash('sha256', $prepared->upstream->payload->input(), true));
		$response = $record->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => $client->signPreparedOperation(
			$record->operationId,
			$credential['credentialRef'],
			$credential['certificateSha256'],
			$this->craftPayload(
				$doubleHashed,
				SigningInputType::Digest,
				SignatureAlgorithm::RsaPkcs1V15,
				SignatureEncoding::RsaPkcs1,
			),
		));

		try {
			$record->completeWith(fn (): string => $this->service->complete(
				$prepared,
				$response->signature,
				$pdf,
				$credential['certificatePem'],
			));
			$this->fail('a double-hashed input must be rejected at completion');
		} catch (ExternalSigningException) {
			$this->addToAssertionCount(1);
		}
		$this->assertSame(ProofOperationRecord::STATE_FAILED, $record->getState());
	}

	/**
	 * Duplicate completion: the coordinator refuses the second attempt
	 * BEFORE invoking the real completion service. The service runs
	 * exactly once across the whole operation lifetime.
	 */
	public function testDuplicateCompletionAttemptIsRefusedBeforeTheService(): void {
		$pdf = $this->makePdf('Local card proof, duplicate completion');
		$lifecycle = $this->runLifecycle('synthetic-rsa-leaf', $pdf);
		$completed = $this->completeGuarded($lifecycle, $pdf);
		$this->assertStringStartsWith('%PDF', $completed);
		$this->assertSame(ProofOperationRecord::STATE_COMPLETED, $lifecycle['record']->getState());
		$this->assertSame(1, $lifecycle['record']->getCompletionInvocations());

		try {
			$lifecycle['record']->completeWith(function (): string {
				$this->fail('the completion service must not be invoked for a duplicate attempt');

				return '';
			});
			$this->fail('a completed operation must not be completed again');
		} catch (\LogicException) {
			$this->addToAssertionCount(1);
		}
		try {
			$lifecycle['record']->submit(fn (): \LibreSign\Tools\LocalCardSigningProof\SignerResponse => throw new \AssertionError('resent'));
			$this->fail('a completed operation must not be re-sent');
		} catch (\LogicException) {
			$this->addToAssertionCount(1);
		}
		$this->assertSame(1, $lifecycle['record']->getCompletionInvocations());
	}

	public function testResponseFromAnotherPreparedOperationIsRejectedAtCompletion(): void {
		$documentA = $this->makePdf('Local card proof, cross operation A');
		$documentB = $this->makePdf('Local card proof, cross operation B');

		$lifecycleA = $this->runLifecycle('synthetic-rsa-leaf', $documentA);
		$lifecycleB = $this->runLifecycle('synthetic-rsa-leaf', $documentB);

		try {
			$lifecycleB['record']->completeWith(fn (): string => $this->service->complete(
				$lifecycleB['prepared'],
				$lifecycleA['signedBySigner']->signature,
				$documentB,
				$lifecycleB['credential']['certificatePem'],
			));
			$this->fail('a signature from another prepared operation must be rejected');
		} catch (ExternalSigningException) {
			$this->addToAssertionCount(1);
		}
		$this->assertSame(ProofOperationRecord::STATE_FAILED, $lifecycleB['record']->getState());
		$this->assertSame(ProofOperationRecord::STATE_SENT, $lifecycleA['record']->getState());
	}

	/**
	 * @param array<string, string> $extraPayloadEntries
	 */
	private function craftPayload(
		string $inputBase64,
		SigningInputType $inputType,
		SignatureAlgorithm $signatureAlgorithm,
		SignatureEncoding $signatureEncoding,
	): ExternalSigningPayload {
		$reflection = new \ReflectionClass(ExternalSigningPayload::class);
		$instance = $reflection->newInstanceWithoutConstructor();

		foreach ([
			'inputBase64' => $inputBase64,
			'inputType' => $inputType,
			'digestAlgorithm' => HashAlgorithm::Sha256,
			'signatureAlgorithm' => $signatureAlgorithm,
			'signatureEncoding' => $signatureEncoding,
		] as $property => $value) {
			$propertyReflection = new \ReflectionProperty(ExternalSigningPayload::class, $property);
			$propertyReflection->setValue($instance, $value);
		}

		return $instance;
	}

	private function buildContext(string $pdf, array $credential): SigningContextDto {
		return new SigningContextDto(
			new PdfContentDto($pdf),
			new SigningOptionsDto(
				metadata: new SignatureMetadataDto(
					reason: 'issue 8356 local-card-signing-proof',
					actor: new SignatureActorDto(name: 'Synthetic Card Signer (test)'),
				),
				useDefaultAppearance: false,
			),
			new SigningCertificateDto($credential['certificatePem'], $credential['chainPem']),
		);
	}

	private function makePdf(string $textLine): string {
		$objects = [
			1 => '<< /Type /Catalog /Pages 2 0 R >>',
			2 => '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
			3 => '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>',
			4 => '<< /Length ' . strlen($textLine) . " >>\nstream\n{$textLine}\nendstream",
		];

		$pdf = "%PDF-1.4\n";
		$offsets = [];
		foreach ($objects as $number => $body) {
			$offsets[$number] = strlen($pdf);
			$pdf .= "{$number} 0 obj\n{$body}\nendobj\n";
		}
		$xrefOffset = strlen($pdf);
		$pdf .= "xref\n0 " . (count($objects) + 1) . "\n0000000000 65535 f \n";
		foreach ($offsets as $offset) {
			$pdf .= sprintf("%010d 00000 n \n", $offset);
		}
		$pdf .= "trailer\n<< /Size " . (count($objects) + 1) . " /Root 1 0 R >>\n";
		$pdf .= "startxref\n{$xrefOffset}\n%%EOF\n";

		return $pdf;
	}

	/**
	 * @return list<array{cms: string, content: string}>
	 */
	private function extractSignatures(string $pdf): array {
		if (! preg_match_all(
			'/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/',
			$pdf,
			$matches,
			\PREG_SET_ORDER,
		)) {
			$this->fail('No /ByteRange found in the completed PDF.');
		}

		$signatures = [];
		foreach ($matches as $match) {
			[$start, $length1, $start2, $length2] = array_map(intval(...), array_slice($match, 1, 4));
			$gap = substr($pdf, $start + $length1, $start2 - ($start + $length1));
			if (! preg_match('/<\s*([0-9A-Fa-f]*)\s*>/', $gap, $hexMatch)) {
				$this->fail('No /Contents placeholder inside a ByteRange gap.');
			}
			$hex = $hexMatch[1];
			if (strlen($hex) % 2 === 1) {
				$hex .= '0';
			}
			$signatures[] = [
				'cms' => (string)hex2bin($hex),
				'content' => substr($pdf, $start, $length1) . substr($pdf, $start2, $length2),
			];
		}

		return $signatures;
	}

	/**
	 * Independent verification with the OpenSSL CLI (-noverify: synthetic
	 * test CA; -binary: no text canonicalization). Test tooling only.
	 */
	private function independentOpensslVerify(string $cmsDer, string $coveredContent): bool {
		$cmsFile = $this->tempManager->getTemporaryFile();
		$contentFile = $this->tempManager->getTemporaryFile();
		file_put_contents($cmsFile, $cmsDer);
		file_put_contents($contentFile, $coveredContent);

		$openssl = getenv('OPENSSL_BINARY') ?: (
			is_executable('/opt/homebrew/opt/openssl@3/bin/openssl')
				? '/opt/homebrew/opt/openssl@3/bin/openssl'
				: 'openssl'
		);
		exec(
			sprintf(
				'%s cms -verify -inform DER -in %s -content %s -out /dev/null -noverify -binary 2>&1',
				escapeshellarg($openssl),
				escapeshellarg($cmsFile),
				escapeshellarg($contentFile),
			),
			$outputLines,
			$exitCode,
		);

		return $exitCode === 0;
	}
}
