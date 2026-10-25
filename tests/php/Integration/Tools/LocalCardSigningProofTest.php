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
 * Reused #9216 guarantees (unchanged): preparation-input binding,
 * DocMDP gate, signer identity resolved from the CMS SignerInfo,
 * completed-revision coverage, cryptographic validity and prior-signature
 * retention. Timestamp/LTV support and certificate trust assessment are
 * OUT OF SCOPE — this proves cryptographic validity only.
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
	private ?array $credentials = null;

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
				. ' python3 -m venv .venv && .venv/bin/pip install cryptography'
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
	 * discovery -> prepare -> external signature -> correlation -> complete.
	 *
	 * @return array{record: ProofOperationRecord, client: LocalSignerClient, prepared: \OCA\Libresign\Service\Signature\PreparedExternalOperation, credential: array, signedBySigner: \LibreSign\Tools\LocalCardSigningProof\SignerResponse}
	 */
	private function runLifecycle(string $credentialRef, string $pdf, ?array $simulation = null): array {
		$client = $this->client();
		$credential = $this->credentialByRef($credentialRef);

		$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
		$record = new ProofOperationRecord('proof-op-' . uniqid(), $credentialRef);
		$record->markSent();

		$signedBySigner = $client->signPreparedOperation(
			$record->operationId,
			$credentialRef,
			$credential['certificateSha256'],
			$prepared->upstream->payload,
			$simulation,
		);
		$this->assertSame($record->operationId, $signedBySigner->operationId);
		$this->assertSame($credentialRef, $signedBySigner->credentialRef);

		return [
			'record' => $record,
			'client' => $client,
			'prepared' => $prepared,
			'credential' => $credential,
			'signedBySigner' => $signedBySigner,
		];
	}

	public function testRsaLifecycleThroughLocalSignerProcess(): void {
		$pdf = $this->makePdf('Local card proof, RSA lifecycle');
		$lifecycle = $this->runLifecycle('synthetic-rsa-leaf', $pdf);
		$this->assertSame('rsa-pkcs1', $lifecycle['signedBySigner']->signatureEncoding);

		$completed = $this->service->complete(
			$lifecycle['prepared'],
			$lifecycle['signedBySigner']->signature,
			$pdf,
			$lifecycle['credential']['certificatePem'],
		);
		$lifecycle['record']->markCompleted();

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

		$completed = $this->service->complete(
			$lifecycle['prepared'],
			$der,
			$pdf,
			$lifecycle['credential']['certificatePem'],
		);
		$lifecycle['record']->markCompleted();

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
		$signedOnce = $this->service->complete(
			$first['prepared'],
			$first['signedBySigner']->signature,
			$pdf,
			$first['credential']['certificatePem'],
		);
		$first['record']->markCompleted();

		$second = $this->runLifecycle('synthetic-rsa-leaf', $signedOnce);
		$signedTwice = $this->service->complete(
			$second['prepared'],
			$second['signedBySigner']->signature,
			$signedOnce,
			$second['credential']['certificatePem'],
		);
		$second['record']->markCompleted();

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
	 * protocol-level rejections BEFORE any key access. No PIN value is
	 * ever set, stored or transmitted — the scenarios are named codes.
	 */
	public function testReaderCancellationAndPinScenariosAreProtocolRejections(): void {
		$pdf = $this->makePdf('Local card proof, reader failures');
		foreach ([
			'no-reader' => 'no-reader',
			'cancelled' => 'cancelled',
			'pin-rejected' => 'pin-rejected',
			'pin-blocked' => 'pin-blocked',
		] as $scenario => $expectedCode) {
			$client = $this->client();
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			$record = new ProofOperationRecord('proof-op-' . uniqid(), $credential['credentialRef']);
			$record->markSent();

			try {
				$client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
					['scenario' => $scenario],
				);
				$this->fail("scenario $scenario must be rejected by the protocol");
			} catch (SignerErrorException $exception) {
				$this->assertSame($expectedCode, $exception->errorCode);
			}
			// No signature exists; the operation stays open (NOT completed,
			// NOT retried here). The prepared state is simply discarded.
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
		try {
			$this->client()->signPreparedOperation(
				'proof-op-replaced',
				$freshCredential['credentialRef'],
				$credential['certificateSha256'],
				$prepared->upstream->payload,
			);
			$this->fail('a replaced credential must be rejected by fingerprint');
		} catch (SignerErrorException $exception) {
			$this->assertSame('fingerprint-mismatch', $exception->errorCode);
		}
	}

	/**
	 * A signer that hangs is killed at the harness timeout. The outcome is
	 * UNCERTAIN (the signature may exist) and the harness record forbids
	 * any automatic retry.
	 */
	public function testTimeoutTerminatesProcessAndOperationIsNeverRetried(): void {
		// Both timeout shapes must be classified as UNCERTAIN: a child
		// that never outputs, and a child that ANSWERS and then refuses
		// to exit. The whole process lifetime is covered by the timeout.
		foreach (['hang', 'output-then-hang'] as $scenario) {
			$pdf = $this->makePdf('Local card proof, hung signer (' . $scenario . ')');
			$client = $this->client(1.0);
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));

			$record = new ProofOperationRecord('proof-op-hang-' . $scenario, $credential['credentialRef']);
			$record->markSent();
			try {
				$client->signPreparedOperation(
					$record->operationId,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
					['scenario' => $scenario],
				);
				$this->fail("scenario $scenario must hit the timeout");
			} catch (SignerTimeoutException $exception) {
				$this->assertStringContainsString('never be retried', $exception->getMessage());
			}
			$record->markUncertain();

			try {
				$record->markSent();
				$this->fail('an uncertain operation must never be retried');
			} catch (\LogicException $exception) {
				$this->addToAssertionCount(1);
			}
		}
	}

	public function testMalformedAndOversizedResponsesAreProtocolRejections(): void {
		$pdf = $this->makePdf('Local card proof, malformed responses');
		foreach (['malformed-response', 'oversized-response'] as $scenario) {
			$client = $this->client();
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			try {
				$client->signPreparedOperation(
					'proof-op-' . $scenario,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
					['scenario' => $scenario],
				);
				$this->fail("scenario $scenario must be rejected by the protocol");
			} catch (SignerProtocolException $exception) {
				$this->assertNotInstanceOf(SignerErrorException::class, $exception);
			}
		}
	}

	public function testWrongOperationAndCredentialCorrelationIsRejected(): void {
		$pdf = $this->makePdf('Local card proof, correlation');
		foreach (['wrong-operation-id', 'wrong-credential-ref'] as $scenario) {
			$client = $this->client();
			$credential = $this->credentialByRef('synthetic-rsa-leaf');
			$prepared = $this->service->prepare($this->buildContext($pdf, $credential));
			try {
				$client->signPreparedOperation(
					'proof-op-' . $scenario,
					$credential['credentialRef'],
					$credential['certificateSha256'],
					$prepared->upstream->payload,
					['scenario' => $scenario],
				);
				$this->fail("scenario $scenario must fail correlation");
			} catch (SignerProtocolException $exception) {
				$this->assertStringContainsStringIgnoringCase('correlates', $exception->getMessage());
			}
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
			try {
				$client->signPreparedOperation(
					'proof-op-unsupported',
					$rsa['credentialRef'],
					$rsa['certificateSha256'],
					$payload,
				);
				$this->fail($label . ' must be rejected');
			} catch (SignerErrorException $exception) {
				$this->assertContains($exception->errorCode, ['unsupported-algorithm', 'unsupported-input-type', 'unsupported-encoding']);
			}
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
			try {
				$client->signPreparedOperation(
					'proof-op-digest',
					$rsa['credentialRef'],
					$rsa['certificateSha256'],
					$this->craftPayload(
						$inputBase64,
						SigningInputType::Digest,
						SignatureAlgorithm::RsaPkcs1V15,
						SignatureEncoding::RsaPkcs1,
					),
				);
				$this->fail($label . ' must be rejected');
			} catch (SignerErrorException $exception) {
				$this->assertSame('invalid-digest', $exception->errorCode);
			}
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
			$rawOutputLines = [];
		}
	}

	/**
	 * A signature produced by a DIFFERENT credential (simulated card
	 * swap) is accepted by the protocol but rejected during completion.
	 */
	public function testWrongKeySignatureIsRejectedAtCompletion(): void {
		$pdf = $this->makePdf('Local card proof, wrong key');
		$lifecycle = $this->runLifecycle('synthetic-rsa-leaf', $pdf, ['scenario' => 'wrong-key']);

		$this->expectException(ExternalSigningException::class);
		try {
			$this->service->complete(
				$lifecycle['prepared'],
				$lifecycle['signedBySigner']->signature,
				$pdf,
				$lifecycle['credential']['certificatePem'],
			);
		} finally {
			// The completed bytes never came back validated: the record
			// stays in `sent` and is discarded, never retried.
			$this->addToAssertionCount(1);
		}
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

		$doubleHashed = base64_encode(hash('sha256', $prepared->upstream->payload->input(), true));
		$response = $client->signPreparedOperation(
			'proof-op-double-hash',
			$credential['credentialRef'],
			$credential['certificateSha256'],
			$this->craftPayload(
				$doubleHashed,
				SigningInputType::Digest,
				SignatureAlgorithm::RsaPkcs1V15,
				SignatureEncoding::RsaPkcs1,
			),
		);

		$this->expectException(ExternalSigningException::class);
		$this->service->complete($prepared, $response->signature, $pdf, $credential['certificatePem']);
	}

	public function testDuplicateCompletionAttemptIsRefusedByHarnessRecord(): void {
		$pdf = $this->makePdf('Local card proof, duplicate completion');
		$lifecycle = $this->runLifecycle('synthetic-rsa-leaf', $pdf);
		$completed = $this->service->complete(
			$lifecycle['prepared'],
			$lifecycle['signedBySigner']->signature,
			$pdf,
			$lifecycle['credential']['certificatePem'],
		);
		$this->assertStringStartsWith('%PDF', $completed);
		$lifecycle['record']->markCompleted();

		try {
			$lifecycle['record']->markSent();
			$this->fail('a completed operation must not be completed or re-sent');
		} catch (\LogicException $exception) {
			$this->addToAssertionCount(1);
		}
	}

	public function testResponseFromAnotherPreparedOperationIsRejectedAtCompletion(): void {
		$documentA = $this->makePdf('Local card proof, cross operation A');
		$documentB = $this->makePdf('Local card proof, cross operation B');

		$lifecycleA = $this->runLifecycle('synthetic-rsa-leaf', $documentA);
		$lifecycleB = $this->runLifecycle('synthetic-rsa-leaf', $documentB);

		$this->expectException(ExternalSigningException::class);
		try {
			$this->service->complete(
				$lifecycleB['prepared'],
				$lifecycleA['signedBySigner']->signature,
				$documentB,
				$lifecycleB['credential']['certificatePem'],
			);
		} finally {
			$this->addToAssertionCount(1);
		}
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
