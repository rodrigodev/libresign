<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2026 rodrigodev
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * TEST-ONLY generator for the proof-specific Psalm configuration
 * (issue #8356 local-signing proof).
 *
 * The application's psalm.xml analyzes lib/ ONLY, so it never covers
 * the PHP this proof adds. This script writes psalm-proof.xml (NOT
 * committed — it embeds environment-specific absolute paths) into the
 * app root. Run it from the APP checkout:
 *
 *   php tools/local-card-signing-proof/psalm/generate-config.php \
 *     --server-root=/path/to/nextcloud-server
 *
 * Then run the scan (from the app root):
 *
 *   CI=1 vendor-bin/psalm/vendor/bin/psalm --no-cache --threads=4 \
 *     -c psalm-proof.xml
 *
 * Requires Psalm (vendor-bin/psalm) and PHP >= 8.3, matching the
 * application's own analysis runtime. The production psalm.xml,
 * baseline and error level are never modified. The PHPUnit stub
 * (phpunit-testcase.phpstub, committed alongside this script) exists
 * because the analysis process does not load PHPUnit classes; it
 * provides RESOLUTION of the test base class parent chain only, with
 * loose method signatures and therefore limited behavioral typing.
 */

$arguments = getopt('', ['server-root:', 'app-root::']);
$serverRoot = isset($arguments['server-root']) ? rtrim((string)$arguments['server-root'], '/') : null;
if ($serverRoot === null || ! is_dir($serverRoot)) {
	fwrite(STDERR, "usage: php generate-config.php --server-root=/path/to/nextcloud-server [--app-root=/path/to/apps/libresign]\n");
	exit(1);
}

$appRoot = isset($arguments['app-root']) && $arguments['app-root'] !== ''
	? rtrim((string)$arguments['app-root'], '/')
	: dirname(__DIR__, 3);
$appRoot = realpath($appRoot);
$serverRoot = realpath($serverRoot);
if ($appRoot === false || $serverRoot === false) {
	fwrite(STDERR, "could not resolve the app or server root\n");
	exit(1);
}

// The app must be the proof checkout; fail early on a wrong selection.
foreach ([
	$serverRoot . '/tests/lib/TestCase.php',
	$appRoot . '/tools/local-card-signing-proof/harness/LocalSignerClient.php',
	$appRoot . '/tests/php/Integration/Tools/LocalCardSigningProofTest.php',
	$appRoot . '/tests/php/lib/AppConfigOverwrite.php',
] as $required) {
	if (! is_file($required)) {
		fwrite(STDERR, "missing {$required}; wrong checkout?\n");
		exit(1);
	}
}

$stubPath = dirname(__DIR__) . '/psalm/phpunit-testcase.phpstub';
$config = <<<XML
<?xml version="1.0"?>
<psalm
	errorLevel="5"
	findUnusedCode="false"
	hideExternalErrors="true"
	resolveFromConfigFile="true"
	phpVersion="8.3"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns="https://getpsalm.org/schema/config"
	xsi:schemaLocation="https://getpsalm.org/schema/config vendor-bin/psalm/vendor/vimeo/psalm/config.xsd"
>
	<!--
		TEMPORARY, GENERATED proof-specific Psalm configuration
		(issue #8356 local-signing proof). Regenerate with:
		php tools/local-card-signing-proof/psalm/generate-config.php
		followed by the server root option (see the script usage).
		The application psalm.xml is unchanged. The PHPUnit stub provides
		parent-chain RESOLUTION only; its loose signatures limit behavioral
		typing of the inherited test helpers.
	-->
	<stubs>
		<file name="{$stubPath}" />
	</stubs>
	<projectFiles>
		<directory name="{$appRoot}/tools/local-card-signing-proof/harness" />
		<directory name="{$appRoot}/tests/php/Integration/Tools" />
		<ignoreFiles>
			<directory name="{$appRoot}/vendor" />
			<directory name="{$appRoot}/vendor-bin" />
			<directory name="{$appRoot}/3rdparty" />
			<directory name="{$appRoot}/tools/local-card-signing-proof/fixtures" />
		</ignoreFiles>
	</projectFiles>
	<extraFiles>
		<directory name="{$appRoot}/lib" />
		<directory name="{$appRoot}/tests/php/Integration" />
		<file name="{$appRoot}/tests/php/lib/AppConfigOverwrite.php" />
		<directory name="{$serverRoot}/lib" />
		<directory name="{$serverRoot}/core/Command" />
		<directory name="{$serverRoot}/apps/dav/lib/Connector/Sabre" />
		<directory name="{$serverRoot}/apps/files/lib" />
		<directory name="{$serverRoot}/apps/files_sharing/lib" />
		<directory name="{$serverRoot}/apps/settings/lib/Mailer" />
		<directory name="{$serverRoot}/3rdparty/doctrine/dbal/src" />
		<directory name="{$serverRoot}/3rdparty/sabre/dav/lib/DAV" />
		<directory name="{$serverRoot}/3rdparty/sabre/event/lib" />
		<directory name="{$serverRoot}/3rdparty/stecman/symfony-console-completion/src" />
		<directory name="{$serverRoot}/tests/lib" />
	</extraFiles>
</psalm>

XML;

$outputPath = $appRoot . '/psalm-proof.xml';
file_put_contents($outputPath, $config);
echo "wrote {$outputPath}\n";
echo "now run (from {$appRoot}):\n";
echo "  CI=1 vendor-bin/psalm/vendor/bin/psalm --no-cache --threads=4 -c psalm-proof.xml\n";
