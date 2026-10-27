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
 * the PHP this proof adds — including this generator itself. This
 * script writes psalm-proof.xml (NOT committed — it embeds
 * environment-specific absolute paths) into the app root. Run it from
 * the APP checkout:
 *
 *   php tools/local-card-signing-proof/psalm/generate-config.php
 *     --server-root=/path/to/nextcloud-server
 *
 * Then run the scan (from the app root):
 *
 *   CI=1 vendor-bin/psalm/vendor/bin/psalm --no-cache --threads=4
 *     -c psalm-proof.xml
 *
 * PHPUnit preference: Psalm loads the APP's composer autoloader
 * (vendor/autoload.php) by itself. The generator probes that autoloader
 * for PHPUnit\Framework\TestCase. When it IS loadable, real PHPUnit
 * definitions are used and NO stub is emitted. When it is NOT (the app
 * ships PHPUnit in vendor-bin, outside its autoloader — the common
 * Nextcloud layout), the committed minimal stub is emitted and its
 * limits are documented: it provides RESOLUTION of the test base class
 * parent chain only, with loose method signatures and therefore
 * limited behavioral typing of inherited helpers. The selection is
 * printed and recorded in the generated comment.
 *
 * Requires the same runtime Psalm requires (Psalm 6.x: PHP >= 8.1; the
 * application targets PHP 8.3, which is what these checks use). The
 * production psalm.xml, baseline and error level are never modified.
 * No suppressions are added.
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

// XML-escape every path before it enters an attribute value, so paths
// with spaces, '&' or '<' cannot break the generated configuration.
$escape = static fn (string $value): string => htmlspecialchars($value, ENT_XML1 | ENT_COMPAT, 'UTF-8');

// PHPUnit preference: probe the APP autoloader that Psalm will load.
$phpUnitLoadable = false;
$appAutoloader = $appRoot . '/vendor/autoload.php';
if (is_file($appAutoloader)) {
	require_once $appAutoloader;
	$phpUnitLoadable = class_exists(\PHPUnit\Framework\TestCase::class);
}
if ($phpUnitLoadable) {
	echo 'PHPUnit: real definitions found through the app autoloader; no stub emitted.' . "\n";
} else {
	echo 'PHPUnit: NOT loadable through the app autoloader; emitting the minimal'
		. ' resolution-only stub (parent-chain resolution only; loose signatures'
		. ' limit behavioral typing of inherited helpers).' . "\n";
}
$stubPath = dirname(__DIR__) . '/psalm/phpunit-testcase.phpstub';
if (! $phpUnitLoadable && ! is_file($stubPath)) {
	fwrite(STDERR, "missing {$stubPath}; wrong checkout?\n");
	exit(1);
}

$modeLine = $phpUnitLoadable
	? 'PHPUnit: REAL definitions (app autoloader); no stub.'
	: 'PHPUnit: stub emitted (resolution-only; loose signatures limit behavioral typing).';
$stubLine = $phpUnitLoadable
	? ''
	: "\t<stubs>\n\t\t<file name=\"" . $escape($stubPath) . "\" />\n\t</stubs>\n";

$generatorPath = __FILE__;
$escapedAppRoot = $escape($appRoot);
$escapedServerRoot = $escape($serverRoot);

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
		The application psalm.xml is unchanged.
		{$modeLine}
	-->
{$stubLine}
	<projectFiles>
		<directory name="{$escapedAppRoot}/tools/local-card-signing-proof/harness" />
		<directory name="{$escapedAppRoot}/tests/php/Integration/Tools" />
		<file name="{$escape($generatorPath)}" />
		<ignoreFiles>
			<directory name="{$escapedAppRoot}/vendor" />
			<directory name="{$escapedAppRoot}/vendor-bin" />
			<directory name="{$escapedAppRoot}/3rdparty" />
			<directory name="{$escapedAppRoot}/tools/local-card-signing-proof/fixtures" />
		</ignoreFiles>
	</projectFiles>
	<extraFiles>
		<directory name="{$escapedAppRoot}/lib" />
		<directory name="{$escapedAppRoot}/tests/php/Integration" />
		<file name="{$escapedAppRoot}/tests/php/lib/AppConfigOverwrite.php" />
		<directory name="{$escapedServerRoot}/lib" />
		<directory name="{$escapedServerRoot}/core/Command" />
		<directory name="{$escapedServerRoot}/apps/dav/lib/Connector/Sabre" />
		<directory name="{$escapedServerRoot}/apps/files/lib" />
		<directory name="{$escapedServerRoot}/apps/files_sharing/lib" />
		<directory name="{$escapedServerRoot}/apps/settings/lib/Mailer" />
		<directory name="{$escapedServerRoot}/3rdparty/doctrine/dbal/src" />
		<directory name="{$escapedServerRoot}/3rdparty/sabre/dav/lib/DAV" />
		<directory name="{$escapedServerRoot}/3rdparty/sabre/event/lib" />
		<directory name="{$escapedServerRoot}/3rdparty/stecman/symfony-console-completion/src" />
		<directory name="{$escapedServerRoot}/tests/lib" />
	</extraFiles>
</psalm>

XML;

$outputPath = $appRoot . '/psalm-proof.xml';
file_put_contents($outputPath, $config);
echo "wrote {$outputPath}\n";
echo "now run (from {$appRoot}):\n";
echo "  CI=1 vendor-bin/psalm/vendor/bin/psalm --no-cache --threads=4 -c psalm-proof.xml\n";
