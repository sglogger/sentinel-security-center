<?php
/**
 * PHPUnit bootstrap.
 *
 * These are deliberately NOT WordPress integration tests. The classes under
 * test — IP resolution, CIDR matching, the access-policy decision, the backdoor
 * signature scanner, the MMDB country lookup — were factored out to be free of
 * WordPress so they can be tested as plain PHP.
 *
 * Plugin class files all start with an `ABSPATH` guard that exits when the file
 * is loaded outside WordPress, so we define the constant here before anything
 * is autoloaded.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', dirname( __DIR__ ) . '/' );
}

require_once dirname( __DIR__ ) . '/vendor/autoload.php';
