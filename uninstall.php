<?php
/**
 * Uninstall handler.
 *
 * Data is only destroyed when the administrator explicitly opted in via
 * Settings → "Delete all data on uninstall". Silently discarding a security
 * audit trail would be the wrong default.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once plugin_dir_path( __FILE__ ) . 'includes/class-installer.php';

\WPSecurityCenter\Installer::uninstall();
