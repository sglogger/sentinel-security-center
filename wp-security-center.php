<?php
/**
 * Plugin Name:       WP Security Center
 * Plugin URI:        https://github.com/sglogger/wp-security-center
 * Description:       Security monitoring and alerting for WordPress. Logs and alerts on plugin/theme changes, administrator and role changes, configuration changes, filesystem integrity and logins from countries outside your allow list — with optional login blocking. Administrator-only, with immediate e-mail alerts.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Steven Glogger
 * Author URI:        https://www.glogger.ch
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-security-center
 * Domain Path:       /languages
 * Update URI:        https://github.com/sglogger/wp-security-center
 *
 * Updates are served directly from GitHub Releases by includes/class-updater.php
 * (no helper plugin required). Repo: https://github.com/sglogger/wp-security-center
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

// Block direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// -----------------------------------------------------------------------------
// Plugin constants
// -----------------------------------------------------------------------------
define( 'WPSEC_VERSION', '1.0.0' );
define( 'WPSEC_FILE', __FILE__ );
define( 'WPSEC_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPSEC_URL', plugin_dir_url( __FILE__ ) );
define( 'WPSEC_BASENAME', plugin_basename( __FILE__ ) );

// Minimum platform versions. Kept as constants so the guards, the admin notice
// and readme.txt can all be checked against a single source.
define( 'WPSEC_MIN_PHP', '8.1' );
define( 'WPSEC_MIN_WP', '6.5' );

// Internal data-version constant – used by the migrator to know whether the
// schema or stored options need patching up after an upgrade. Bumped
// independently of the plugin version.
define( 'WPSEC_DATA_VERSION', '1.0' );

// -----------------------------------------------------------------------------
// Platform guards
//
// A security plugin that fatals on an old platform is worse than one that
// disables itself loudly, so both guards return early with an admin notice.
// The text domain is not loaded yet at this point, so these two notices are
// deliberately untranslated — they must render even when nothing else works.
// -----------------------------------------------------------------------------
if ( version_compare( PHP_VERSION, WPSEC_MIN_PHP, '<' ) ) {
	add_action(
		'admin_notices',
		static function () {
			echo '<div class="notice notice-error"><p>';
			printf(
			/* translators: 1: required PHP version, 2: current PHP version */
				esc_html( 'WP Security Center requires PHP %1$s or newer. You are running %2$s. The plugin has been disabled.' ),
				esc_html( WPSEC_MIN_PHP ),
				esc_html( PHP_VERSION )
			);
			echo '</p></div>';
		}
	);
	return;
}

if ( version_compare( (string) get_bloginfo( 'version' ), WPSEC_MIN_WP, '<' ) ) {
	add_action(
		'admin_notices',
		static function () {
			echo '<div class="notice notice-error"><p>';
			printf(
			/* translators: 1: required WordPress version, 2: current WordPress version */
				esc_html( 'WP Security Center requires WordPress %1$s or newer. You are running %2$s. The plugin has been disabled.' ),
				esc_html( WPSEC_MIN_WP ),
				esc_html( (string) get_bloginfo( 'version' ) )
			);
			echo '</p></div>';
		}
	);
	return;
}

// -----------------------------------------------------------------------------
// Class files, in dependency order. No autoloader in production by design —
// see README "Coding conventions". Composer's autoloader is only pulled in
// lazily by Country_Resolver, for the MaxMind reader.
// -----------------------------------------------------------------------------
require_once WPSEC_DIR . 'includes/class-plugin.php';
require_once WPSEC_DIR . 'includes/class-installer.php';
require_once WPSEC_DIR . 'includes/class-updater.php';
require_once WPSEC_DIR . 'admin/class-admin.php';

// -----------------------------------------------------------------------------
// Lifecycle hooks
// -----------------------------------------------------------------------------
register_activation_hook( __FILE__, [ \WPSecurityCenter\Installer::class, 'activate' ] );
register_deactivation_hook( __FILE__, [ \WPSecurityCenter\Installer::class, 'deactivate' ] );

// -----------------------------------------------------------------------------
// Boot
// -----------------------------------------------------------------------------
add_action(
	'plugins_loaded',
	static function () {
		\WPSecurityCenter\Plugin::instance()->boot();
	}
);
