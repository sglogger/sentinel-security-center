<?php
/**
 * Plugin Name:       Sentinel Security Center
 * Plugin URI:        https://github.com/sglogger/sentinel-security-center
 * Description:       Security monitoring and alerting for WordPress. Logs and alerts on plugin/theme changes, administrator and role changes, configuration changes, filesystem integrity and logins from countries outside your allow list — with optional login blocking and two-factor authentication. Administrator-only, with immediate e-mail alerts.
 * Version:           1.6.5
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Steven Glogger
 * Author URI:        https://www.glogger.ch
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       sentinel-security-center
 * Domain Path:       /languages
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
define( 'WPSEC_VERSION', '1.6.5' );
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
define( 'WPSEC_DATA_VERSION', '1.2' );

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
				esc_html( 'Sentinel Security Center requires PHP %1$s or newer. You are running %2$s. The plugin has been disabled.' ),
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
				esc_html( 'Sentinel Security Center requires WordPress %1$s or newer. You are running %2$s. The plugin has been disabled.' ),
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

// Core: the event catalogue, request context, and the write path.
require_once WPSEC_DIR . 'includes/class-event-registry.php';
require_once WPSEC_DIR . 'includes/class-context.php';
require_once WPSEC_DIR . 'includes/class-logger.php';
require_once WPSEC_DIR . 'includes/class-log-query.php';
require_once WPSEC_DIR . 'includes/class-alerts.php';
require_once WPSEC_DIR . 'includes/class-mailer.php';
require_once WPSEC_DIR . 'includes/class-hardening.php';

// Location handling. Ip_Matcher, Ip_Resolver and Access_Policy are free of
// WordPress so the decision logic can be unit-tested on its own.
require_once WPSEC_DIR . 'includes/geo/class-ip-matcher.php';
require_once WPSEC_DIR . 'includes/geo/class-ip-resolver.php';
require_once WPSEC_DIR . 'includes/geo/class-access-policy.php';
require_once WPSEC_DIR . 'includes/geo/class-tar-reader.php';
require_once WPSEC_DIR . 'includes/geo/class-geoip-database.php';
require_once WPSEC_DIR . 'includes/geo/class-country-resolver.php';
require_once WPSEC_DIR . 'includes/geo/class-cloudflare-ranges.php';
require_once WPSEC_DIR . 'includes/geo/class-allowlist.php';
require_once WPSEC_DIR . 'includes/geo/class-denylist.php';
require_once WPSEC_DIR . 'includes/geo/class-bypass-token.php';
require_once WPSEC_DIR . 'includes/geo/class-login-guard.php';

// Two-factor authentication. Totp and Secret_Cipher are free of WordPress so
// the code generation can be tested against the RFC vectors.
require_once WPSEC_DIR . 'includes/auth/class-totp.php';
require_once WPSEC_DIR . 'includes/auth/class-secret-cipher.php';
require_once WPSEC_DIR . 'includes/auth/class-two-factor.php';
require_once WPSEC_DIR . 'includes/auth/class-two-factor-login.php';

// Hook-driven monitors.
require_once WPSEC_DIR . 'includes/monitors/class-plugin-monitor.php';
require_once WPSEC_DIR . 'includes/monitors/class-user-monitor.php';
require_once WPSEC_DIR . 'includes/monitors/class-option-monitor.php';

// Scheduled scanners, for everything that has no usable hook.
require_once WPSEC_DIR . 'includes/scanners/class-signature-scanner.php';
require_once WPSEC_DIR . 'includes/scanners/class-file-scanner.php';
require_once WPSEC_DIR . 'includes/scanners/class-user-reconciler.php';
require_once WPSEC_DIR . 'includes/scanners/class-config-scanner.php';
require_once WPSEC_DIR . 'includes/scanners/class-core-checksums.php';
require_once WPSEC_DIR . 'includes/scanners/class-update-scanner.php';

// Admin surface.
require_once WPSEC_DIR . 'admin/class-admin.php';
require_once WPSEC_DIR . 'admin/class-log-list-table.php';
require_once WPSEC_DIR . 'admin/class-csv-exporter.php';
require_once WPSEC_DIR . 'admin/class-two-factor-admin.php';

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
