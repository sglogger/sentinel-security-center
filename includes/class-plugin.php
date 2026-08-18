<?php
/**
 * Main plugin class – wires every component together.
 *
 * Components are plain objects with a single `register(): void` method that
 * does nothing but add hooks. Nothing happens at file-load time.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin {

	/** @var Plugin|null */
	private static ?Plugin $instance = null;

	/** @var array<string, object> */
	private array $components = [];

	private bool $booted = false;

	private function __construct() {}

	public static function instance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Spin everything up. Called once on `plugins_loaded`.
	 */
	public function boot(): void {
		if ( $this->booted ) {
			return;
		}
		$this->booted = true;

		// No load_plugin_textdomain() call. Since WordPress 4.6 a translation is
		// loaded just in time on the first __() for the domain, and for a plugin
		// hosted on WordPress.org the .mo files are delivered into WP_LANG_DIR
		// and picked up from there. Calling it explicitly is discouraged and
		// Plugin Check flags it.

		// Converge the schema and options even when the plugin was updated by
		// uploading files rather than through the WordPress.org updater.
		Installer::maybe_migrate();

		// Monitors and the login guard must run on every request: a plugin can
		// be activated over AJAX, a user created through the REST API, and a
		// login happens on the front end.
		$this->add( 'logger', new Logger() );
		$this->add( 'plugin_monitor', new Plugin_Monitor() );
		$this->add( 'user_monitor', new User_Monitor() );
		$this->add( 'option_monitor', new Option_Monitor() );
		$this->add( 'login_guard', new Login_Guard() );
		$this->add( 'bypass_token', new Bypass_Token() );
		$this->add( 'two_factor_login', new Two_Factor_Login() );

		// Scheduled work. Registering the handlers is cheap; they only do
		// anything when their cron event fires.
		$this->add( 'file_scanner', new File_Scanner() );
		$this->add( 'user_reconciler', new User_Reconciler() );
		$this->add( 'config_scanner', new Config_Scanner() );
		$this->add( 'core_checksums', new Core_Checksums() );
		$this->add( 'update_scanner', new Update_Scanner() );
		$this->add( 'geoip_database', new Geoip_Database() );

		// Admin surface. Everything user-visible is gated on `manage_options`
		// inside these components — the plugin must be imperceptible to anyone
		// who is not an administrator.
		if ( is_admin() ) {
			$this->add( 'admin', new Admin() );
			$this->add( 'csv_exporter', new Csv_Exporter() );

			// Enrolment belongs to the account holder, not to administrators,
			// so this one registers for every signed-in user.
			$this->add( 'two_factor_admin', new Two_Factor_Admin() );
		}

		do_action( 'wpsec_loaded', $this );
	}

	/**
	 * Register and immediately hook up a component.
	 */
	private function add( string $key, object $component ): void {
		$this->components[ $key ] = $component;

		if ( method_exists( $component, 'register' ) ) {
			$component->register();
		}
	}

	/**
	 * @return object|null
	 */
	public function component( string $key ) {
		return $this->components[ $key ] ?? null;
	}
}
