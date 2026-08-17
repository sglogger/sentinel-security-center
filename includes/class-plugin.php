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

		load_plugin_textdomain(
			'wp-security-center',
			false,
			dirname( WPSEC_BASENAME ) . '/languages'
		);

		// Converge the schema and options even when the plugin was updated by
		// uploading files rather than through the updater.
		Installer::maybe_migrate();

		// Admin surface. Everything user-visible is gated on `manage_options`
		// inside this component — the plugin must be imperceptible to anyone
		// who is not an administrator.
		if ( is_admin() ) {
			$this->add( 'admin', new Admin() );
		}

		// GitHub Releases self-updater. Only ever needed in the admin, during
		// cron, or under WP-CLI; loading it on front-end requests would add an
		// HTTP lookup to page loads for no reason.
		if ( is_admin() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			$this->add( 'updater', new Updater() );
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
