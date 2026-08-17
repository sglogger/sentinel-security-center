<?php
/**
 * Admin surface: menu registration and capability gating.
 *
 * This is the single place where the plugin becomes visible. Requirement:
 * the plugin must be invisible and imperceptible to anyone who is not an
 * administrator — no menu, no admin-bar node, no notices, no assets, and no
 * front-end footprint whatsoever.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Admin {

	/** Capability required for every screen and action in this plugin. */
	public const CAP = 'manage_options';

	/** Top-level menu slug. */
	public const MENU_LOG = 'wp-security-center';

	/** Sub-page slugs. */
	public const MENU_SETTINGS    = 'wp-security-center-settings';
	public const MENU_DIAGNOSTICS = 'wp-security-center-diagnostics';
	public const MENU_STATUS      = 'wp-security-center-status';

	public function register(): void {
		add_action( 'admin_menu', [ $this, 'add_menu' ] );
		add_filter( 'plugin_action_links_' . WPSEC_BASENAME, [ $this, 'action_links' ] );
	}

	/**
	 * Register the menu. `add_menu_page()` already enforces the capability, so
	 * a non-administrator never sees these entries at all.
	 */
	public function add_menu(): void {
		add_menu_page(
			__( 'Security Center', 'wp-security-center' ),
			__( 'Security Center', 'wp-security-center' ),
			self::CAP,
			self::MENU_LOG,
			[ $this, 'render_log' ],
			'dashicons-shield-alt',
			80
		);

		add_submenu_page(
			self::MENU_LOG,
			__( 'Event Log', 'wp-security-center' ),
			__( 'Event Log', 'wp-security-center' ),
			self::CAP,
			self::MENU_LOG,
			[ $this, 'render_log' ]
		);

		add_submenu_page(
			self::MENU_LOG,
			__( 'Status', 'wp-security-center' ),
			__( 'Status', 'wp-security-center' ),
			self::CAP,
			self::MENU_STATUS,
			[ $this, 'render_status' ]
		);

		add_submenu_page(
			self::MENU_LOG,
			__( 'Diagnostics', 'wp-security-center' ),
			__( 'Diagnostics', 'wp-security-center' ),
			self::CAP,
			self::MENU_DIAGNOSTICS,
			[ $this, 'render_diagnostics' ]
		);

		add_submenu_page(
			self::MENU_LOG,
			__( 'Settings', 'wp-security-center' ),
			__( 'Settings', 'wp-security-center' ),
			self::CAP,
			self::MENU_SETTINGS,
			[ $this, 'render_settings' ]
		);
	}

	/**
	 * Add a Settings shortcut on the Plugins screen.
	 *
	 * @param string[] $links Existing action links.
	 * @return string[]
	 */
	public function action_links( $links ): array {
		if ( ! current_user_can( self::CAP ) ) {
			return (array) $links;
		}

		$settings = sprintf(
			'<a href="%s">%s</a>',
			esc_url( admin_url( 'admin.php?page=' . self::MENU_SETTINGS ) ),
			esc_html__( 'Settings', 'wp-security-center' )
		);

		array_unshift( $links, $settings );

		return (array) $links;
	}

	// -------------------------------------------------------------------------
	// Screens
	//
	// Each render method re-checks the capability. The menu already gates it,
	// but these are public callbacks and defence in depth costs one line.
	// -------------------------------------------------------------------------

	public function render_log(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$this->placeholder( __( 'Event Log', 'wp-security-center' ) );
	}

	public function render_status(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$this->placeholder( __( 'Status', 'wp-security-center' ) );
	}

	public function render_diagnostics(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$this->placeholder( __( 'Diagnostics', 'wp-security-center' ) );
	}

	public function render_settings(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$this->placeholder( __( 'Settings', 'wp-security-center' ) );
	}

	/**
	 * Temporary scaffold body. Replaced screen by screen in later phases.
	 */
	private function placeholder( string $title ): void {
		echo '<div class="wrap">';
		echo '<h1>' . esc_html( $title ) . '</h1>';
		echo '<p>' . esc_html__( 'This screen is not implemented yet.', 'wp-security-center' ) . '</p>';
		echo '</div>';
	}
}
