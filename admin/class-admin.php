<?php
/**
 * Admin surface: menus, screens and form handling.
 *
 * This is the only place the plugin becomes visible, and everything in it is
 * gated on `manage_options`. Requirement: the plugin must be invisible and
 * imperceptible to anyone who is not an administrator — no menu, no admin-bar
 * node, no notices, no assets, and no front-end footprint at all.
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

	public const MENU_LOG         = 'sentinel-security-center';
	public const MENU_SETTINGS    = 'sentinel-security-center-settings';
	public const MENU_DIAGNOSTICS = 'sentinel-security-center-diagnostics';
	public const MENU_STATUS      = 'sentinel-security-center-status';
	public const MENU_HARDENING   = 'sentinel-security-center-hardening';

	private const NONCE = 'wpsec_settings';

	private ?Log_List_Table $table = null;

	public function register(): void {
		add_action( 'admin_menu', [ $this, 'add_menu' ] );
		add_action( 'admin_init', [ $this, 'handle_post' ] );
		add_action( 'admin_notices', [ $this, 'notices' ] );
		add_filter( 'plugin_action_links_' . WPSEC_BASENAME, [ $this, 'action_links' ] );
		add_filter( 'set-screen-option', [ $this, 'save_screen_option' ], 10, 3 );
	}

	// -------------------------------------------------------------------------
	// Menu
	// -------------------------------------------------------------------------

	public function add_menu(): void {
		$hook = add_menu_page(
			__( 'Security Center', 'sentinel-security-center' ),
			__( 'Security Center', 'sentinel-security-center' ),
			self::CAP,
			self::MENU_LOG,
			[ $this, 'render_log' ],
			'dashicons-shield-alt',
			80
		);

		add_submenu_page(
			self::MENU_LOG,
			__( 'Event Log', 'sentinel-security-center' ),
			__( 'Event Log', 'sentinel-security-center' ),
			self::CAP,
			self::MENU_LOG,
			[ $this, 'render_log' ]
		);

		add_submenu_page(
			self::MENU_LOG,
			__( 'Status', 'sentinel-security-center' ),
			__( 'Status', 'sentinel-security-center' ),
			self::CAP,
			self::MENU_STATUS,
			[ $this, 'render_status' ]
		);

		add_submenu_page(
			self::MENU_LOG,
			__( 'Hardening', 'sentinel-security-center' ),
			__( 'Hardening', 'sentinel-security-center' ),
			self::CAP,
			self::MENU_HARDENING,
			[ $this, 'render_hardening' ]
		);

		add_submenu_page(
			self::MENU_LOG,
			__( 'Diagnostics', 'sentinel-security-center' ),
			__( 'Diagnostics', 'sentinel-security-center' ),
			self::CAP,
			self::MENU_DIAGNOSTICS,
			[ $this, 'render_diagnostics' ]
		);

		add_submenu_page(
			self::MENU_LOG,
			__( 'Settings', 'sentinel-security-center' ),
			__( 'Settings', 'sentinel-security-center' ),
			self::CAP,
			self::MENU_SETTINGS,
			[ $this, 'render_settings' ]
		);

		add_action( 'load-' . $hook, [ $this, 'load_log_screen' ] );
	}

	public function load_log_screen(): void {
		add_screen_option(
			'per_page',
			[
				'label'   => __( 'Events per page', 'sentinel-security-center' ),
				'default' => 50,
				'option'  => 'wpsec_per_page',
			]
		);

		$this->table = new Log_List_Table();
	}

	/**
	 * @param mixed  $status Current value.
	 * @param string $option Option name.
	 * @param mixed  $value  Submitted value.
	 * @return mixed
	 */
	public function save_screen_option( $status, $option, $value ) {
		return 'wpsec_per_page' === $option ? (int) $value : $status;
	}

	/**
	 * @param string[] $links Existing action links.
	 * @return string[]
	 */
	public function action_links( $links ): array {
		if ( ! current_user_can( self::CAP ) ) {
			return (array) $links;
		}

		array_unshift(
			$links,
			sprintf(
				'<a href="%s">%s</a>',
				esc_url( admin_url( 'admin.php?page=' . self::MENU_SETTINGS ) ),
				esc_html__( 'Settings', 'sentinel-security-center' )
			)
		);

		return (array) $links;
	}

	// -------------------------------------------------------------------------
	// Notices — administrators only, and only on our own screens
	// -------------------------------------------------------------------------

	public function notices(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}

		$screen = get_current_screen();

		if ( ! $screen || false === strpos( (string) $screen->id, self::MENU_LOG ) ) {
			return;
		}

		$geo = (array) get_option( Installer::OPTION_GEO, [] );

		if ( ! empty( $geo['enabled'] ) && empty( $geo['countries'] ) ) {
			$this->notice(
				'warning',
				__( 'No countries are on the allow list, so login location rules do nothing at all. Add at least your own country on the Settings screen.', 'sentinel-security-center' )
			);
		}

		if ( 'block' === ( $geo['mode'] ?? '' ) && ! Country_Resolver::is_healthy() ) {
			$this->notice(
				'error',
				__( 'Login blocking is armed but no working country lookup is available. Blocking will stand itself down until a GeoIP database is installed.', 'sentinel-security-center' )
			);
		}

		if ( Geoip_Database::exists() && Geoip_Database::is_stale() ) {
			$this->notice(
				'warning',
				__( 'The GeoIP database is out of date. It is still being used, but country results may be wrong for recently reassigned addresses.', 'sentinel-security-center' )
			);
		}
	}

	private function notice( string $type, string $message ): void {
		printf(
			'<div class="notice notice-%s"><p>%s</p></div>',
			esc_attr( $type ),
			esc_html( $message )
		);
	}

	// -------------------------------------------------------------------------
	// Screens
	// -------------------------------------------------------------------------

	public function render_log(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}

		if ( null === $this->table ) {
			$this->table = new Log_List_Table();
		}

		$this->table->prepare_items();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Security Event Log', 'sentinel-security-center' ) . '</h1>';

		printf(
			'<p>%s</p>',
			esc_html(
				sprintf(
					/* translators: %d: number of matching events */
					_n( '%d matching event.', '%d matching events.', $this->table->get_total(), 'sentinel-security-center' ),
					$this->table->get_total()
				)
			)
		);

		echo '<form method="get">';
		printf( '<input type="hidden" name="page" value="%s">', esc_attr( self::MENU_LOG ) );
		$this->table->search_box( __( 'Search log', 'sentinel-security-center' ), 'wpsec-search' );
		$this->table->display();
		echo '</form>';
		echo '</div>';
	}

	public function render_status(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}

		require WPSEC_DIR . 'admin/views/page-status.php';
	}

	public function render_hardening(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}

		require WPSEC_DIR . 'admin/views/page-hardening.php';
	}

	public function render_diagnostics(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}

		require WPSEC_DIR . 'admin/views/page-diagnostics.php';
	}

	public function render_settings(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}

		require WPSEC_DIR . 'admin/views/page-settings.php';
	}

	/**
	 * Which settings tab is showing.
	 */
	public static function current_tab(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- navigation only.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( (string) $_GET['tab'] ) ) : 'general';

		return in_array( $tab, [ 'general', 'alerts', 'geo', 'twofactor', 'integrity' ], true ) ? $tab : 'general';
	}

	// -------------------------------------------------------------------------
	// Form handling
	// -------------------------------------------------------------------------

	public function handle_post(): void {
		if ( empty( $_POST['wpsec_action'] ) ) {
			return;
		}

		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You do not have permission to change these settings.', 'sentinel-security-center' ), '', [ 'response' => 403 ] );
		}

		check_admin_referer( self::NONCE );

		$action = sanitize_key( wp_unslash( (string) $_POST['wpsec_action'] ) );
		$post   = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- each field is sanitised individually below.

		switch ( $action ) {
			case 'save_general':
				$this->save_general( $post );
				$this->redirect( 'general', 'saved' );
				break;

			case 'save_alerts':
				$this->save_alerts( $post );
				$this->redirect( 'alerts', 'saved' );
				break;

			case 'save_geo':
				$this->save_geo( $post );
				$this->redirect( 'geo', $this->took_self_off_denylist() ? 'denylist_self' : 'saved' );
				break;

			case 'save_two_factor':
				$this->save_two_factor( $post );
				$this->redirect( 'twofactor', 'saved' );
				break;

			case 'save_integrity':
				$this->save_integrity( $post );
				$this->redirect( 'integrity', 'saved' );
				break;

			case 'test_email':
				$this->redirect( 'general', $this->send_test_email() ? 'mail_ok' : 'mail_failed' );
				break;

			case 'download_geoip':
				$result = Geoip_Database::refresh();
				$this->redirect( 'geo', is_wp_error( $result ) ? 'geoip_failed' : 'geoip_ok' );
				break;

			case 'apply_preset':
				$this->apply_preset( sanitize_key( (string) ( $post['preset'] ?? '' ) ) );
				$this->redirect( 'geo', 'saved' );
				break;

			case 'add_my_country':
				$this->add_my_country();
				$this->redirect( 'geo', 'saved' );
				break;

			case 'revoke_grants':
				Allowlist::revoke_all();
				$this->redirect( 'geo', 'saved' );
				break;

			case 'run_scans':
				File_Scanner::run();
				User_Reconciler::run();
				Config_Scanner::run();
				Core_Checksums::run();
				$this->redirect_status( 'scanned' );
				break;

			case 'destroy_sessions':
				\WP_Session_Tokens::destroy_all_for_all_users();
				$this->redirect_status( 'sessions' );
				break;
		}
	}

	/**
	 * @param array<string, mixed> $post Submitted data.
	 */
	private function save_general( array $post ): void {
		$settings = (array) get_option( Installer::OPTION_SETTINGS, [] );

		$recipients = [];
		foreach ( preg_split( '/[\r\n,]+/', (string) ( $post['recipients'] ?? '' ) ) ?: [] as $email ) {
			$email = sanitize_email( trim( $email ) );
			if ( '' !== $email && is_email( $email ) ) {
				$recipients[] = $email;
			}
		}

		$settings['recipients']               = array_values( array_unique( $recipients ) );
		$settings['from_name']                = sanitize_text_field( (string) ( $post['from_name'] ?? '' ) );
		$settings['from_email']               = sanitize_email( (string) ( $post['from_email'] ?? '' ) );
		$settings['mail_budget_per_hour']     = max( 0, min( 1000, (int) ( $post['mail_budget_per_hour'] ?? 50 ) ) );
		$settings['delete_data_on_uninstall'] = ! empty( $post['delete_data_on_uninstall'] );

		update_option( Installer::OPTION_SETTINGS, $settings );

		$log                   = (array) get_option( Installer::OPTION_LOG, [] );
		$log['retention_days'] = max( 0, min( 3650, (int) ( $post['retention_days'] ?? 180 ) ) );

		update_option( Installer::OPTION_LOG, $log );
	}

	/**
	 * @param array<string, mixed> $post Submitted data.
	 */
	private function save_alerts( array $post ): void {
		$modes  = (array) ( $post['event_mode'] ?? [] );
		$stored = [];

		foreach ( Event_Registry::all() as $type => $definition ) {
			$mode = sanitize_key( (string) ( $modes[ $type ] ?? '' ) );

			if ( ! in_array( $mode, [ Event_Registry::MODE_OFF, Event_Registry::MODE_LOG, Event_Registry::MODE_EMAIL ], true ) ) {
				continue;
			}

			$stored[ $type ] = $mode;
		}

		update_option( Installer::OPTION_EVENTS, $stored );
	}

	/**
	 * @param array<string, mixed> $post Submitted data.
	 */
	private function save_geo( array $post ): void {
		$geo = (array) get_option( Installer::OPTION_GEO, [] );

		$geo['enabled'] = ! empty( $post['enabled'] );

		$countries = [];
		foreach ( preg_split( '/[\s,]+/', strtoupper( (string) ( $post['countries'] ?? '' ) ) ) ?: [] as $code ) {
			$code = trim( $code );
			if ( preg_match( '/^[A-Z]{2}$/', $code ) ) {
				$countries[] = $code;
			}
		}
		$geo['countries'] = array_values( array_unique( $countries ) );

		$geo['allow_ips'] = Ip_Matcher::sanitize_list( preg_split( '/[\r\n,]+/', (string) ( $post['allow_ips'] ?? '' ) ) ?: [] );

		// A deny list that catches the administrator saving it is a lockout in
		// slow motion: the setting saves, the session survives, and the door is
		// shut at the next login. Entries matching the current address are
		// dropped and reported rather than stored.
		$deny = Ip_Matcher::sanitize_list( preg_split( '/[\r\n,]+/', (string) ( $post['deny_ips'] ?? '' ) ) ?: [] );
		$here = (string) Context::client_ip();
		$self = [];

		if ( '' !== $here ) {
			foreach ( $deny as $entry ) {
				if ( Ip_Matcher::in_any( $here, [ $entry ] ) ) {
					$self[] = $entry;
				}
			}
		}

		$geo['deny_ips'] = array_values( array_diff( $deny, $self ) );

		if ( ! empty( $self ) ) {
			$notices                  = (array) get_option( Installer::OPTION_NOTICES, [] );
			$notices['denylist_self'] = implode( ', ', $self );
			update_option( Installer::OPTION_NOTICES, $notices, false );
		}

		$geo['trusted_proxies'] = Ip_Matcher::sanitize_list( preg_split( '/[\r\n,]+/', (string) ( $post['trusted_proxies'] ?? '' ) ) ?: [] );

		$geo['use_country_header']   = ! empty( $post['use_country_header'] );
		$geo['apply_to_api_auth']    = ! empty( $post['apply_to_api_auth'] );
		$geo['bypass_enabled']       = ! empty( $post['bypass_enabled'] );
		$geo['bypass_token_ttl_min'] = max( 5, min( 1440, (int) ( $post['bypass_token_ttl_min'] ?? 60 ) ) );
		$geo['bypass_grant_hours']   = max( 1, min( 168, (int) ( $post['bypass_grant_hours'] ?? 8 ) ) );
		$geo['db_stale_days']        = max( 0, min( 365, (int) ( $post['db_stale_days'] ?? 45 ) ) );

		// The key is only overwritten when something was actually typed, so the
		// masked placeholder cannot wipe a stored key by accident.
		$key = trim( (string) ( $post['maxmind_license_key'] ?? '' ) );
		if ( '' !== $key && false === strpos( $key, '•' ) ) {
			$geo['maxmind_license_key'] = sanitize_text_field( $key );
		}

		// Blocking cannot be armed without a working lookup. Without this rail,
		// fail-closed plus a missing database equals a locked-out site.
		$mode = sanitize_key( (string) ( $post['mode'] ?? 'monitor' ) );

		if ( 'block' === $mode && Country_Resolver::is_healthy() && ! empty( $geo['countries'] ) ) {
			$geo['mode'] = 'block';
		} else {
			$geo['mode'] = 'monitor';
		}

		update_option( Installer::OPTION_GEO, $geo );

		Country_Resolver::flush();
	}

	/**
	 * Did the last save drop deny-list entries that matched this administrator?
	 */
	private function took_self_off_denylist(): bool {
		$notices = (array) get_option( Installer::OPTION_NOTICES, [] );

		return ! empty( $notices['denylist_self'] );
	}

	/**
	 * @param array<string, mixed> $post Submitted data.
	 */
	private function save_two_factor( array $post ): void {
		$before   = Two_Factor::settings();
		$settings = $before;

		$settings['enabled']        = ! empty( $post['2fa_enabled'] );
		$settings['require_admins'] = ! empty( $post['2fa_require_admins'] );
		$settings['email_fallback'] = ! empty( $post['2fa_email_fallback'] );
		$settings['grace_days']     = max( 0, min( 90, (int) ( $post['2fa_grace_days'] ?? 7 ) ) );
		$settings['email_ttl_min']  = max( 2, min( 60, (int) ( $post['2fa_email_ttl_min'] ?? 10 ) ) );

		// The grace clock starts the moment the requirement is switched on, not
		// when the plugin was installed. Otherwise turning it on would lock out
		// every administrator who happens to be away from their phone.
		if ( $settings['require_admins'] && empty( $before['require_admins'] ) ) {
			$settings['required_since'] = time();
		} elseif ( ! $settings['require_admins'] ) {
			$settings['required_since'] = 0;
		}

		update_option( Installer::OPTION_2FA, $settings );

		$changes = [];

		foreach ( [
			'enabled'        => 'the feature itself',
			'require_admins' => 'the requirement for administrators',
			'email_fallback' => 'the e-mail fallback',
		] as $key => $label ) {
			if ( (bool) $before[ $key ] !== (bool) $settings[ $key ] ) {
				$changes[] = sprintf( '%s was switched %s', $label, $settings[ $key ] ? 'on' : 'off' );
			}
		}

		if ( empty( $changes ) ) {
			return;
		}

		Logger::log(
			'2fa.policy_changed',
			[
				'object_id' => 'two_factor',
				'message'   => sprintf( 'The two-factor policy changed: %s.', implode( '; ', $changes ) ),
				'data'      => [
					'enabled'        => $settings['enabled'],
					'require_admins' => $settings['require_admins'],
					'email_fallback' => $settings['email_fallback'],
					'grace_days'     => $settings['grace_days'],
				],
			]
		);
	}

	/**
	 * @param array<string, mixed> $post Submitted data.
	 */
	private function save_integrity( array $post ): void {
		$integrity = (array) get_option( Installer::OPTION_INTEGRITY, [] );

		$integrity['scan_muplugins']      = ! empty( $post['scan_muplugins'] );
		$integrity['scan_uploads']        = ! empty( $post['scan_uploads'] );
		$integrity['scan_config_files']   = ! empty( $post['scan_config_files'] );
		$integrity['core_checksums']      = ! empty( $post['core_checksums'] );
		$integrity['heuristics']          = ! empty( $post['heuristics'] );
		$integrity['signature_threshold'] = max( 1, min( 100, (int) ( $post['signature_threshold'] ?? 60 ) ) );
		$integrity['max_files_per_run']   = max( 100, min( 200000, (int) ( $post['max_files_per_run'] ?? 20000 ) ) );

		$exclusions = [];
		foreach ( preg_split( '/[\r\n]+/', (string) ( $post['exclusions'] ?? '' ) ) ?: [] as $line ) {
			$line = trim( sanitize_text_field( $line ) );
			if ( '' !== $line ) {
				$exclusions[] = $line;
			}
		}
		$integrity['exclusions'] = $exclusions;

		update_option( Installer::OPTION_INTEGRITY, $integrity );
	}

	/**
	 * Send a test alert.
	 *
	 * The whole value of this plugin is alerts arriving. A misconfigured sender
	 * address fails silently on many hosts, so being able to prove delivery in
	 * one click is worth a button.
	 */
	private function send_test_email(): bool {
		$settings   = (array) get_option( Installer::OPTION_SETTINGS, [] );
		$recipients = Alerts::recipients( $settings );

		if ( empty( $recipients ) ) {
			return false;
		}

		$failure = '';

		$capture = static function ( $error ) use ( &$failure ): void {
			$failure = is_wp_error( $error ) ? $error->get_error_message() : '';
		};

		add_action( 'wp_mail_failed', $capture );

		$sent = Mailer::send_event(
			$recipients,
			'security_center.activated',
			[
				'event_type'  => 'security_center.activated',
				'severity'    => Event_Registry::NOTICE,
				'event_time'  => gmdate( 'Y-m-d H:i:s' ),
				'actor_login' => wp_get_current_user()->user_login,
				'message'     => 'This is a test alert. If it reached you, alert delivery is working.',
				'data'        => wp_json_encode( [ 'test' => true ] ),
			]
		);

		remove_action( 'wp_mail_failed', $capture );

		if ( ! $sent && '' !== $failure ) {
			$notices                    = (array) get_option( Installer::OPTION_NOTICES, [] );
			$notices['last_mail_error'] = $failure;
			update_option( Installer::OPTION_NOTICES, $notices, false );
		}

		return (bool) $sent;
	}

	private function apply_preset( string $preset ): void {
		$presets = Cloudflare_Ranges::presets();

		if ( ! isset( $presets[ $preset ] ) ) {
			return;
		}

		$geo = (array) get_option( Installer::OPTION_GEO, [] );

		$geo['trusted_proxies'] = Ip_Matcher::sanitize_list(
			array_merge( (array) ( $geo['trusted_proxies'] ?? [] ), $presets[ $preset ]['ranges'] )
		);

		update_option( Installer::OPTION_GEO, $geo );
	}

	/**
	 * Add the country the administrator is currently connecting from.
	 */
	private function add_my_country(): void {
		$ip       = Context::client_ip();
		$resolved = Country_Resolver::resolve( $ip );
		$country  = $resolved['country'];

		if ( ! preg_match( '/^[A-Z]{2}$/', $country ) ) {
			return;
		}

		$geo = (array) get_option( Installer::OPTION_GEO, [] );

		$geo['countries'] = array_values(
			array_unique( array_merge( (array) ( $geo['countries'] ?? [] ), [ $country ] ) )
		);

		update_option( Installer::OPTION_GEO, $geo );
	}

	private function redirect( string $tab, string $message ): void {
		wp_safe_redirect(
			add_query_arg(
				[
					'page'         => self::MENU_SETTINGS,
					'tab'          => $tab,
					'wpsec_notice' => $message,
				],
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	private function redirect_status( string $message ): void {
		wp_safe_redirect(
			add_query_arg(
				[
					'page'         => self::MENU_STATUS,
					'wpsec_notice' => $message,
				],
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Render the feedback banner after a redirect.
	 */
	public static function render_notice(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only, no action taken.
		$notice = isset( $_GET['wpsec_notice'] ) ? sanitize_key( wp_unslash( (string) $_GET['wpsec_notice'] ) ) : '';

		if ( '' === $notice ) {
			return;
		}

		$messages = [
			'saved'         => [ 'success', __( 'Settings saved.', 'sentinel-security-center' ) ],
			'geoip_ok'      => [ 'success', __( 'The GeoIP database was downloaded and installed.', 'sentinel-security-center' ) ],
			'geoip_failed'  => [ 'error', __( 'The GeoIP database could not be downloaded. See the Status screen for the reason.', 'sentinel-security-center' ) ],
			'mail_ok'       => [ 'success', __( 'The test alert was accepted for delivery. Check the recipient inbox.', 'sentinel-security-center' ) ],
			'mail_failed'   => [ 'error', self::mail_failure_message() ],
			'scanned'       => [ 'success', __( 'All scans have been run. Any findings are in the event log.', 'sentinel-security-center' ) ],
			'sessions'      => [ 'success', __( 'All sessions were destroyed. Everyone, including you, must sign in again.', 'sentinel-security-center' ) ],
			'denylist_self' => [ 'warning', self::denylist_self_message() ],
		];

		if ( ! isset( $messages[ $notice ] ) ) {
			return;
		}

		printf(
			'<div class="notice notice-%s is-dismissible"><p>%s</p></div>',
			esc_attr( $messages[ $notice ][0] ),
			esc_html( $messages[ $notice ][1] )
		);
	}

	/**
	 * Report the deny-list entries that were refused because they matched the
	 * address the administrator was saving from.
	 */
	private static function denylist_self_message(): string {
		$notices = (array) get_option( Installer::OPTION_NOTICES, [] );
		$entries = trim( (string) ( $notices['denylist_self'] ?? '' ) );

		unset( $notices['denylist_self'] );
		update_option( Installer::OPTION_NOTICES, $notices, false );

		if ( '' === $entries ) {
			return __( 'Everything else was saved.', 'sentinel-security-center' );
		}

		return sprintf(
			/* translators: %s: comma-separated list of IP addresses or CIDR blocks */
			__( 'Saved, but these deny-list entries match the address you are working from and were not stored: %s. Denying yourself would have shut the door at your next login, with the current session hiding it until then.', 'sentinel-security-center' ),
			$entries
		);
	}

	/**
	 * Explain why a test alert did not go out, including whatever the mail
	 * layer actually said — "sending failed" on its own is useless.
	 */
	private static function mail_failure_message(): string {
		$notices = (array) get_option( Installer::OPTION_NOTICES, [] );
		$error   = trim( (string) ( $notices['last_mail_error'] ?? '' ) );

		if ( '' === $error ) {
			return __( 'The test alert could not be sent. Check that at least one recipient is configured.', 'sentinel-security-center' );
		}

		return sprintf(
			/* translators: %s: error message from the mail layer */
			__( 'The test alert could not be sent: %s', 'sentinel-security-center' ),
			$error
		);
	}

	/**
	 * Open a settings form with its nonce.
	 */
	public static function form_open( string $action ): void {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin.php?page=' . self::MENU_SETTINGS ) ) . '">';
		wp_nonce_field( self::NONCE );
		printf( '<input type="hidden" name="wpsec_action" value="%s">', esc_attr( $action ) );
	}
}
