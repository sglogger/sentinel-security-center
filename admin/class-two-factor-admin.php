<?php
/**
 * The screens where a user sets up, inspects and turns off their second factor.
 *
 * Enrolment cannot live behind `manage_options` the way the rest of this
 * plugin does — the person enrolling is the account holder, whoever they are.
 * The setup page is therefore registered with the `read` capability but hidden
 * from the menu for anyone who cannot see the plugin, so it stays reachable
 * without becoming visible.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Two_Factor_Admin {

	public const PAGE = 'wp-security-center-2fa';

	private const NONCE = 'wpsec_2fa';

	public function register(): void {
		add_action( 'admin_menu', [ $this, 'add_page' ], 20 );
		add_action( 'admin_init', [ $this, 'handle_post' ] );
		add_action( 'admin_notices', [ $this, 'grace_notice' ] );

		add_action( 'show_user_profile', [ $this, 'profile_section' ] );
		add_action( 'edit_user_profile', [ $this, 'profile_section' ] );
		add_action( 'edit_user_profile_update', [ $this, 'handle_admin_reset' ] );
	}

	public function add_page(): void {
		$page = add_submenu_page(
			Admin::MENU_LOG,
			__( 'Two-factor authentication', 'wp-security-center' ),
			__( 'Two-factor', 'wp-security-center' ),
			'read',
			self::PAGE,
			[ $this, 'render' ]
		);

		// A user who cannot see the plugin must not see a menu entry for it
		// either — but the page itself stays routable so their profile can
		// link to it.
		if ( $page && ! current_user_can( Admin::CAP ) ) {
			remove_submenu_page( Admin::MENU_LOG, self::PAGE );
		}
	}

	public static function url(): string {
		return admin_url( 'admin.php?page=' . self::PAGE );
	}

	// -------------------------------------------------------------------------
	// The setup page
	// -------------------------------------------------------------------------

	public function render(): void {
		$wpsec_user = wp_get_current_user();

		if ( ! $wpsec_user->exists() ) {
			return;
		}

		$wpsec_available  = Two_Factor::is_available();
		$wpsec_active     = Two_Factor::is_active_for( (int) $wpsec_user->ID );
		$wpsec_left       = Two_Factor::recovery_codes_left( (int) $wpsec_user->ID );
		$wpsec_required   = Two_Factor::required_for( $wpsec_user );
		$wpsec_new_codes  = self::flash( 'codes' );
		$wpsec_setting_up = ! $wpsec_active && ( self::flash( 'setup' ) || Two_Factor::must_enrol( $wpsec_user ) );
		$wpsec_secret     = '';
		$wpsec_uri        = '';
		$wpsec_svg        = '';

		if ( $wpsec_available && $wpsec_setting_up ) {
			$wpsec_secret = Two_Factor::pending_secret( (int) $wpsec_user->ID );

			if ( '' === $wpsec_secret ) {
				$wpsec_secret = Two_Factor::start_enrolment( (int) $wpsec_user->ID );
			}

			$wpsec_uri = Two_Factor::provisioning_uri( $wpsec_user, $wpsec_secret );
			$wpsec_svg = Two_Factor::qr_svg( $wpsec_uri );
		}

		require WPSEC_DIR . 'admin/views/page-two-factor.php';
	}

	/**
	 * Open a form on this page with its nonce.
	 */
	public static function form_open( string $action ): void {
		echo '<form method="post" action="' . esc_url( self::url() ) . '">';
		wp_nonce_field( self::NONCE );
		printf( '<input type="hidden" name="wpsec_2fa_action" value="%s">', esc_attr( $action ) );
	}

	// -------------------------------------------------------------------------
	// Form handling
	// -------------------------------------------------------------------------

	public function handle_post(): void {
		if ( empty( $_POST['wpsec_2fa_action'] ) ) {
			return;
		}

		check_admin_referer( self::NONCE );

		$user = wp_get_current_user();

		if ( ! $user->exists() ) {
			return;
		}

		$user_id = (int) $user->ID;
		$action  = sanitize_key( wp_unslash( (string) $_POST['wpsec_2fa_action'] ) );

		switch ( $action ) {
			case 'start':
				Two_Factor::start_enrolment( $user_id );
				$this->redirect( 'setup' );
				break;

			case 'confirm':
				$code  = isset( $_POST['wpsec_code'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['wpsec_code'] ) ) : '';
				$codes = Two_Factor::confirm_enrolment( $user_id, $code );

				if ( null === $codes ) {
					$this->redirect( 'setup', 'bad_code' );
				}

				$this->stash_codes( $codes );
				$this->redirect( '', 'enabled' );
				break;

			case 'regenerate':
				if ( ! Two_Factor::is_active_for( $user_id ) ) {
					$this->redirect( '' );
				}

				$this->stash_codes( Two_Factor::generate_recovery_codes( $user_id ) );

				Logger::log(
					'2fa.recovery_codes_regenerated',
					[
						'object_id'    => (string) $user_id,
						'object_label' => (string) $user->user_login,
						'target_user'  => $user_id,
						'message'      => sprintf( '"%s" generated a new set of two-factor recovery codes. The previous set no longer works.', $user->user_login ),
						'data'         => [ 'count' => Two_Factor::RECOVERY_COUNT ],
					]
				);

				$this->redirect( '', 'codes' );
				break;

			case 'disable':
				Two_Factor::disable( $user_id, 'self' );
				$this->redirect( '', 'disabled' );
				break;
		}
	}

	/**
	 * An administrator clearing someone else's second factor.
	 *
	 * The only way back for a user who has lost the authenticator, the recovery
	 * codes and access to their mailbox. It is a reset, not a bypass: they must
	 * enrol again.
	 *
	 * @param int $user_id The user being edited.
	 */
	public function handle_admin_reset( $user_id ): void {
		$user_id = (int) $user_id;

		if ( ! current_user_can( 'edit_user', $user_id ) || get_current_user_id() === $user_id ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- the profile form's own nonce is checked by WordPress before this hook fires.
		if ( empty( $_POST['wpsec_2fa_reset'] ) ) {
			return;
		}

		Two_Factor::disable( $user_id, 'admin' );
	}

	private function redirect( string $view = '', string $notice = '' ): void {
		$args = [ 'page' => self::PAGE ];

		if ( '' !== $view ) {
			$args['view'] = $view;
		}

		if ( '' !== $notice ) {
			$args['wpsec_2fa_notice'] = $notice;
		}

		wp_safe_redirect( add_query_arg( $args, admin_url( 'admin.php' ) ) );
		exit;
	}

	/**
	 * Hold the fresh recovery codes for exactly one page load.
	 *
	 * A transient rather than the URL or the user meta: they must be shown
	 * once, must not sit in a browser history, and must not be stored anywhere
	 * readable afterwards.
	 *
	 * @param string[] $codes The codes in the clear.
	 */
	private function stash_codes( array $codes ): void {
		set_transient( 'wpsec_2fa_codes_' . get_current_user_id(), $codes, 5 * MINUTE_IN_SECONDS );
	}

	/**
	 * @return string[]|bool The stashed codes, or whether a view was requested.
	 */
	private static function flash( string $what ) {
		if ( 'codes' === $what ) {
			$key   = 'wpsec_2fa_codes_' . get_current_user_id();
			$codes = get_transient( $key );

			if ( is_array( $codes ) ) {
				delete_transient( $key );
				return $codes;
			}

			return [];
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- navigation only.
		$view = isset( $_GET['view'] ) ? sanitize_key( wp_unslash( (string) $_GET['view'] ) ) : '';

		return $view === $what;
	}

	public static function render_notice(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.
		$notice = isset( $_GET['wpsec_2fa_notice'] ) ? sanitize_key( wp_unslash( (string) $_GET['wpsec_2fa_notice'] ) ) : '';

		$messages = [
			'enabled'  => [ 'success', __( 'Two-factor authentication is on. Save the recovery codes below.', 'wp-security-center' ) ],
			'disabled' => [ 'warning', __( 'Two-factor authentication has been switched off for your account.', 'wp-security-center' ) ],
			'codes'    => [ 'success', __( 'New recovery codes generated. The previous set no longer works.', 'wp-security-center' ) ],
			'bad_code' => [ 'error', __( 'That code was not right. Make sure the phone clock is correct and try the code showing now.', 'wp-security-center' ) ],
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

	// -------------------------------------------------------------------------
	// Profile screen and nudges
	// -------------------------------------------------------------------------

	/**
	 * @param \WP_User $user The user whose profile is being shown.
	 */
	public function profile_section( $user ): void {
		if ( ! $user instanceof \WP_User || ! Two_Factor::is_available() ) {
			return;
		}

		$own    = get_current_user_id() === (int) $user->ID;
		$active = Two_Factor::is_active_for( (int) $user->ID );

		echo '<h2>' . esc_html__( 'Two-factor authentication', 'wp-security-center' ) . '</h2>';
		echo '<table class="form-table" role="presentation"><tr>';
		echo '<th scope="row">' . esc_html__( 'Status', 'wp-security-center' ) . '</th><td>';

		if ( $active ) {
			printf(
				'<p><strong>%s</strong> %s</p>',
				esc_html__( 'On.', 'wp-security-center' ),
				esc_html(
					sprintf(
						/* translators: %d: number of unused recovery codes */
						_n( '%d unused recovery code remains.', '%d unused recovery codes remain.', Two_Factor::recovery_codes_left( (int) $user->ID ), 'wp-security-center' ),
						Two_Factor::recovery_codes_left( (int) $user->ID )
					)
				)
			);
		} else {
			echo '<p><strong>' . esc_html__( 'Off.', 'wp-security-center' ) . '</strong> '
				. esc_html__( 'A stolen password is enough to sign in to this account.', 'wp-security-center' ) . '</p>';
		}

		if ( $own ) {
			printf(
				'<p><a class="button" href="%s">%s</a></p>',
				esc_url( self::url() ),
				esc_html( $active ? __( 'Manage two-factor authentication', 'wp-security-center' ) : __( 'Set up two-factor authentication', 'wp-security-center' ) )
			);
		} elseif ( $active && current_user_can( 'edit_user', (int) $user->ID ) ) {
			echo '<p><label><input type="checkbox" name="wpsec_2fa_reset" value="1"> '
				. esc_html__( 'Reset two-factor authentication for this user', 'wp-security-center' ) . '</label><br>'
				. '<span class="description">'
				. esc_html__( 'Use this when they have lost the authenticator, the recovery codes and access to their mailbox. They will have to set it up again, and the reset is recorded in the event log.', 'wp-security-center' )
				. '</span></p>';
		}

		echo '</td></tr></table>';
	}

	/**
	 * Nag an administrator who is required to enrol but has not yet.
	 */
	public function grace_notice(): void {
		$user = wp_get_current_user();

		if ( ! $user->exists() || ! Two_Factor::in_grace( $user ) ) {
			return;
		}

		$days = max( 0, (int) ceil( ( Two_Factor::grace_ends() - time() ) / DAY_IN_SECONDS ) );

		printf(
			'<div class="notice notice-warning"><p>%s <a href="%s">%s</a></p></div>',
			esc_html(
				sprintf(
					/* translators: %d: days left before two-factor becomes mandatory */
					_n(
						'This site requires administrators to use two-factor authentication. You have %d day left to set it up before you cannot sign in without it.',
						'This site requires administrators to use two-factor authentication. You have %d days left to set it up before you cannot sign in without it.',
						$days,
						'wp-security-center'
					),
					$days
				)
			),
			esc_url( self::url() ),
			esc_html__( 'Set it up now', 'wp-security-center' )
		);
	}
}
