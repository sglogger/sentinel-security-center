<?php
/**
 * The second-factor step of an interactive login.
 *
 * WordPress has no hook between "the password was right" and "the session is
 * issued", so this works the way every 2FA plugin has to: `wp_login` fires
 * after wp_signon() has already set the cookie, and the first thing done here
 * is to destroy that session again. The user is then held on an interstitial
 * until they prove the second factor, and only then is a cookie issued for
 * real.
 *
 * Application passwords, REST and XML-RPC are deliberately out of scope. They
 * are non-interactive by definition — there is nobody to type a code — and an
 * application password is already a separate, revocable credential.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Two_Factor_Login {

	/** The wp-login.php action this class answers on. */
	public const ACTION = 'wpsec_2fa';

	private const META_NONCE = 'wpsec_2fa_login_nonce';

	/** How long a half-finished login may sit on the interstitial. */
	private const NONCE_TTL = 15 * MINUTE_IN_SECONDS;

	private const MAX_ATTEMPTS   = 10;
	private const ATTEMPT_WINDOW = 15 * MINUTE_IN_SECONDS;

	/** The session token wp_set_auth_cookie() just created, if it did. */
	private string $session_token = '';

	public function register(): void {
		add_action( 'set_logged_in_cookie', [ $this, 'remember_token' ], 10, 6 );
		add_action( 'wp_login', [ $this, 'maybe_challenge' ], 20, 2 );
		add_action( 'login_form_' . self::ACTION, [ $this, 'handle' ] );
	}

	/**
	 * Note the session token as it is minted.
	 *
	 * wp_set_auth_cookie() creates the session before `wp_login` fires but does
	 * not populate $_COOKIE, so wp_get_session_token() cannot see it. Catching
	 * it here means exactly one session is destroyed — the half-finished one —
	 * instead of every session the user has open elsewhere.
	 *
	 * @param string $cookie     The cookie value.
	 * @param int    $expire     Cookie expiry.
	 * @param int    $expiration Session expiry.
	 * @param int    $user_id    User the cookie is for.
	 * @param string $scheme     Cookie scheme.
	 * @param string $token      Session token.
	 */
	public function remember_token( $cookie = '', $expire = 0, $expiration = 0, $user_id = 0, $scheme = '', $token = '' ): void {
		$this->session_token = (string) $token;
	}

	/**
	 * @param string        $user_login The login name.
	 * @param \WP_User|null $user       The user that just authenticated.
	 */
	public function maybe_challenge( $user_login = '', $user = null ): void {
		if ( ! $user instanceof \WP_User || ! Two_Factor::is_available() ) {
			return;
		}

		if ( Login_Guard::is_api_auth() ) {
			return;
		}

		if ( Two_Factor::is_active_for( (int) $user->ID ) ) {
			$stage = 'verify';
		} elseif ( Two_Factor::must_enrol( $user ) ) {
			$stage = 'enrol';
		} else {
			return;
		}

		$this->undo_login( $user );

		$nonce = $this->issue_nonce( (int) $user->ID, $stage );

		Logger::log(
			'2fa.challenge_issued',
			[
				'object_id'    => (string) $user->ID,
				'object_label' => (string) $user->user_login,
				'target_user'  => (int) $user->ID,
				'ip'           => (string) Context::client_ip(),
				'message'      => 'enrol' === $stage
					? sprintf( '"%s" signed in correctly but must set up two-factor authentication before the session is issued.', $user->user_login )
					: sprintf( '"%s" signed in correctly and was asked for a second factor.', $user->user_login ),
				'data'         => [ 'stage' => $stage ],
			]
		);

		$this->render(
			$user,
			$stage,
			$nonce,
			$this->requested_redirect(),
			$this->requested_remember()
		);
	}

	/**
	 * Handle the interstitial's submission.
	 */
	public function handle(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- the login nonce below IS the nonce; a WordPress nonce needs a session this half-authenticated request does not have.
		$user_id    = isset( $_POST['wpsec_user'] ) ? absint( wp_unslash( $_POST['wpsec_user'] ) ) : 0;
		$nonce      = isset( $_POST['wpsec_nonce'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['wpsec_nonce'] ) ) : '';
		$code       = isset( $_POST['wpsec_code'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['wpsec_code'] ) ) : '';
		$wants_mail = isset( $_POST['wpsec_send_email'] );
		$remember   = ! empty( $_POST['rememberme'] );
		$redirect   = isset( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( (string) $_POST['redirect_to'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		$user  = $user_id > 0 ? get_userdata( $user_id ) : false;
		$stage = $this->check_nonce( $user_id, $nonce );

		if ( ! $user instanceof \WP_User || null === $stage ) {
			// Expired, tampered with, or replayed. Back to the login form with
			// no hint about which of those it was.
			wp_safe_redirect( wp_login_url( $redirect ) );
			exit;
		}

		if ( ! $this->attempt_allowed( $user_id ) ) {
			$this->render( $user, $stage, $nonce, $redirect, $remember, __( 'Too many attempts. Wait a few minutes and sign in again.', 'wp-security-center' ) );
		}

		if ( $wants_mail && 'verify' === $stage ) {
			$sent = Two_Factor::send_email_code( $user );

			$this->render(
				$user,
				$stage,
				$nonce,
				$redirect,
				$remember,
				is_wp_error( $sent ) ? $sent->get_error_message() : '',
				is_wp_error( $sent ) ? '' : __( 'A one-time code is on its way to the address on your account.', 'wp-security-center' )
			);
		}

		if ( 'enrol' === $stage ) {
			$codes = Two_Factor::confirm_enrolment( $user_id, $code );

			if ( null === $codes ) {
				$this->count_failure( $user, 'enrol' );
				$this->render( $user, $stage, $nonce, $redirect, $remember, __( 'That code was not right. Check the app and try the current code.', 'wp-security-center' ) );
			}

			$this->complete( $user, $remember, $redirect, $codes );
		}

		$method = Two_Factor::verify( $user, $code );

		if ( false === $method ) {
			$this->count_failure( $user, 'verify' );
			$this->render( $user, $stage, $nonce, $redirect, $remember, __( 'That code was not right, or it has already been used.', 'wp-security-center' ) );
		}

		$this->complete( $user, $remember, $redirect, null, (string) $method );
	}

	// -------------------------------------------------------------------------
	// Session handling
	// -------------------------------------------------------------------------

	/**
	 * Throw away the session wp_signon() just created.
	 */
	private function undo_login( \WP_User $user ): void {
		if ( '' !== $this->session_token ) {
			\WP_Session_Tokens::get_instance( (int) $user->ID )->destroy( $this->session_token );
			$this->session_token = '';
		}

		wp_clear_auth_cookie();
		wp_set_current_user( 0 );
	}

	/**
	 * Issue the session for real, now that the second factor is proven.
	 *
	 * @param string[]|null $recovery_codes Codes to show once, after enrolment.
	 */
	private function complete( \WP_User $user, bool $remember, string $redirect, ?array $recovery_codes = null, string $method = 'totp' ): void {
		delete_user_meta( (int) $user->ID, self::META_NONCE );
		delete_transient( $this->attempt_key( (int) $user->ID ) );

		wp_set_current_user( (int) $user->ID );
		wp_set_auth_cookie( (int) $user->ID, $remember );

		Logger::log(
			'2fa.challenge_passed',
			[
				'object_id'    => (string) $user->ID,
				'object_label' => (string) $user->user_login,
				'target_user'  => (int) $user->ID,
				'ip'           => (string) Context::client_ip(),
				'message'      => sprintf( '"%s" completed the second factor and the session was issued.', $user->user_login ),
				'data'         => [ 'method' => null !== $recovery_codes ? 'enrolment' : $method ],
			]
		);

		$target = $this->safe_redirect_target( $redirect, $user );

		if ( null !== $recovery_codes ) {
			$this->render_recovery_codes( $recovery_codes, $target );
		}

		wp_safe_redirect( $target );
		exit;
	}

	private function safe_redirect_target( string $redirect, \WP_User $user ): string {
		$fallback = user_can( $user, 'read' ) ? admin_url() : home_url();

		if ( '' === $redirect ) {
			return $fallback;
		}

		return wp_validate_redirect( $redirect, $fallback );
	}

	// -------------------------------------------------------------------------
	// The login nonce
	// -------------------------------------------------------------------------

	private function issue_nonce( int $user_id, string $stage ): string {
		$nonce = bin2hex( random_bytes( 24 ) );

		update_user_meta(
			$user_id,
			self::META_NONCE,
			[
				'hash'    => hash( 'sha256', $nonce ),
				'stage'   => $stage,
				'expires' => time() + self::NONCE_TTL,
			]
		);

		return $nonce;
	}

	/**
	 * @return string|null The stage this nonce was issued for, or null.
	 */
	private function check_nonce( int $user_id, string $nonce ): ?string {
		if ( $user_id <= 0 || '' === $nonce ) {
			return null;
		}

		$stored = (array) get_user_meta( $user_id, self::META_NONCE, true );

		if ( empty( $stored['hash'] ) || time() > (int) ( $stored['expires'] ?? 0 ) ) {
			return null;
		}

		if ( ! hash_equals( (string) $stored['hash'], hash( 'sha256', $nonce ) ) ) {
			return null;
		}

		return (string) ( $stored['stage'] ?? 'verify' );
	}

	// -------------------------------------------------------------------------
	// Rate limiting
	// -------------------------------------------------------------------------

	private function attempt_key( int $user_id ): string {
		return 'wpsec_2fa_att_' . hash( 'sha256', $user_id . '|' . (string) Context::client_ip() );
	}

	private function attempt_allowed( int $user_id ): bool {
		return (int) get_transient( $this->attempt_key( $user_id ) ) < self::MAX_ATTEMPTS;
	}

	private function count_failure( \WP_User $user, string $stage ): void {
		$key   = $this->attempt_key( (int) $user->ID );
		$count = (int) get_transient( $key ) + 1;

		set_transient( $key, $count, self::ATTEMPT_WINDOW );

		Logger::log(
			'2fa.challenge_failed',
			[
				'object_id'    => (string) $user->ID,
				'object_label' => (string) $user->user_login,
				'target_user'  => (int) $user->ID,
				'ip'           => (string) Context::client_ip(),
				'message'      => sprintf(
					'A second-factor code for "%s" was wrong. The password was correct, so whoever submitted it has valid credentials. Attempt %d of %d before the challenge is locked.',
					$user->user_login,
					$count,
					self::MAX_ATTEMPTS
				),
				'data'         => [
					'stage'    => $stage,
					'attempts' => $count,
				],
			]
		);
	}

	// -------------------------------------------------------------------------
	// Rendering
	// -------------------------------------------------------------------------

	private function requested_redirect(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading the login form's own field, validated through wp_validate_redirect() before use.
		return isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( (string) $_REQUEST['redirect_to'] ) ) : '';
	}

	private function requested_remember(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading the login form's own checkbox.
		return ! empty( $_REQUEST['rememberme'] );
	}

	/**
	 * Render the interstitial and stop. This never returns.
	 */
	private function render( \WP_User $user, string $stage, string $nonce, string $redirect, bool $remember, string $error = '', string $notice = '' ): void {
		$secret = '';
		$uri    = '';
		$svg    = '';

		if ( 'enrol' === $stage ) {
			$secret = Two_Factor::pending_secret( (int) $user->ID );

			if ( '' === $secret ) {
				$secret = Two_Factor::start_enrolment( (int) $user->ID );
			}

			$uri = Two_Factor::provisioning_uri( $user, $secret );
			$svg = Two_Factor::qr_svg( $uri );
		}

		$this->page_header(
			'enrol' === $stage
				? __( 'Set up two-factor authentication', 'wp-security-center' )
				: __( 'Two-factor authentication', 'wp-security-center' )
		);

		if ( '' !== $error ) {
			echo '<div id="login_error">' . esc_html( $error ) . '</div>';
		}

		if ( '' !== $notice ) {
			echo '<p class="message">' . esc_html( $notice ) . '</p>';
		}

		echo '<form name="wpsec2fa" id="loginform" method="post" action="' . esc_url( add_query_arg( 'action', self::ACTION, wp_login_url() ) ) . '">';

		if ( 'enrol' === $stage ) {
			echo '<p>' . esc_html__( 'This site requires administrators to use an authenticator app. Scan the code below, then enter the six digits it shows.', 'wp-security-center' ) . '</p>';
			$this->render_enrolment_key( $secret, $uri, $svg );
		} else {
			echo '<p>' . esc_html__( 'Enter the six-digit code from your authenticator app. A recovery code works here too.', 'wp-security-center' ) . '</p>';
		}

		?>
		<p>
			<label for="wpsec_code"><?php esc_html_e( 'Authentication code', 'wp-security-center' ); ?></label>
			<input type="text" name="wpsec_code" id="wpsec_code" class="input" value="" size="20"
				autocomplete="one-time-code" inputmode="numeric" pattern="[0-9A-Za-z \-]*"
				autocapitalize="off" autocorrect="off" spellcheck="false" autofocus>
		</p>
		<input type="hidden" name="wpsec_user" value="<?php echo esc_attr( (string) $user->ID ); ?>">
		<input type="hidden" name="wpsec_nonce" value="<?php echo esc_attr( $nonce ); ?>">
		<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect ); ?>">
		<?php if ( $remember ) : ?>
			<input type="hidden" name="rememberme" value="forever">
		<?php endif; ?>
		<p class="submit">
			<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large"
				value="<?php echo esc_attr( 'enrol' === $stage ? __( 'Confirm and sign in', 'wp-security-center' ) : __( 'Sign in', 'wp-security-center' ) ); ?>">
		</p>
		<?php

		if ( 'verify' === $stage && Two_Factor::email_fallback_enabled() ) {
			?>
			<p style="margin-top:16px;border-top:1px solid #dcdcde;padding-top:16px;">
				<?php esc_html_e( 'Lost your authenticator?', 'wp-security-center' ); ?>
				<button type="submit" name="wpsec_send_email" value="1" class="button button-secondary" style="margin-left:6px;">
					<?php esc_html_e( 'E-mail me a code', 'wp-security-center' ); ?>
				</button>
			</p>
			<?php
		}

		echo '</form>';

		$this->page_footer();
		exit;
	}

	/**
	 * The scannable code plus the typed fallback.
	 */
	private function render_enrolment_key( string $secret, string $uri, string $svg ): void {
		if ( '' !== $svg ) {
			echo '<div style="text-align:center;margin:12px 0;">';
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- SVG generated locally by the bundled QR renderer from a URI we built ourselves.
			echo $svg;
			echo '</div>';
		}

		echo '<p style="margin:0 0 4px;"><small>' . esc_html__( 'Or type this key into the app:', 'wp-security-center' ) . '</small></p>';
		echo '<p style="margin:0 0 12px;"><code style="display:block;padding:8px;word-break:break-all;">'
			. esc_html( Totp::format_secret( $secret ) ) . '</code></p>';

		if ( '' !== $uri ) {
			echo '<p style="margin:0 0 12px;"><a href="' . esc_url( $uri, [ 'otpauth' ] ) . '">'
				. esc_html__( 'Open in an authenticator app on this device', 'wp-security-center' ) . '</a></p>';
		}
	}

	/**
	 * Show the recovery codes once, immediately after enrolment.
	 *
	 * @param string[] $codes  The codes, in the clear.
	 * @param string   $target Where "continue" goes.
	 */
	private function render_recovery_codes( array $codes, string $target ): void {
		$this->page_header( __( 'Save your recovery codes', 'wp-security-center' ) );

		echo '<p>' . esc_html__( 'Two-factor authentication is now on. These recovery codes are the way back in if you lose the authenticator. Each one works once. This is the only time they are shown.', 'wp-security-center' ) . '</p>';
		echo '<p><code style="display:block;padding:10px;line-height:1.9;">';

		foreach ( $codes as $code ) {
			echo esc_html( $code ) . '<br>';
		}

		echo '</code></p>';
		echo '<p class="submit"><a class="button button-primary button-large" href="' . esc_url( $target ) . '">'
			. esc_html__( 'I have saved them — continue', 'wp-security-center' ) . '</a></p>';

		$this->page_footer();
		exit;
	}

	private function page_header( string $title ): void {
		if ( function_exists( 'login_header' ) ) {
			login_header( $title, '' );
			return;
		}

		// wp_signon() called from somewhere other than wp-login.php. Rare, but
		// it must not produce a blank page.
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );

		echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>' . esc_html( $title ) . '</title>';
		echo '<meta name="viewport" content="width=device-width,initial-scale=1">';
		echo '</head><body style="font-family:sans-serif;max-width:420px;margin:60px auto;padding:0 16px;">';
		echo '<h1 style="font-size:20px;">' . esc_html( $title ) . '</h1>';
	}

	private function page_footer(): void {
		if ( function_exists( 'login_footer' ) ) {
			login_footer( 'wpsec_code' );
			return;
		}

		echo '</body></html>';
	}
}
