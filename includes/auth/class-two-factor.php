<?php
/**
 * Two-factor state, policy and verification.
 *
 * Everything about a user's second factor lives here: the enrolment handshake,
 * the stored secret, the recovery codes, the optional e-mail fallback, and the
 * question of who is required to have one. The login flow and the admin screens
 * are deliberately thin wrappers around this class.
 *
 * Three rules shape the design:
 *
 *   - A code is accepted once. TOTP codes stay valid for a whole time step, so
 *     the last accepted step is recorded and a replay is refused.
 *   - Every path fails closed. An undecryptable secret, a missing OpenSSL, a
 *     broken option — none of them let a login through unchallenged.
 *   - Recovery is possible without the database being readable in the clear.
 *     Recovery codes are hashed, so rotating the site's salts destroys the TOTP
 *     secrets but leaves a way back in.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Two_Factor {

	// User meta. Everything is per-user; there is no shared state.
	public const META_SECRET     = 'wpsec_2fa_secret';
	public const META_PENDING    = 'wpsec_2fa_pending';
	public const META_ENABLED_AT = 'wpsec_2fa_enabled_at';
	public const META_LAST_SLOT  = 'wpsec_2fa_last_slot';
	public const META_RECOVERY   = 'wpsec_2fa_recovery';
	public const META_EMAIL_CODE = 'wpsec_2fa_email_code';

	/** How many recovery codes are minted at a time. */
	public const RECOVERY_COUNT = 10;

	/** Characters per recovery code. 10 of these is ~50 bits of entropy. */
	private const RECOVERY_LENGTH = 10;

	private const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

	/** Wrong e-mail codes tolerated before the code is thrown away. */
	private const EMAIL_MAX_ATTEMPTS = 5;

	// -------------------------------------------------------------------------
	// Settings
	// -------------------------------------------------------------------------

	/**
	 * @return array<string, mixed>
	 */
	public static function settings(): array {
		return array_merge(
			Installer::default_two_factor(),
			(array) get_option( Installer::OPTION_2FA, [] )
		);
	}

	/**
	 * Is the feature usable at all on this installation?
	 */
	public static function is_available(): bool {
		$settings = self::settings();

		return ! empty( $settings['enabled'] ) && Secret_Cipher::is_available();
	}

	/**
	 * Does this user have a working second factor right now?
	 */
	public static function is_active_for( int $user_id ): bool {
		if ( ! self::is_available() || $user_id <= 0 ) {
			return false;
		}

		return '' !== self::secret_for( $user_id );
	}

	/**
	 * Is this user covered by the "administrators must use it" rule?
	 */
	public static function required_for( \WP_User $user ): bool {
		$settings = self::settings();

		if ( empty( $settings['require_admins'] ) || ! self::is_available() ) {
			return false;
		}

		return user_can( $user, Admin::CAP );
	}

	/**
	 * When the grace period for the requirement runs out.
	 *
	 * The clock starts when the requirement is switched on, not when the plugin
	 * was installed — turning it on must never lock out an administrator who is
	 * mid-session and has no phone to hand.
	 */
	public static function grace_ends(): int {
		$settings = self::settings();
		$since    = (int) ( $settings['required_since'] ?? 0 );

		if ( $since <= 0 ) {
			return 0;
		}

		return $since + ( max( 0, (int) ( $settings['grace_days'] ?? 7 ) ) * DAY_IN_SECONDS );
	}

	/**
	 * Should this user be sent to enrolment before being let in?
	 */
	public static function must_enrol( \WP_User $user ): bool {
		if ( ! self::required_for( $user ) || self::is_active_for( (int) $user->ID ) ) {
			return false;
		}

		return time() >= self::grace_ends();
	}

	/**
	 * Required, not yet enrolled, but still inside the grace period.
	 */
	public static function in_grace( \WP_User $user ): bool {
		if ( ! self::required_for( $user ) || self::is_active_for( (int) $user->ID ) ) {
			return false;
		}

		return time() < self::grace_ends();
	}

	// -------------------------------------------------------------------------
	// Enrolment
	// -------------------------------------------------------------------------

	/**
	 * Start (or restart) enrolment and return the secret to display.
	 *
	 * The secret is held as "pending" until a code proves the authenticator
	 * actually has it. Activating on trust would let a user lock themselves out
	 * by mistyping the setup key.
	 */
	public static function start_enrolment( int $user_id ): string {
		$secret = Totp::generate_secret();
		$sealed = Secret_Cipher::encrypt( $secret );

		if ( '' === $sealed ) {
			return '';
		}

		update_user_meta( $user_id, self::META_PENDING, $sealed );

		return $secret;
	}

	public static function pending_secret( int $user_id ): string {
		return Secret_Cipher::decrypt( (string) get_user_meta( $user_id, self::META_PENDING, true ) );
	}

	/**
	 * Confirm enrolment with a code from the authenticator.
	 *
	 * @return string[]|null The recovery codes, in the clear and shown once, or
	 *                       null when the code did not match.
	 */
	public static function confirm_enrolment( int $user_id, string $code ): ?array {
		$secret = self::pending_secret( $user_id );

		if ( '' === $secret ) {
			return null;
		}

		$slot = Totp::verify( $secret, $code, time() );

		if ( null === $slot ) {
			return null;
		}

		update_user_meta( $user_id, self::META_SECRET, (string) get_user_meta( $user_id, self::META_PENDING, true ) );
		update_user_meta( $user_id, self::META_ENABLED_AT, time() );
		update_user_meta( $user_id, self::META_LAST_SLOT, $slot );
		delete_user_meta( $user_id, self::META_PENDING );

		$codes = self::generate_recovery_codes( $user_id );

		$user = get_userdata( $user_id );

		Logger::log(
			'2fa.enabled',
			[
				'object_id'    => (string) $user_id,
				'object_label' => $user ? (string) $user->user_login : (string) $user_id,
				'target_user'  => $user_id,
				'message'      => sprintf(
					'Two-factor authentication was switched on for "%s".',
					$user ? $user->user_login : $user_id
				),
				'data'         => [ 'recovery_codes' => count( $codes ) ],
			]
		);

		return $codes;
	}

	/**
	 * Turn the second factor off and forget everything about it.
	 *
	 * @param string $reason Free text for the log: "self", "admin", "reset".
	 */
	public static function disable( int $user_id, string $reason = 'self' ): void {
		$was_active = self::is_active_for( $user_id );

		foreach ( [ self::META_SECRET, self::META_PENDING, self::META_ENABLED_AT, self::META_LAST_SLOT, self::META_RECOVERY, self::META_EMAIL_CODE ] as $meta ) {
			delete_user_meta( $user_id, $meta );
		}

		if ( ! $was_active ) {
			return;
		}

		$user  = get_userdata( $user_id );
		$login = $user ? (string) $user->user_login : (string) $user_id;

		Logger::log(
			'admin' === $reason ? '2fa.reset_by_admin' : '2fa.disabled',
			[
				'object_id'    => (string) $user_id,
				'object_label' => $login,
				'target_user'  => $user_id,
				'message'      => 'admin' === $reason
					? sprintf( 'Two-factor authentication was reset for "%s" by another administrator.', $login )
					: sprintf( 'Two-factor authentication was switched off for "%s".', $login ),
				'data'         => [ 'reason' => $reason ],
			]
		);
	}

	public static function secret_for( int $user_id ): string {
		return Secret_Cipher::decrypt( (string) get_user_meta( $user_id, self::META_SECRET, true ) );
	}

	// -------------------------------------------------------------------------
	// Verification
	// -------------------------------------------------------------------------

	/**
	 * Check a submitted code against every factor this user has.
	 *
	 * @return string|false The method that matched — "totp", "recovery" or
	 *                      "email" — or false.
	 */
	public static function verify( \WP_User $user, string $code ) {
		$user_id = (int) $user->ID;
		$code    = trim( $code );

		if ( '' === $code ) {
			return false;
		}

		if ( self::verify_totp( $user_id, $code ) ) {
			return 'totp';
		}

		if ( self::consume_email_code( $user, $code ) ) {
			return 'email';
		}

		if ( self::consume_recovery_code( $user, $code ) ) {
			return 'recovery';
		}

		return false;
	}

	private static function verify_totp( int $user_id, string $code ): bool {
		$secret = self::secret_for( $user_id );

		if ( '' === $secret ) {
			return false;
		}

		$slot = Totp::verify( $secret, $code, time() );

		if ( null === $slot ) {
			return false;
		}

		// A TOTP code is valid for a whole 30-second step, and the drift window
		// widens that to 90. Accepting the same step twice would leave a code
		// captured over the shoulder — or by a proxy — usable a second time.
		if ( $slot <= (int) get_user_meta( $user_id, self::META_LAST_SLOT, true ) ) {
			return false;
		}

		update_user_meta( $user_id, self::META_LAST_SLOT, $slot );

		return true;
	}

	// -------------------------------------------------------------------------
	// Recovery codes
	// -------------------------------------------------------------------------

	/**
	 * Mint a fresh set, discarding any that already existed.
	 *
	 * @return string[] The codes in the clear. This is the only time they exist
	 *                  in readable form — only hashes are stored.
	 */
	public static function generate_recovery_codes( int $user_id ): array {
		$codes  = [];
		$hashes = [];

		for ( $i = 0; $i < self::RECOVERY_COUNT; $i++ ) {
			$code = '';

			for ( $c = 0; $c < self::RECOVERY_LENGTH; $c++ ) {
				$code .= self::RECOVERY_ALPHABET[ random_int( 0, strlen( self::RECOVERY_ALPHABET ) - 1 ) ];
			}

			$codes[]  = $code;
			$hashes[] = self::hash_recovery_code( $code );
		}

		update_user_meta( $user_id, self::META_RECOVERY, $hashes );

		return $codes;
	}

	public static function recovery_codes_left( int $user_id ): int {
		return count( (array) get_user_meta( $user_id, self::META_RECOVERY, true ) );
	}

	/**
	 * A recovery code is single-use: matching one removes it.
	 */
	private static function consume_recovery_code( \WP_User $user, string $code ): bool {
		$user_id = (int) $user->ID;
		$stored  = (array) get_user_meta( $user_id, self::META_RECOVERY, true );

		if ( empty( $stored ) ) {
			return false;
		}

		$candidate = self::hash_recovery_code( $code );
		$matched   = null;

		foreach ( $stored as $index => $hash ) {
			if ( hash_equals( (string) $hash, $candidate ) ) {
				$matched = $index;
			}
		}

		if ( null === $matched ) {
			return false;
		}

		unset( $stored[ $matched ] );
		update_user_meta( $user_id, self::META_RECOVERY, array_values( $stored ) );

		$left = count( $stored );

		Logger::log(
			'2fa.recovery_code_used',
			[
				'object_id'    => (string) $user_id,
				'object_label' => (string) $user->user_login,
				'target_user'  => $user_id,
				'ip'           => (string) Context::client_ip(),
				'message'      => sprintf(
					'"%s" signed in with a two-factor recovery code. %d of %d codes remain.',
					$user->user_login,
					$left,
					self::RECOVERY_COUNT
				),
				'data'         => [ 'codes_left' => $left ],
			]
		);

		return true;
	}

	/**
	 * Codes are high-entropy random strings, so a fast hash is the right tool:
	 * there is nothing to brute-force and nothing to slow down.
	 */
	private static function hash_recovery_code( string $code ): string {
		$normalised = strtoupper( (string) preg_replace( '/[^A-Za-z0-9]+/', '', $code ) );

		return hash_hmac( 'sha256', $normalised, wp_salt( 'nonce' ) );
	}

	// -------------------------------------------------------------------------
	// E-mail fallback
	// -------------------------------------------------------------------------

	public static function email_fallback_enabled(): bool {
		$settings = self::settings();

		return self::is_available() && ! empty( $settings['email_fallback'] );
	}

	/**
	 * Mail a one-time code to the account's own address.
	 *
	 * This is a genuine weakening of two-factor authentication and is off by
	 * default: whoever reads the mailbox can complete the login. It exists for
	 * the case the whole feature otherwise fails on — the authenticator is gone
	 * and the recovery codes with it.
	 *
	 * @return true|\WP_Error
	 */
	public static function send_email_code( \WP_User $user ) {
		if ( ! self::email_fallback_enabled() ) {
			return new \WP_Error( 'wpsec_2fa_no_email', __( 'The e-mail fallback is switched off on this site.', 'sentinel-security-center' ) );
		}

		$user_id = (int) $user->ID;
		$state   = (array) get_user_meta( $user_id, self::META_EMAIL_CODE, true );

		// One code per minute, so the endpoint cannot be used to flood an
		// inbox or to fish for whether an account exists.
		if ( ! empty( $state['sent'] ) && ( time() - (int) $state['sent'] ) < MINUTE_IN_SECONDS ) {
			return new \WP_Error( 'wpsec_2fa_email_throttled', __( 'A code was just sent. Check your inbox before requesting another.', 'sentinel-security-center' ) );
		}

		$settings = self::settings();
		$ttl      = max( 2, min( 60, (int) ( $settings['email_ttl_min'] ?? 10 ) ) ) * MINUTE_IN_SECONDS;
		$code     = str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );

		update_user_meta(
			$user_id,
			self::META_EMAIL_CODE,
			[
				'hash'     => self::hash_recovery_code( $code ),
				'expires'  => time() + $ttl,
				'sent'     => time(),
				'attempts' => 0,
			]
		);

		$site = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );

		$body = sprintf(
			/* translators: 1: site name, 2: the one-time code, 3: minutes until it expires, 4: client IP address */
			__(
				"Someone is signing in to %1\$s as you and asked for a one-time code because their authenticator app was unavailable.\n\nYour code is: %2\$s\n\nIt expires in %3\$d minutes and can be used once.\n\nThe request came from %4\$s.\n\nIf this was not you, someone knows your password. Change it now and tell an administrator.",
				'sentinel-security-center'
			),
			$site,
			$code,
			(int) ( $ttl / MINUTE_IN_SECONDS ),
			(string) Context::client_ip()
		);

		$sent = Mailer::send_to(
			(string) $user->user_email,
			/* translators: %s: site name */
			sprintf( __( 'Your sign-in code for %s', 'sentinel-security-center' ), $site ),
			$body
		);

		Logger::log(
			'2fa.email_code_sent',
			[
				'object_id'    => (string) $user_id,
				'object_label' => (string) $user->user_login,
				'target_user'  => $user_id,
				'ip'           => (string) Context::client_ip(),
				'message'      => sprintf(
					'A one-time sign-in code was e-mailed to "%s" because the authenticator app was unavailable.',
					$user->user_login
				),
				'data'         => [ 'delivered' => $sent ],
			]
		);

		if ( ! $sent ) {
			// Nothing was delivered, so the stored code is unusable. Clearing
			// it also clears the one-per-minute throttle, which would
			// otherwise punish the user for the mail server's failure.
			delete_user_meta( $user_id, self::META_EMAIL_CODE );

			return new \WP_Error( 'wpsec_2fa_email_failed', __( 'The code could not be sent. Check the site\'s mail configuration.', 'sentinel-security-center' ) );
		}

		return true;
	}

	private static function consume_email_code( \WP_User $user, string $code ): bool {
		if ( ! self::email_fallback_enabled() ) {
			return false;
		}

		$user_id = (int) $user->ID;
		$state   = (array) get_user_meta( $user_id, self::META_EMAIL_CODE, true );

		if ( empty( $state['hash'] ) || time() > (int) ( $state['expires'] ?? 0 ) ) {
			return false;
		}

		if ( (int) ( $state['attempts'] ?? 0 ) >= self::EMAIL_MAX_ATTEMPTS ) {
			delete_user_meta( $user_id, self::META_EMAIL_CODE );
			return false;
		}

		if ( ! hash_equals( (string) $state['hash'], self::hash_recovery_code( $code ) ) ) {
			$state['attempts'] = (int) ( $state['attempts'] ?? 0 ) + 1;
			update_user_meta( $user_id, self::META_EMAIL_CODE, $state );
			return false;
		}

		delete_user_meta( $user_id, self::META_EMAIL_CODE );

		Logger::log(
			'2fa.email_code_used',
			[
				'object_id'    => (string) $user_id,
				'object_label' => (string) $user->user_login,
				'target_user'  => $user_id,
				'ip'           => (string) Context::client_ip(),
				'message'      => sprintf(
					'"%s" signed in with a one-time code sent by e-mail rather than an authenticator app.',
					$user->user_login
				),
				'data'         => [],
			]
		);

		return true;
	}

	// -------------------------------------------------------------------------
	// Enrolment display
	// -------------------------------------------------------------------------

	public static function provisioning_uri( \WP_User $user, string $secret ): string {
		$issuer = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );

		if ( '' === trim( $issuer ) ) {
			$issuer = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		}

		return Totp::provisioning_uri( $secret, (string) $user->user_login, $issuer );
	}

	/**
	 * The QR code as inline SVG.
	 *
	 * Rendered locally — sending the provisioning URI to an external QR service
	 * would hand the shared secret to a third party. A missing or broken vendor
	 * directory degrades to "no image"; the setup screen then falls back to the
	 * typed secret, which works everywhere.
	 *
	 * @return string '' when no renderer is available.
	 */
	public static function qr_svg( string $uri, int $size = 220 ): string {
		if ( ! class_exists( '\BaconQrCode\Writer' ) ) {
			$autoload = WPSEC_DIR . 'vendor/autoload.php';

			if ( ! is_readable( $autoload ) ) {
				return '';
			}

			require_once $autoload;

			if ( ! class_exists( '\BaconQrCode\Writer' ) ) {
				return '';
			}
		}

		try {
			$renderer = new \BaconQrCode\Renderer\ImageRenderer(
				new \BaconQrCode\Renderer\RendererStyle\RendererStyle( $size, 1 ),
				new \BaconQrCode\Renderer\Image\SvgImageBackEnd()
			);

			$svg = ( new \BaconQrCode\Writer( $renderer ) )->writeString( $uri );
		} catch ( \Throwable $e ) {
			return '';
		}

		// Strip the XML declaration: this is going inline into an HTML page.
		return (string) preg_replace( '/^<\?xml[^>]*\?>\s*/', '', $svg );
	}
}
