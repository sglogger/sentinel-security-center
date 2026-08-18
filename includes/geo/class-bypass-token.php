<?php
/**
 * Single-use, time-limited links that let a locked-out administrator back in.
 *
 * Split-token design: the selector is the lookup key and the verifier is the
 * secret, of which only a hash is stored. That way a database read cannot mint
 * a working link, and lookup does not need a timing-safe search.
 *
 * Stored in an option rather than a transient on purpose — an object-cache
 * flush must not destroy the token an administrator is about to click.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Bypass_Token {

	public const ACTION = 'wpsecbypass';

	private const MAX_LIVE       = 5;
	private const MIN_INTERVAL   = 15 * MINUTE_IN_SECONDS;
	private const ATTEMPT_WINDOW = 15 * MINUTE_IN_SECONDS;
	private const MAX_ATTEMPTS   = 10;

	public function register(): void {
		add_action( 'login_form_' . self::ACTION, [ $this, 'handle_redemption' ] );
	}

	/**
	 * Mint a token for a blocked login, or null when rate-limited or disabled.
	 *
	 * @return string|null The full token, "selector.verifier".
	 */
	public static function issue( int $user_id, string $blocked_ip, string $country ): ?string {
		$geo = (array) get_option( Installer::OPTION_GEO, [] );

		if ( empty( $geo['bypass_enabled'] ) ) {
			return null;
		}

		$tokens = self::live_tokens();

		if ( count( $tokens ) >= self::MAX_LIVE ) {
			return null;
		}

		// One unused token per user per interval, so a bot hammering a valid
		// password from a blocked country cannot flood the inbox.
		foreach ( $tokens as $token ) {
			if ( (int) ( $token['user_id'] ?? 0 ) === $user_id
				&& 0 === (int) ( $token['used_at'] ?? 0 )
				&& ( time() - (int) ( $token['created'] ?? 0 ) ) < self::MIN_INTERVAL ) {
				return null;
			}
		}

		$selector = bin2hex( random_bytes( 8 ) );
		$verifier = bin2hex( random_bytes( 32 ) );

		$ttl   = max( 5, min( 1440, (int) ( $geo['bypass_token_ttl_min'] ?? 60 ) ) );
		$hours = max( 1, min( 168, (int) ( $geo['bypass_grant_hours'] ?? 8 ) ) );

		$tokens[ $selector ] = [
			'verifier_hash'   => hash( 'sha256', $verifier ),
			'user_id'         => $user_id,
			'blocked_ip'      => $blocked_ip,
			'blocked_country' => $country,
			'created'         => time(),
			'expires'         => time() + ( $ttl * MINUTE_IN_SECONDS ),
			'used_at'         => 0,
			'grant_hours'     => $hours,
		];

		update_option( Installer::OPTION_BYPASS, $tokens, false );

		return $selector . '.' . $verifier;
	}

	public static function url( string $token ): string {
		return add_query_arg(
			[
				'action'      => self::ACTION,
				'wpsec_token' => rawurlencode( $token ),
			],
			wp_login_url()
		);
	}

	/**
	 * Handle a click on a bypass link.
	 *
	 * Every failure path renders the ordinary login form with no message at
	 * all, so the endpoint cannot be used to discover whether a selector
	 * exists.
	 */
	public function handle_redemption(): void {
		$ip = Context::client_ip();

		if ( ! $this->attempt_allowed( $ip ) ) {
			$this->fail( 'rate-limited', $ip );
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the token IS the credential; a nonce would require a session the locked-out user does not have.
		$raw = isset( $_GET['wpsec_token'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['wpsec_token'] ) ) : '';

		if ( ! preg_match( '/^([0-9a-f]{16})\.([0-9a-f]{64})$/', $raw, $m ) ) {
			$this->fail( 'malformed', $ip );
			return;
		}

		[ , $selector, $verifier ] = $m;

		$tokens = (array) get_option( Installer::OPTION_BYPASS, [] );
		$token  = $tokens[ $selector ] ?? null;

		if ( ! is_array( $token ) ) {
			$this->fail( 'unknown-selector', $ip );
			return;
		}

		if ( ! hash_equals( (string) ( $token['verifier_hash'] ?? '' ), hash( 'sha256', $verifier ) ) ) {
			$this->fail( 'bad-verifier', $ip );
			return;
		}

		if ( 0 !== (int) ( $token['used_at'] ?? 0 ) ) {
			$this->fail( 'already-used', $ip );
			return;
		}

		if ( time() > (int) ( $token['expires'] ?? 0 ) ) {
			$this->fail( 'expired', $ip );
			return;
		}

		// Consume before granting, so a race cannot redeem the same token twice.
		$tokens[ $selector ]['used_at'] = time();
		update_option( Installer::OPTION_BYPASS, $tokens, false );

		// The address that clicked the link is what gets allowed — not the one
		// that was blocked. Someone reading the alert on their phone is on a
		// different network than the laptop that was refused.
		if ( null === $ip ) {
			$this->fail( 'no-client-ip', $ip );
			return;
		}

		$hours = (int) ( $token['grant_hours'] ?? 8 );

		Allowlist::grant( $ip, $hours, (int) ( $token['user_id'] ?? 0 ), $selector );

		$user  = get_userdata( (int) ( $token['user_id'] ?? 0 ) );
		$login = $user ? (string) $user->user_login : '';

		Logger::log(
			'login.bypass_redeemed',
			[
				'object_id'    => $selector,
				'object_label' => $login,
				'target_user'  => (int) ( $token['user_id'] ?? 0 ),
				'ip'           => $ip,
				'message'      => sprintf(
					'A bypass link was redeemed from %s. That address may sign in for the next %d hours. The originally blocked address was %s (%s).',
					$ip,
					$hours,
					(string) ( $token['blocked_ip'] ?? '?' ),
					(string) ( $token['blocked_country'] ?? '?' )
				),
				'data'         => [
					'redeemed_from'   => $ip,
					'blocked_ip'      => (string) ( $token['blocked_ip'] ?? '' ),
					'blocked_country' => (string) ( $token['blocked_country'] ?? '' ),
					'grant_hours'     => $hours,
				],
			]
		);

		wp_safe_redirect(
			add_query_arg( 'wpsec_bypass', 'ok', wp_login_url() )
		);
		exit;
	}

	/**
	 * Render the normal login form, indistinguishable from any other visit.
	 */
	private function fail( string $reason, ?string $ip ): void {
		Logger::log(
			'login.bypass_rejected',
			[
				'object_id' => $reason,
				'ip'        => (string) ( $ip ?? '' ),
				'message'   => sprintf( 'A bypass link was rejected (%s).', $reason ),
				'data'      => [ 'reason' => $reason ],
			]
		);

		wp_safe_redirect( wp_login_url() );
		exit;
	}

	/**
	 * The one rate limit in this plugin. It guards an unauthenticated token
	 * endpoint, not a login, so it does not conflict with the decision not to
	 * process failed logins.
	 */
	private function attempt_allowed( ?string $ip ): bool {
		if ( null === $ip ) {
			return true;
		}

		$key   = 'wpsec_bypass_try_' . md5( $ip );
		$count = (int) get_transient( $key );

		if ( $count >= self::MAX_ATTEMPTS ) {
			return false;
		}

		set_transient( $key, $count + 1, self::ATTEMPT_WINDOW );

		return true;
	}

	/**
	 * Stored tokens with expired and long-consumed ones dropped.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function live_tokens(): array {
		$tokens = (array) get_option( Installer::OPTION_BYPASS, [] );
		$now    = time();
		$live   = [];

		foreach ( $tokens as $selector => $token ) {
			if ( ! is_array( $token ) ) {
				continue;
			}

			$expired = $now > (int) ( $token['expires'] ?? 0 );
			$used    = (int) ( $token['used_at'] ?? 0 );

			// Consumed tokens are kept briefly so a second click can be
			// recognised as a replay rather than an unknown selector.
			if ( $expired && ( 0 === $used || ( $now - $used ) > DAY_IN_SECONDS ) ) {
				continue;
			}

			$live[ $selector ] = $token;
		}

		if ( count( $live ) !== count( $tokens ) ) {
			update_option( Installer::OPTION_BYPASS, $live, false );
		}

		return $live;
	}
}
