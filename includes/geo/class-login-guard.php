<?php
/**
 * Wires the access decision into WordPress authentication.
 *
 * Hooked on `authenticate` at priority 50: after the credential checks
 * (priority 20) and before wp_authenticate_spam_check (99). At that point
 * $user is a WP_User only if the credentials were valid — which is exactly the
 * requirement, since only successful authentication is of interest here.
 * Returning a WP_Error makes wp_signon() bail before wp_set_auth_cookie(), so
 * no cookie is issued and no session token is created.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Login_Guard {

	public function register(): void {
		add_filter( 'authenticate', [ $this, 'evaluate' ], 50, 3 );
		add_action( 'wp_login', [ $this, 'on_login' ], 10, 2 );
		add_action( 'wp_logout', [ $this, 'on_logout' ], 10, 1 );
	}

	/**
	 * @param \WP_User|\WP_Error|null $user     Result so far.
	 * @param string                  $username Submitted username.
	 * @param string                  $password Submitted password.
	 * @return \WP_User|\WP_Error|null
	 */
	public function evaluate( $user, $username = '', $password = '' ) {
		// Credentials were wrong, or another filter already rejected. Failed
		// logins are deliberately not processed at all by this plugin.
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}

		$geo      = (array) get_option( Installer::OPTION_GEO, [] );
		$ip       = Context::client_ip();
		$resolved = Country_Resolver::resolve( $ip );

		$decision = Access_Policy::decide(
			[
				'ip'                => $ip,
				'country'           => $resolved['country'],
				'enabled'           => ! empty( $geo['enabled'] ),
				'mode'              => (string) ( $geo['mode'] ?? 'monitor' ),
				'countries'         => (array) ( $geo['countries'] ?? [] ),
				'allow_ips'         => Allowlist::stat(),
				'temp_allow_ips'    => Allowlist::temporary(),
				'kill_switch'       => self::kill_switch_active(),
				'geoip_healthy'     => Country_Resolver::is_healthy(),
				'is_api_auth'       => self::is_api_auth(),
				'apply_to_api_auth' => ! empty( $geo['apply_to_api_auth'] ),
			]
		);

		// The subsystem is broken rather than the address being unknown: stand
		// blocking down so a missing database file cannot seal the site.
		if ( ! empty( $decision['disarm'] ) ) {
			$geo['mode'] = 'monitor';
			update_option( Installer::OPTION_GEO, $geo );
		}

		if ( Access_Policy::BLOCK === $decision['action'] ) {
			return $this->block( $user, $ip, $decision );
		}

		if ( '' !== $decision['event'] ) {
			$this->record( $decision['event'], $user, $ip, $decision, $resolved['source'] );
		}

		// Remember the verdict so wp_login does not log the same login twice.
		$GLOBALS['wpsec_login_logged'] = true;

		return $user;
	}

	/**
	 * @param \WP_User             $user     The authenticated user.
	 * @param string|null          $ip       Client address.
	 * @param array<string, mixed> $decision Policy verdict.
	 */
	private function block( \WP_User $user, ?string $ip, array $decision ): \WP_Error {
		$token = Bypass_Token::issue( (int) $user->ID, (string) $ip, (string) $decision['country'] );

		$log_id = $this->record( 'login.blocked_geo', $user, $ip, $decision, 'policy', $token );

		if ( null !== $token ) {
			Logger::log(
				'login.bypass_issued',
				[
					'object_id'   => (string) $log_id,
					'target_user' => (int) $user->ID,
					'ip'          => (string) $ip,
					'message'     => 'A single-use bypass link was e-mailed to the configured recipients.',
					'data'        => [ 'grant_hours' => 8 ],
				]
			);
		}

		// The message is byte-identical to the core wrong-password error, so
		// nothing on the login screen betrays that a geo rule exists. The error
		// CODE is our own, so third-party brute-force plugins keyed on core
		// codes do not count this against the address.
		return new \WP_Error(
			'wpsec_geo_blocked',
			__( '<strong>Error:</strong> The username or password you entered is incorrect.' ) // phpcs:ignore WordPress.WP.I18n.MissingArgDomain -- deliberately reuses the core string so the wording matches exactly.
		);
	}

	/**
	 * @param \WP_User             $user     The authenticated user.
	 * @param string|null          $ip       Client address.
	 * @param array<string, mixed> $decision Policy verdict.
	 */
	private function record( string $event, \WP_User $user, ?string $ip, array $decision, string $source, ?string $token = null ): int {
		$country = (string) $decision['country'];
		$name    = Country_Resolver::country_name( $country );

		$messages = [
			'login.blocked_geo'            => 'Login by "%1$s" from %2$s (%3$s) was BLOCKED: the country is not on the allow list.',
			'login.would_block_geo'        => 'Login by "%1$s" from %2$s (%3$s) would have been blocked, but blocking is in monitor mode.',
			'login.foreign_allowed'        => 'Login by "%1$s" from %2$s (%3$s), which is not on the country allow list.',
			'login.allowed_private_ip'     => 'Login by "%1$s" from the local network (%2$s).',
			'login.allowed_by_allowlist'   => 'Login by "%1$s" from %2$s, which is on the IP allow list.',
			'login.allowed_by_bypass'      => 'Login by "%1$s" from %2$s, permitted by an active bypass grant.',
			'login.blocking_kill_switch'   => 'Login by "%1$s" from %2$s (%3$s) would have been blocked, but WPSEC_DISABLE_BLOCKING is set.',
			'login.success'                => 'Login by "%1$s" from %2$s (%3$s).',
			'geoip.blocking_auto_disarmed' => 'Login by "%1$s" from %2$s could not be checked because the GeoIP lookup is unavailable. Blocking has been switched back to monitor mode.',
		];

		$template = $messages[ $event ] ?? 'Login by "%1$s" from %2$s (%3$s).';

		$data = [
			'rail'    => $decision['rail'],
			'trace'   => $decision['trace'],
			'country' => $country,
			'source'  => $source,
		];

		if ( null !== $token ) {
			$data['bypass_url'] = Bypass_Token::url( $token );
		}

		return Logger::log(
			$event,
			[
				'object_id'     => (string) $user->ID,
				'object_label'  => (string) $user->user_login,
				'target_user'   => (int) $user->ID,
				'ip'            => (string) $ip,
				'country'       => $country,
				'actor_user_id' => (int) $user->ID,
				'actor_login'   => (string) $user->user_login,
				'message'       => sprintf( $template, $user->user_login, (string) $ip, $name ),
				'data'          => $data,
			]
		);
	}

	/**
	 * Catches logins that never went through `authenticate` — cookie-based
	 * auto-login, or a plugin calling wp_set_auth_cookie() directly.
	 *
	 * @param string   $user_login The login name.
	 * @param \WP_User $user       The user.
	 */
	public function on_login( $user_login, $user = null ): void {
		if ( ! empty( $GLOBALS['wpsec_login_logged'] ) ) {
			return;
		}

		if ( ! $user instanceof \WP_User ) {
			return;
		}

		$ip       = Context::client_ip();
		$resolved = Country_Resolver::resolve( $ip );

		Logger::log(
			'login.success',
			[
				'object_id'     => (string) $user->ID,
				'object_label'  => (string) $user->user_login,
				'target_user'   => (int) $user->ID,
				'ip'            => (string) $ip,
				'country'       => $resolved['country'],
				'actor_user_id' => (int) $user->ID,
				'actor_login'   => (string) $user->user_login,
				'message'       => sprintf(
					'Login by "%s" from %s (%s).',
					$user->user_login,
					(string) $ip,
					Country_Resolver::country_name( $resolved['country'] )
				),
				'data'          => [ 'source' => $resolved['source'] ],
			]
		);
	}

	/**
	 * @param int $user_id The user logging out.
	 */
	public function on_logout( $user_id = 0 ): void {
		$user = get_userdata( (int) $user_id );

		if ( ! $user ) {
			return;
		}

		Logger::log(
			'user.logout',
			[
				'object_id'    => (string) $user->ID,
				'object_label' => (string) $user->user_login,
				'target_user'  => (int) $user->ID,
				'message'      => sprintf( 'User "%s" logged out.', $user->user_login ),
			]
		);
	}

	/**
	 * Is this an application-password or XML-RPC authentication rather than an
	 * interactive login?
	 */
	public static function is_api_auth(): bool {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return true;
		}

		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return true;
		}

		// Basic-auth credentials on a non-login endpoint means an application
		// password is being presented.
		return isset( $_SERVER['PHP_AUTH_USER'] ) && ! isset( $_POST['log'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- presence check only, no value is read.
	}

	public static function kill_switch_active(): bool {
		if ( defined( 'WPSEC_DISABLE_BLOCKING' ) && WPSEC_DISABLE_BLOCKING ) {
			return true;
		}

		/**
		 * Disable login blocking at runtime.
		 *
		 * @param bool $disabled Whether blocking is disabled.
		 */
		return (bool) apply_filters( 'wpsec_disable_blocking', false );
	}
}
