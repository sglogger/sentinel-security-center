<?php
/**
 * Who did it, from where, and through which entry point.
 *
 * Resolved once per request and memoised: several monitors can fire in a single
 * request and none of them should pay for the lookup twice.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Context {

	/** @var array<string, mixed>|null */
	private static ?array $cache = null;

	/** @var string|null */
	private static ?string $ip_cache = null;

	private static bool $ip_resolved = false;

	/**
	 * @return array{actor_user_id:int, actor_login:string, actor_roles:string, context:string, ip:string, request_uri:string, user_agent:string}
	 */
	public static function current(): array {
		if ( null !== self::$cache ) {
			return self::$cache;
		}

		$user = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;

		$actor_id    = ( $user && $user->exists() ) ? (int) $user->ID : 0;
		$actor_login = ( $user && $user->exists() ) ? (string) $user->user_login : '';
		$actor_roles = ( $user && $user->exists() ) ? implode( ',', (array) $user->roles ) : '';

		// An unattended change is not anonymous, it is the system acting. Say so
		// rather than leaving the actor blank.
		if ( 0 === $actor_id ) {
			$actor_login = self::is_unattended() ? 'system' : '';
		}

		self::$cache = [
			'actor_user_id' => $actor_id,
			'actor_login'   => $actor_login,
			'actor_roles'   => $actor_roles,
			'context'       => self::request_context(),
			'ip'            => (string) ( self::client_ip() ?? '' ),
			'request_uri'   => self::request_uri(),
			'user_agent'    => self::user_agent(),
		];

		return self::$cache;
	}

	/**
	 * Where the request came in. Useful when triaging: the same event means
	 * something different from wp-admin than it does from the REST API.
	 */
	public static function request_context(): string {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'cli';
		}
		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return 'cron';
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'xmlrpc';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest';
		}
		if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
			return 'ajax';
		}
		if ( is_admin() ) {
			return 'admin';
		}

		return 'web';
	}

	public static function is_unattended(): bool {
		return in_array( self::request_context(), [ 'cli', 'cron' ], true );
	}

	/**
	 * The client address, resolved through the configured trusted proxies.
	 *
	 * Returns null when there is no connecting address at all (WP-CLI, cron).
	 */
	public static function client_ip(): ?string {
		if ( self::$ip_resolved ) {
			return self::$ip_cache;
		}

		self::$ip_resolved = true;

		$geo = (array) get_option( Installer::OPTION_GEO, [] );

		$resolver = new Ip_Resolver(
			(array) ( $geo['trusted_proxies'] ?? [] ),
			(array) ( $geo['header_priority'] ?? [] )
		);

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- the resolver validates every value with filter_var and discards anything that is not an IP address.
		self::$ip_cache = $resolver->client_ip( (array) $_SERVER );

		/**
		 * Override the detected client IP. Intended for local development only.
		 *
		 * @param string|null $ip The resolved address.
		 */
		$filtered = apply_filters( 'wpsec_client_ip', self::$ip_cache );

		if ( is_string( $filtered ) ) {
			self::$ip_cache = Ip_Matcher::normalise( $filtered );
		}

		return self::$ip_cache;
	}

	/**
	 * Full resolution detail, for the Diagnostics screen.
	 *
	 * @return array{ip:?string, source:string, remote:?string, remote_trusted:bool, chain:string[]}
	 */
	public static function ip_detail(): array {
		$geo = (array) get_option( Installer::OPTION_GEO, [] );

		$resolver = new Ip_Resolver(
			(array) ( $geo['trusted_proxies'] ?? [] ),
			(array) ( $geo['header_priority'] ?? [] )
		);

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- validated inside the resolver.
		return $resolver->resolve( (array) $_SERVER );
	}

	private static function request_uri(): string {
		if ( ! isset( $_SERVER['REQUEST_URI'] ) ) {
			return '';
		}

		$uri = esc_url_raw( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) );

		return mb_substr( $uri, 0, 255 );
	}

	private static function user_agent(): string {
		if ( ! isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
			return '';
		}

		$ua = sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_USER_AGENT'] ) );

		return mb_substr( $ua, 0, 255 );
	}

	/**
	 * Drop the memoised values. Only needed by tests and long-running CLI work
	 * that switches user mid-process.
	 */
	public static function flush(): void {
		self::$cache       = null;
		self::$ip_cache    = null;
		self::$ip_resolved = false;
	}
}
