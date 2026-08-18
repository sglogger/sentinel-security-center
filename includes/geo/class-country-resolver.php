<?php
/**
 * Resolves an IP address to an ISO-3166-1 alpha-2 country code.
 *
 * Order: a CDN country header (only when the request demonstrably came through
 * a trusted proxy), then the local MaxMind database, then unknown. No external
 * API is ever called — a login must not wait on a third-party HTTP request, and
 * visitor IP addresses must not be handed to a third party.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Country_Resolver {

	public const UNKNOWN = 'ZZ';

	/** @var \MaxMind\Db\Reader|null */
	private static $reader = null;

	private static bool $reader_tried = false;

	/** @var array<string, string> Per-request memoisation. */
	private static array $memo = [];

	/**
	 * Country for an address, or 'ZZ'.
	 */
	public static function lookup( ?string $ip ): string {
		if ( null === $ip || '' === $ip ) {
			return self::UNKNOWN;
		}

		$ip = Ip_Matcher::normalise( $ip );

		if ( null === $ip ) {
			return self::UNKNOWN;
		}

		if ( isset( self::$memo[ $ip ] ) ) {
			return self::$memo[ $ip ];
		}

		$reader = self::reader();

		if ( null === $reader ) {
			self::$memo[ $ip ] = self::UNKNOWN;
			return self::$memo[ $ip ];
		}

		try {
			$record = $reader->get( $ip );
		} catch ( \Throwable $e ) {
			// A corrupt database, or an address family the file does not carry.
			// Never fatal: the caller treats unknown as not-allowed and the
			// health check stands blocking down if the file is truly broken.
			self::$memo[ $ip ] = self::UNKNOWN;
			return self::$memo[ $ip ];
		}

		$code = '';

		if ( is_array( $record ) ) {
			$code = (string) ( $record['country']['iso_code'] ?? $record['registered_country']['iso_code'] ?? '' );
		}

		$code = strtoupper( trim( $code ) );

		if ( ! preg_match( '/^[A-Z]{2}$/', $code ) ) {
			$code = self::UNKNOWN;
		}

		self::$memo[ $ip ] = $code;

		return $code;
	}

	/**
	 * Country from a CDN header, but only when the connecting address is a
	 * trusted proxy — otherwise anyone could simply send the header themselves.
	 *
	 * @param array<string, mixed> $server A $_SERVER-shaped array.
	 */
	public static function from_header( array $server ): ?string {
		$geo = (array) get_option( Installer::OPTION_GEO, [] );

		if ( empty( $geo['use_country_header'] ) ) {
			return null;
		}

		$trusted = (array) ( $geo['trusted_proxies'] ?? [] );
		$remote  = isset( $server['REMOTE_ADDR'] ) ? Ip_Matcher::normalise( (string) $server['REMOTE_ADDR'] ) : null;

		if ( null === $remote || empty( $trusted ) || ! Ip_Matcher::in_any( $remote, $trusted ) ) {
			return null;
		}

		foreach ( (array) ( $geo['country_headers'] ?? [] ) as $header ) {
			$header = (string) $header;

			if ( empty( $server[ $header ] ) ) {
				continue;
			}

			$code = strtoupper( trim( (string) $server[ $header ] ) );

			// Cloudflare uses XX for "unknown" and T1 for Tor. Both mean we do
			// not have a country, so both map to unknown rather than being
			// treated as a real (and never allow-listed) country code.
			if ( 'XX' === $code || 'T1' === $code ) {
				return self::UNKNOWN;
			}

			if ( preg_match( '/^[A-Z]{2}$/', $code ) ) {
				return $code;
			}
		}

		return null;
	}

	/**
	 * Resolve for the current request: header first, then the database.
	 *
	 * @param array<string, mixed>|null $server Optional $_SERVER override.
	 * @return array{country:string, source:string}
	 */
	public static function resolve( ?string $ip, ?array $server = null ): array {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- values are pattern-validated before use.
		$server = $server ?? (array) $_SERVER;

		$header = self::from_header( $server );

		if ( null !== $header ) {
			return [
				'country' => $header,
				'source'  => 'header',
			];
		}

		return [
			'country' => self::lookup( $ip ),
			'source'  => self::reader() ? 'database' : 'none',
		];
	}

	/**
	 * Is the lookup subsystem usable?
	 *
	 * This is what separates "this one address is unknown" (blocked, as
	 * specified) from "nothing can be resolved at all" (blocking stands itself
	 * down, because otherwise a deleted file seals the site shut).
	 */
	public static function is_healthy( ?array $server = null ): bool {
		if ( null !== self::reader() ) {
			return true;
		}

		// A trusted CDN supplying country headers is a complete substitute for
		// the database — but only if it is ACTUALLY supplying one. Treating a
		// merely configured header name as proof of health was a real hole:
		// trusted proxies are usually configured for X-Forwarded-For alone, so
		// a site with no database would have reported healthy, kept blocking
		// armed, and locked everyone out under the fail-closed rule.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- pattern-validated inside from_header().
		$server = $server ?? (array) $_SERVER;

		return null !== self::from_header( $server );
	}

	/**
	 * Lazily construct the MaxMind reader.
	 *
	 * Composer's autoloader is only pulled in here, and a missing or broken
	 * vendor directory degrades to "no reader" rather than a fatal error.
	 *
	 * @return \MaxMind\Db\Reader|null
	 */
	public static function reader() {
		if ( self::$reader_tried ) {
			return self::$reader;
		}

		self::$reader_tried = true;

		$path = Geoip_Database::path();

		if ( '' === $path ) {
			return null;
		}

		if ( ! class_exists( '\MaxMind\Db\Reader' ) ) {
			$autoload = WPSEC_DIR . 'vendor/autoload.php';

			if ( ! is_readable( $autoload ) ) {
				return null;
			}

			require_once $autoload;

			if ( ! class_exists( '\MaxMind\Db\Reader' ) ) {
				return null;
			}
		}

		try {
			self::$reader = new \MaxMind\Db\Reader( $path );
		} catch ( \Throwable $e ) {
			self::$reader = null;
		}

		return self::$reader;
	}

	/**
	 * Verify the database answers a known query. Used by the settings screen
	 * before it will let blocking be armed.
	 */
	public static function self_test(): bool {
		$reader = self::reader();

		if ( null === $reader ) {
			return false;
		}

		// Several probes rather than one: the point is "does the reader answer
		// at all", and pinning the check to a single address makes it fail
		// against perfectly valid databases that happen not to carry it.
		foreach ( [ '8.8.8.8', '1.1.1.1', '81.2.69.160', '89.160.20.112' ] as $probe ) {
			try {
				$record = $reader->get( $probe );
			} catch ( \Throwable $e ) {
				return false;
			}

			if ( is_array( $record ) && ! empty( $record['country']['iso_code'] ) ) {
				return true;
			}
		}

		return false;
	}

	public static function flush(): void {
		self::$reader       = null;
		self::$reader_tried = false;
		self::$memo         = [];
	}

	/**
	 * ISO country code to display name, using PHP's ICU data when available.
	 */
	public static function country_name( string $code ): string {
		$code = strtoupper( trim( $code ) );

		if ( 'LO' === $code ) {
			return __( 'Local network', 'sentinel-security-center' );
		}

		if ( self::UNKNOWN === $code || '' === $code ) {
			return __( 'Unknown', 'sentinel-security-center' );
		}

		if ( class_exists( '\Locale' ) && function_exists( 'locale_get_display_region' ) ) {
			$name = locale_get_display_region( '-' . $code, get_user_locale() );

			if ( is_string( $name ) && '' !== $name && $name !== $code ) {
				return $name;
			}
		}

		return $code;
	}
}
