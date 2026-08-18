<?php
/**
 * IPv4/IPv6 address normalisation and CIDR matching.
 *
 * Deliberately free of WordPress so it can be unit-tested as plain PHP. This
 * class decides whether the safety rails fire, so its edge cases are the ones
 * that must not be wrong.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Ip_Matcher {

	/**
	 * Addresses that must never be geo-blocked. Blocking is fail-closed, so
	 * without this rail a local or LAN login would resolve to "unknown
	 * country" and be refused — locking an admin out of their own site.
	 *
	 * @return string[]
	 */
	public static function private_ranges(): array {
		return [
			'127.0.0.0/8',      // loopback
			'10.0.0.0/8',       // RFC1918
			'172.16.0.0/12',    // RFC1918
			'192.168.0.0/16',   // RFC1918
			'169.254.0.0/16',   // link-local
			'100.64.0.0/10',    // carrier-grade NAT
			'0.0.0.0/8',        // "this network"
			'::1/128',          // loopback
			'fc00::/7',         // unique local
			'fe80::/10',        // link-local
			'::/128',           // unspecified
		];
	}

	/**
	 * Normalise a raw address into a comparable form, or null if it is not an
	 * IP address at all.
	 *
	 * Handles the shapes that actually turn up in proxy headers: bracketed
	 * IPv6 (`[::1]`), an appended port (`1.2.3.4:5678`), IPv6 zone indices
	 * (`fe80::1%eth0`), and IPv4-mapped IPv6 (`::ffff:1.2.3.4`), which is
	 * collapsed to its IPv4 form so a mapped loopback still matches the
	 * loopback rail.
	 */
	public static function normalise( string $ip ): ?string {
		$ip = trim( $ip );

		if ( '' === $ip ) {
			return null;
		}

		// Bracketed IPv6, with or without a trailing port.
		if ( '[' === $ip[0] ) {
			$close = strpos( $ip, ']' );
			if ( false === $close ) {
				return null;
			}
			$ip = substr( $ip, 1, $close - 1 );
		} elseif ( substr_count( $ip, ':' ) === 1 && false !== strpos( $ip, '.' ) ) {
			// IPv4 with a port. A bare IPv6 address has several colons, so a
			// single colon alongside dots can only be host:port.
			$ip = substr( $ip, 0, (int) strpos( $ip, ':' ) );
		}

		// Strip an IPv6 zone index.
		$percent = strpos( $ip, '%' );
		if ( false !== $percent ) {
			$ip = substr( $ip, 0, $percent );
		}

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return null;
		}

		// Collapse IPv4-mapped IPv6 to plain IPv4.
		if ( 0 === stripos( $ip, '::ffff:' ) ) {
			$tail = substr( $ip, 7 );
			if ( filter_var( $tail, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				return $tail;
			}
		}

		return $ip;
	}

	public static function is_valid( string $ip ): bool {
		return null !== self::normalise( $ip );
	}

	public static function is_ipv6( string $ip ): bool {
		$ip = self::normalise( $ip );

		return null !== $ip && false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );
	}

	/**
	 * Is $ip inside $cidr? Accepts a bare address as a /32 or /128.
	 *
	 * Never throws and never returns true for malformed input — a broken
	 * allow-list entry must fail closed, not open.
	 */
	public static function in_cidr( string $ip, string $cidr ): bool {
		$ip = self::normalise( $ip );
		if ( null === $ip ) {
			return false;
		}

		$cidr = trim( $cidr );
		if ( '' === $cidr ) {
			return false;
		}

		if ( false === strpos( $cidr, '/' ) ) {
			$single = self::normalise( $cidr );
			return null !== $single && $single === $ip;
		}

		[ $subnet, $bits ] = explode( '/', $cidr, 2 );

		$subnet = self::normalise( $subnet );
		if ( null === $subnet || ! preg_match( '/^\d{1,3}$/', trim( $bits ) ) ) {
			return false;
		}

		$bits = (int) $bits;

		$ip_bin     = @inet_pton( $ip );
		$subnet_bin = @inet_pton( $subnet );

		if ( false === $ip_bin || false === $subnet_bin ) {
			return false;
		}

		// A v4 address is never inside a v6 network, and vice versa.
		if ( strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$max = strlen( $ip_bin ) * 8;
		if ( $bits < 0 || $bits > $max ) {
			return false;
		}

		if ( 0 === $bits ) {
			return true;
		}

		$whole_bytes = intdiv( $bits, 8 );
		$rest_bits   = $bits % 8;

		if ( $whole_bytes > 0 && substr( $ip_bin, 0, $whole_bytes ) !== substr( $subnet_bin, 0, $whole_bytes ) ) {
			return false;
		}

		if ( 0 === $rest_bits ) {
			return true;
		}

		$mask = ~( ( 1 << ( 8 - $rest_bits ) ) - 1 ) & 0xFF;

		return ( ord( $ip_bin[ $whole_bytes ] ) & $mask ) === ( ord( $subnet_bin[ $whole_bytes ] ) & $mask );
	}

	/**
	 * Does $ip match any entry in the list?
	 *
	 * @param string[] $cidrs List of addresses or CIDR blocks.
	 */
	public static function in_any( string $ip, array $cidrs ): bool {
		foreach ( $cidrs as $cidr ) {
			if ( is_string( $cidr ) && self::in_cidr( $ip, $cidr ) ) {
				return true;
			}
		}

		return false;
	}

	public static function is_private( string $ip ): bool {
		return self::in_any( $ip, self::private_ranges() );
	}

	/**
	 * Validate and clean a user-supplied list of addresses/CIDRs, dropping
	 * anything unparseable. Used when saving settings so a typo cannot quietly
	 * widen or break an allow list.
	 *
	 * @param string[] $lines Raw entries.
	 * @return string[]
	 */
	public static function sanitize_list( array $lines ): array {
		$clean = [];

		foreach ( $lines as $line ) {
			$line = trim( (string) $line );
			if ( '' === $line ) {
				continue;
			}

			if ( false !== strpos( $line, '/' ) ) {
				[ $subnet, $bits ] = array_pad( explode( '/', $line, 2 ), 2, '' );
				$subnet            = self::normalise( $subnet );

				if ( null === $subnet || ! preg_match( '/^\d{1,3}$/', trim( $bits ) ) ) {
					continue;
				}

				$max = self::is_ipv6( $subnet ) ? 128 : 32;
				if ( (int) $bits > $max ) {
					continue;
				}

				$clean[] = $subnet . '/' . (int) $bits;
				continue;
			}

			$single = self::normalise( $line );
			if ( null !== $single ) {
				$clean[] = $single;
			}
		}

		return array_values( array_unique( $clean ) );
	}
}
