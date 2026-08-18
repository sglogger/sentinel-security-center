<?php
/**
 * RFC 6238 time-based one-time passwords, and the RFC 4648 base32 they travel in.
 *
 * Deliberately free of WordPress: this is the part that decides whether a login
 * is let through, so it is plain PHP that can be tested against the published
 * RFC vectors. Nothing here reads options, touches the database or trusts the
 * clock beyond the timestamp it is handed.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Totp {

	/** Seconds per code. 30 is what every authenticator app assumes. */
	public const PERIOD = 30;

	/** Digits per code. */
	public const DIGITS = 6;

	/**
	 * HMAC algorithm. SHA-1 is not a security weakness here — HOTP relies on
	 * HMAC, and HMAC-SHA1 is unbroken — and it is the only algorithm every
	 * authenticator app supports.
	 */
	public const ALGO = 'sha1';

	/**
	 * How many periods either side of "now" are accepted, to absorb clock
	 * drift between the phone and the server. One step is 30 seconds back and
	 * 30 forward; more than that widens the guessing window for no real gain.
	 */
	public const WINDOW = 1;

	private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * A fresh secret, base32 encoded.
	 *
	 * 20 bytes is the RFC 4226 recommendation and encodes to exactly 32 base32
	 * characters with no padding — which matters, because several authenticator
	 * apps choke on "=" in a secret.
	 */
	public static function generate_secret( int $bytes = 20 ): string {
		return self::base32_encode( random_bytes( max( 10, $bytes ) ) );
	}

	public static function base32_encode( string $bytes ): string {
		if ( '' === $bytes ) {
			return '';
		}

		$buffer = 0;
		$bits   = 0;
		$out    = '';

		$length = strlen( $bytes );

		for ( $i = 0; $i < $length; $i++ ) {
			$buffer = ( $buffer << 8 ) | ord( $bytes[ $i ] );
			$bits  += 8;

			while ( $bits >= 5 ) {
				$bits -= 5;
				$out  .= self::ALPHABET[ ( $buffer >> $bits ) & 31 ];
			}
		}

		if ( $bits > 0 ) {
			$out .= self::ALPHABET[ ( $buffer << ( 5 - $bits ) ) & 31 ];
		}

		return $out . str_repeat( '=', ( 8 - ( strlen( $out ) % 8 ) ) % 8 );
	}

	/**
	 * @return string The raw bytes, or '' when the input is not valid base32.
	 */
	public static function base32_decode( string $input ): string {
		$input = strtoupper( (string) preg_replace( '/[\s-]+/', '', $input ) );
		$input = rtrim( $input, '=' );

		if ( '' === $input ) {
			return '';
		}

		$buffer = 0;
		$bits   = 0;
		$out    = '';

		$length = strlen( $input );

		for ( $i = 0; $i < $length; $i++ ) {
			$index = strpos( self::ALPHABET, $input[ $i ] );

			if ( false === $index ) {
				return '';
			}

			$buffer = ( $buffer << 5 ) | $index;
			$bits  += 5;

			if ( $bits >= 8 ) {
				$bits -= 8;
				$out  .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}

		return $out;
	}

	/**
	 * The code valid at a point in time.
	 *
	 * @return string '' when the secret is not decodable.
	 */
	public static function code_at(
		string $secret,
		int $timestamp,
		int $digits = self::DIGITS,
		int $period = self::PERIOD,
		string $algo = self::ALGO
	): string {
		$key = self::base32_decode( $secret );

		if ( '' === $key ) {
			return '';
		}

		return self::code_for_slot( $key, intdiv( $timestamp, max( 1, $period ) ), $digits, $algo );
	}

	/**
	 * Check a submitted code against the accepted drift window.
	 *
	 * Returns the time slot that matched rather than a boolean, so the caller
	 * can record it and refuse the same code a second time. Without that, a
	 * code shoulder-surfed or captured from a proxy stays usable for the rest
	 * of its 30 seconds.
	 *
	 * @return int|null The matching slot, or null when nothing matched.
	 */
	public static function verify(
		string $secret,
		string $code,
		int $timestamp,
		int $window = self::WINDOW,
		int $digits = self::DIGITS,
		int $period = self::PERIOD,
		string $algo = self::ALGO
	): ?int {
		$code = (string) preg_replace( '/\D+/', '', $code );

		if ( strlen( $code ) !== $digits ) {
			return null;
		}

		$key = self::base32_decode( $secret );

		if ( '' === $key ) {
			return null;
		}

		$current = intdiv( $timestamp, max( 1, $period ) );
		$window  = max( 0, $window );
		$match   = null;

		// Every candidate is evaluated even after a hit: returning early would
		// make the response time reveal which slot matched.
		for ( $offset = -$window; $offset <= $window; $offset++ ) {
			if ( hash_equals( self::code_for_slot( $key, $current + $offset, $digits, $algo ), $code ) ) {
				$match = $current + $offset;
			}
		}

		return $match;
	}

	/**
	 * The otpauth:// URI an authenticator app scans or opens.
	 */
	public static function provisioning_uri(
		string $secret,
		string $account,
		string $issuer,
		int $digits = self::DIGITS,
		int $period = self::PERIOD,
		string $algo = self::ALGO
	): string {
		// The issuer appears twice on purpose: in the label for apps that only
		// read the label, and as a parameter for those that read both.
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account );

		$query = http_build_query(
			[
				'secret'    => rtrim( $secret, '=' ),
				'issuer'    => $issuer,
				'algorithm' => strtoupper( $algo ),
				'digits'    => $digits,
				'period'    => $period,
			],
			'',
			'&',
			PHP_QUERY_RFC3986
		);

		return 'otpauth://totp/' . $label . '?' . $query;
	}

	/**
	 * The secret in blocks of four, for someone typing it in by hand.
	 */
	public static function format_secret( string $secret ): string {
		return trim( chunk_split( rtrim( $secret, '=' ), 4, ' ' ) );
	}

	private static function code_for_slot( string $key, int $slot, int $digits, string $algo ): string {
		$hash   = hash_hmac( $algo, pack( 'J', $slot ), $key, true );
		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;

		$value = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ord( $hash[ $offset + 1 ] ) << 16 )
			| ( ord( $hash[ $offset + 2 ] ) << 8 )
			| ord( $hash[ $offset + 3 ] );

		$digits = max( 6, min( 10, $digits ) );

		return str_pad( (string) ( $value % ( 10 ** $digits ) ), $digits, '0', STR_PAD_LEFT );
	}
}
