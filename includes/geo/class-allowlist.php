<?php
/**
 * The static and temporary IP allow lists.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Allowlist {

	/**
	 * Addresses granted temporarily by a redeemed bypass link, expired entries
	 * removed. Pruned on read so a stale grant can never outlive its window
	 * just because nothing happened to write the option.
	 *
	 * @return string[]
	 */
	public static function temporary(): array {
		$entries = (array) get_option( Installer::OPTION_TEMP_ALLOW, [] );
		$now     = time();
		$live    = [];
		$ips     = [];

		foreach ( $entries as $entry ) {
			if ( ! is_array( $entry ) ) {
				continue;
			}

			if ( (int) ( $entry['expires'] ?? 0 ) <= $now ) {
				continue;
			}

			$ip = Ip_Matcher::normalise( (string) ( $entry['ip'] ?? '' ) );

			if ( null === $ip ) {
				continue;
			}

			$live[] = $entry;
			$ips[]  = $ip;
		}

		if ( count( $live ) !== count( $entries ) ) {
			update_option( Installer::OPTION_TEMP_ALLOW, $live, false );
		}

		return array_values( array_unique( $ips ) );
	}

	/**
	 * Grant an address temporary access.
	 */
	public static function grant( string $ip, int $hours, int $user_id, string $selector = '' ): bool {
		$ip = Ip_Matcher::normalise( $ip );

		if ( null === $ip ) {
			return false;
		}

		$hours   = max( 1, min( 168, $hours ) );
		$entries = (array) get_option( Installer::OPTION_TEMP_ALLOW, [] );

		$entries[] = [
			'ip'       => $ip,
			'expires'  => time() + ( $hours * HOUR_IN_SECONDS ),
			'user_id'  => $user_id,
			'selector' => $selector,
			'granted'  => time(),
		];

		update_option( Installer::OPTION_TEMP_ALLOW, $entries, false );

		return true;
	}

	/**
	 * Full detail of live grants, for the Status screen.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function temporary_detail(): array {
		self::temporary(); // prunes

		$entries = (array) get_option( Installer::OPTION_TEMP_ALLOW, [] );

		return array_values( array_filter( $entries, 'is_array' ) );
	}

	public static function revoke_all(): void {
		update_option( Installer::OPTION_TEMP_ALLOW, [], false );
	}

	/**
	 * The administrator's static allow list.
	 *
	 * @return string[]
	 */
	public static function stat(): array {
		$geo = (array) get_option( Installer::OPTION_GEO, [] );

		return array_map( 'strval', (array) ( $geo['allow_ips'] ?? [] ) );
	}
}
