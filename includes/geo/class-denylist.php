<?php
/**
 * The static IP deny list.
 *
 * The mirror image of the allow list, and the stronger of the two: an address
 * here is refused a login whatever else would have permitted it. Stored beside
 * the rest of the location settings because it is evaluated in the same place —
 * see Access_Policy, where it sits ahead of every other rail.
 *
 * Naming follows the rest of this plugin: "allow list" and "deny list", not the
 * older colour-coded pair.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Denylist {

	/**
	 * The administrator's deny list: single addresses and CIDR blocks, IPv4
	 * and IPv6 alike.
	 *
	 * @return string[]
	 */
	public static function entries(): array {
		$geo = (array) get_option( Installer::OPTION_GEO, [] );

		return array_values( array_map( 'strval', (array) ( $geo['deny_ips'] ?? [] ) ) );
	}

	/**
	 * Is this address on the list?
	 */
	public static function blocks( string $ip ): bool {
		$entries = self::entries();

		if ( empty( $entries ) || '' === $ip ) {
			return false;
		}

		return Ip_Matcher::in_any( $ip, $entries );
	}

	/**
	 * Which entries would catch this address.
	 *
	 * Used by the settings screen to refuse a list that would lock the
	 * administrator out of their own site, and by Diagnostics to explain a
	 * verdict rather than merely state it.
	 *
	 * @return string[]
	 */
	public static function matching( string $ip ): array {
		if ( '' === $ip ) {
			return [];
		}

		return array_values(
			array_filter(
				self::entries(),
				static fn( string $entry ): bool => Ip_Matcher::in_any( $ip, [ $entry ] )
			)
		);
	}
}
