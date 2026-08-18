<?php
/**
 * The login access decision, as a pure function.
 *
 * Every safety rail and the fail-closed behaviour live here, deliberately free
 * of WordPress, so the whole decision table can be unit-tested without booting
 * a site. Login_Guard is only the wiring that feeds this class and acts on its
 * verdict.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Access_Policy {

	public const ALLOW   = 'allow';
	public const MONITOR = 'monitor';
	public const BLOCK   = 'block';

	/** Country code used whenever the country cannot be established. */
	public const UNKNOWN = 'ZZ';

	/**
	 * Decide what to do about an authenticated login.
	 *
	 * @param array{
	 *     ip: ?string,
	 *     country: string,
	 *     enabled: bool,
	 *     mode: string,
	 *     countries: string[],
	 *     deny_ips: string[],
	 *     allow_ips: string[],
	 *     temp_allow_ips: string[],
	 *     kill_switch: bool,
	 *     geoip_healthy: bool,
	 *     is_api_auth: bool,
	 *     apply_to_api_auth: bool
	 * } $ctx Decision context.
	 *
	 * @return array{action:string, event:string, rail:string, country:string, disarm:bool, trace:string[]}
	 */
	public static function decide( array $ctx ): array {
		$trace   = [];
		$country = strtoupper( (string) ( $ctx['country'] ?? self::UNKNOWN ) );
		$ip      = $ctx['ip'] ?? null;

		$verdict = static function ( string $action, string $event, string $rail, bool $disarm = false ) use ( &$trace, &$country ): array {
			$trace[] = $rail;

			return [
				'action'  => $action,
				'event'   => $event,
				'rail'    => $rail,
				'country' => $country,
				'disarm'  => $disarm,
				'trace'   => $trace,
			];
		};

		// 1. No connecting address: WP-CLI, cron, a unit test. Never blocked —
		//    blocking here could lock an operator out of their own recovery
		//    tooling. Nothing below can match without an address anyway.
		if ( null === $ip || '' === $ip ) {
			return $verdict( self::ALLOW, '', 'no-remote-addr' );
		}

		// 2. The deny list, and it comes first for a reason.
		//
		//    Firewall semantics: an address the administrator named explicitly
		//    is refused whatever else would have said yes — the allow list, an
		//    allowed country, even the private-network rail. Anything weaker
		//    would mean a deny list that silently does nothing whenever it
		//    overlaps with a rule the site already had.
		//
		//    It is also independent of the country feature: a deny list still
		//    applies when location checking is switched off entirely, because
		//    typing an address into it is an instruction in its own right.
		//
		//    The one thing that stands it down is the wp-config kill switch,
		//    which exists precisely for the case where this list is what locked
		//    the administrator out.
		if ( ! empty( $ctx['deny_ips'] ) && Ip_Matcher::in_any( $ip, (array) $ctx['deny_ips'] ) ) {
			if ( ! empty( $ctx['kill_switch'] ) ) {
				return $verdict( self::MONITOR, 'login.blocking_kill_switch', 'kill-switch-denylist' );
			}

			return $verdict( self::BLOCK, 'login.blocked_denylist', 'rail-0-denylist' );
		}

		// 3. Feature switched off entirely.
		if ( empty( $ctx['enabled'] ) ) {
			return $verdict( self::ALLOW, '', 'disabled' );
		}

		// 4. Application passwords and XML-RPC authenticate through the same
		//    hook as an interactive login. Blocking them by default would
		//    silently break integrations hosted abroad, so they are exempt
		//    unless the admin opted in. A denied address is already gone by
		//    this point: an explicit deny covers API authentication too.
		if ( ! empty( $ctx['is_api_auth'] ) && empty( $ctx['apply_to_api_auth'] ) ) {
			return $verdict( self::ALLOW, '', 'api-auth-exempt' );
		}

		// ---------------------------------------------------------------------
		// Safety rails. These exist because the country rule is fail-closed;
		// each one short-circuits before any country is considered.
		// ---------------------------------------------------------------------

		// Rail A — private, loopback and link-local space is always allowed and
		// is never reported as a foreign login.
		if ( Ip_Matcher::is_private( $ip ) ) {
			$country = 'LO';
			return $verdict( self::ALLOW, 'login.allowed_private_ip', 'rail-a-private' );
		}

		// Rail B — the administrator's static allow list.
		if ( ! empty( $ctx['allow_ips'] ) && Ip_Matcher::in_any( $ip, (array) $ctx['allow_ips'] ) ) {
			return $verdict( self::ALLOW, 'login.allowed_by_allowlist', 'rail-b-allowlist' );
		}

		// Rail C — a temporary grant from a redeemed bypass link.
		if ( ! empty( $ctx['temp_allow_ips'] ) && Ip_Matcher::in_any( $ip, (array) $ctx['temp_allow_ips'] ) ) {
			return $verdict( self::ALLOW, 'login.allowed_by_bypass', 'rail-c-bypass' );
		}

		// Rail D — an empty country list is a misconfiguration, not an
		// instruction to block the world. The settings screen warns about it.
		$countries = array_map( 'strtoupper', (array) ( $ctx['countries'] ?? [] ) );
		if ( empty( $countries ) ) {
			return $verdict( self::ALLOW, 'login.foreign_allowed', 'rail-d-empty-list' );
		}

		// ---------------------------------------------------------------------
		// Country evaluation
		// ---------------------------------------------------------------------
		if ( in_array( $country, $countries, true ) ) {
			return $verdict( self::ALLOW, 'login.success', 'country-allowed' );
		}

		// The country is not allowed. Note that an unresolvable country lands
		// here too: unknown is treated as not allowed, i.e. fail closed.
		$trace[] = ( self::UNKNOWN === $country ) ? 'country-unknown' : 'country-not-allowed';

		$wants_block = 'block' === ( $ctx['mode'] ?? 'monitor' );

		if ( ! $wants_block ) {
			return $verdict( self::MONITOR, 'login.foreign_allowed', 'monitor-mode' );
		}

		// The admin armed blocking. Two things can still stand it down.

		// The wp-config kill switch, for when the admin cannot reach the admin.
		if ( ! empty( $ctx['kill_switch'] ) ) {
			return $verdict( self::MONITOR, 'login.blocking_kill_switch', 'kill-switch' );
		}

		// A single unresolvable IP is blocked, as specified. But if the lookup
		// subsystem as a whole is unavailable, every login would be unknown and
		// the site would be sealed shut — so blocking stands itself down and
		// shouts instead.
		if ( empty( $ctx['geoip_healthy'] ) ) {
			return $verdict( self::MONITOR, 'geoip.blocking_auto_disarmed', 'geoip-unhealthy', true );
		}

		return $verdict( self::BLOCK, 'login.blocked_geo', 'blocked' );
	}
}
