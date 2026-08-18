<?php
/**
 * The login access decision table.
 *
 * Two properties matter most here and are asserted from several angles:
 * an unknown country is blocked (fail closed), and none of the four lockout
 * safeguards can be bypassed by that policy.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPSecurityCenter\Access_Policy;

final class AccessPolicyTest extends TestCase {

	/**
	 * A fully armed policy: blocking on, Switzerland only, lookup healthy.
	 *
	 * @param array<string, mixed> $overrides Fields to change.
	 * @return array<string, mixed>
	 */
	private function armed( array $overrides = [] ): array {
		return array_merge(
			[
				'ip'                => '203.0.113.9',
				'country'           => 'RU',
				'enabled'           => true,
				'mode'              => 'block',
				'countries'         => [ 'CH' ],
				'deny_ips'          => [],
				'allow_ips'         => [],
				'temp_allow_ips'    => [],
				'kill_switch'       => false,
				'geoip_healthy'     => true,
				'is_api_auth'       => false,
				'apply_to_api_auth' => false,
			],
			$overrides
		);
	}

	// -------------------------------------------------------------------------
	// Core behaviour
	// -------------------------------------------------------------------------

	public function test_disallowed_country_is_blocked_when_armed(): void {
		$decision = Access_Policy::decide( $this->armed() );

		$this->assertSame( Access_Policy::BLOCK, $decision['action'] );
		$this->assertSame( 'login.blocked_geo', $decision['event'] );
	}

	public function test_allowed_country_passes(): void {
		$decision = Access_Policy::decide( $this->armed( [ 'country' => 'CH' ] ) );

		$this->assertSame( Access_Policy::ALLOW, $decision['action'] );
		$this->assertSame( 'country-allowed', $decision['rail'] );
	}

	public function test_country_comparison_is_case_insensitive(): void {
		$decision = Access_Policy::decide(
			$this->armed(
				[
					'country'   => 'ch',
					'countries' => [ 'ch' ],
				]
			)
		);

		$this->assertSame( Access_Policy::ALLOW, $decision['action'] );
	}

	/**
	 * The decision the whole design hinges on: an address whose country cannot
	 * be established is treated as not allowed.
	 */
	public function test_unknown_country_is_blocked_when_armed(): void {
		$decision = Access_Policy::decide( $this->armed( [ 'country' => Access_Policy::UNKNOWN ] ) );

		$this->assertSame( Access_Policy::BLOCK, $decision['action'], 'Unknown country must fail closed.' );
		$this->assertContains( 'country-unknown', $decision['trace'] );
	}

	public function test_unknown_country_only_warns_in_monitor_mode(): void {
		$decision = Access_Policy::decide(
			$this->armed(
				[
					'country' => Access_Policy::UNKNOWN,
					'mode'    => 'monitor',
				]
			)
		);

		$this->assertSame( Access_Policy::MONITOR, $decision['action'] );
		$this->assertSame( 'login.foreign_allowed', $decision['event'] );
	}

	public function test_monitor_mode_never_blocks(): void {
		$decision = Access_Policy::decide( $this->armed( [ 'mode' => 'monitor' ] ) );

		$this->assertSame( Access_Policy::MONITOR, $decision['action'] );
		$this->assertNotSame( Access_Policy::BLOCK, $decision['action'] );
	}

	// -------------------------------------------------------------------------
	// Lockout safeguards
	// -------------------------------------------------------------------------

	public function test_private_addresses_are_always_allowed(): void {
		foreach ( [ '127.0.0.1', '10.1.2.3', '192.168.1.50', '172.20.0.1', '::1', 'fd00::1' ] as $ip ) {
			$decision = Access_Policy::decide( $this->armed( [ 'ip' => $ip ] ) );

			$this->assertSame(
				Access_Policy::ALLOW,
				$decision['action'],
				"{$ip} must never be blocked — otherwise a local login is impossible under a fail-closed policy."
			);
			$this->assertSame( 'rail-a-private', $decision['rail'] );
		}
	}

	public function test_private_addresses_are_allowed_even_with_an_empty_country_list(): void {
		$decision = Access_Policy::decide(
			$this->armed(
				[
					'ip'        => '127.0.0.1',
					'countries' => [],
				]
			)
		);

		$this->assertSame( Access_Policy::ALLOW, $decision['action'] );
		$this->assertSame( 'rail-a-private', $decision['rail'] );
	}

	public function test_static_allowlist_short_circuits_before_the_country_check(): void {
		$decision = Access_Policy::decide( $this->armed( [ 'allow_ips' => [ '203.0.113.0/24' ] ] ) );

		$this->assertSame( Access_Policy::ALLOW, $decision['action'] );
		$this->assertSame( 'rail-b-allowlist', $decision['rail'] );
		$this->assertNotContains( 'country-not-allowed', $decision['trace'] );
	}

	public function test_bypass_grant_short_circuits_before_the_country_check(): void {
		$decision = Access_Policy::decide( $this->armed( [ 'temp_allow_ips' => [ '203.0.113.9' ] ] ) );

		$this->assertSame( Access_Policy::ALLOW, $decision['action'] );
		$this->assertSame( 'rail-c-bypass', $decision['rail'] );
	}

	public function test_empty_country_list_never_blocks(): void {
		$decision = Access_Policy::decide( $this->armed( [ 'countries' => [] ] ) );

		$this->assertSame( Access_Policy::ALLOW, $decision['action'] );
		$this->assertSame( 'rail-d-empty-list', $decision['rail'] );
	}

	public function test_kill_switch_forces_monitor_mode(): void {
		$decision = Access_Policy::decide( $this->armed( [ 'kill_switch' => true ] ) );

		$this->assertSame( Access_Policy::MONITOR, $decision['action'] );
		$this->assertSame( 'login.blocking_kill_switch', $decision['event'] );
	}

	/**
	 * One unresolvable address is blocked, but a broken lookup subsystem must
	 * not seal the whole site shut.
	 */
	public function test_unhealthy_geoip_disarms_blocking_instead_of_locking_everyone_out(): void {
		$decision = Access_Policy::decide( $this->armed( [ 'geoip_healthy' => false ] ) );

		$this->assertSame( Access_Policy::MONITOR, $decision['action'] );
		$this->assertTrue( $decision['disarm'], 'Blocking must stand itself down.' );
		$this->assertSame( 'geoip.blocking_auto_disarmed', $decision['event'] );
	}

	public function test_missing_client_ip_is_never_blocked(): void {
		$decision = Access_Policy::decide( $this->armed( [ 'ip' => null ] ) );

		$this->assertSame( Access_Policy::ALLOW, $decision['action'] );
		$this->assertSame( 'no-remote-addr', $decision['rail'] );
	}

	// -------------------------------------------------------------------------
	// Scope
	// -------------------------------------------------------------------------

	public function test_api_authentication_is_exempt_by_default(): void {
		$decision = Access_Policy::decide( $this->armed( [ 'is_api_auth' => true ] ) );

		$this->assertSame( Access_Policy::ALLOW, $decision['action'] );
		$this->assertSame( 'api-auth-exempt', $decision['rail'] );
	}

	public function test_api_authentication_is_blocked_when_explicitly_enabled(): void {
		$decision = Access_Policy::decide(
			$this->armed(
				[
					'is_api_auth'       => true,
					'apply_to_api_auth' => true,
				]
			)
		);

		$this->assertSame( Access_Policy::BLOCK, $decision['action'] );
	}

	public function test_disabled_feature_does_nothing_at_all(): void {
		$decision = Access_Policy::decide( $this->armed( [ 'enabled' => false ] ) );

		$this->assertSame( Access_Policy::ALLOW, $decision['action'] );
		$this->assertSame( '', $decision['event'] );
	}

	// -------------------------------------------------------------------------
	// The deny list. It is the only rule that outranks every other, so each
	// thing it has to beat gets its own assertion.
	// -------------------------------------------------------------------------

	public function test_denied_address_is_blocked(): void {
		$decision = Access_Policy::decide( $this->armed( [ 'deny_ips' => [ '203.0.113.9' ] ] ) );

		$this->assertSame( Access_Policy::BLOCK, $decision['action'] );
		$this->assertSame( 'login.blocked_denylist', $decision['event'] );
		$this->assertSame( 'rail-0-denylist', $decision['rail'] );
	}

	public function test_deny_list_beats_the_allow_list(): void {
		$decision = Access_Policy::decide(
			$this->armed(
				[
					'deny_ips'  => [ '203.0.113.0/24' ],
					'allow_ips' => [ '203.0.113.9' ],
				]
			)
		);

		$this->assertSame( Access_Policy::BLOCK, $decision['action'], 'an explicit deny must win over an explicit allow' );
	}

	public function test_deny_list_beats_an_allowed_country(): void {
		$decision = Access_Policy::decide(
			$this->armed(
				[
					'deny_ips' => [ '203.0.113.9' ],
					'country'  => 'CH',
				]
			)
		);

		$this->assertSame( Access_Policy::BLOCK, $decision['action'] );
	}

	public function test_deny_list_beats_the_private_network_rail(): void {
		$decision = Access_Policy::decide(
			$this->armed(
				[
					'ip'       => '192.168.1.50',
					'deny_ips' => [ '192.168.1.0/24' ],
				]
			)
		);

		$this->assertSame( Access_Policy::BLOCK, $decision['action'], 'a denied LAN address must not be rescued by rail A' );
	}

	public function test_deny_list_applies_even_when_location_checking_is_off(): void {
		$decision = Access_Policy::decide(
			$this->armed(
				[
					'enabled'  => false,
					'deny_ips' => [ '203.0.113.9' ],
				]
			)
		);

		$this->assertSame( Access_Policy::BLOCK, $decision['action'], 'the deny list is its own control, not part of the country feature' );
	}

	public function test_deny_list_applies_to_api_authentication_without_opting_in(): void {
		$decision = Access_Policy::decide(
			$this->armed(
				[
					'is_api_auth' => true,
					'deny_ips'    => [ '203.0.113.9' ],
				]
			)
		);

		$this->assertSame( Access_Policy::BLOCK, $decision['action'] );
	}

	public function test_kill_switch_stands_the_deny_list_down(): void {
		$decision = Access_Policy::decide(
			$this->armed(
				[
					'deny_ips'    => [ '203.0.113.9' ],
					'kill_switch' => true,
				]
			)
		);

		$this->assertSame( Access_Policy::MONITOR, $decision['action'], 'the wp-config escape hatch has to cover the deny list too' );
		$this->assertSame( 'kill-switch-denylist', $decision['rail'] );
	}

	/**
	 * @dataProvider deny_range_provider
	 */
	public function test_deny_list_matches_ranges( string $ip, string $entry, bool $blocked ): void {
		$decision = Access_Policy::decide(
			$this->armed(
				[
					'ip'       => $ip,
					'deny_ips' => [ $entry ],
					'country'  => 'CH',
				]
			)
		);

		$this->assertSame(
			$blocked ? Access_Policy::BLOCK : Access_Policy::ALLOW,
			$decision['action'],
			"{$ip} against {$entry}"
		);
	}

	/**
	 * @return array<string, array{0:string, 1:string, 2:bool}>
	 */
	public static function deny_range_provider(): array {
		return [
			'v4 exact match'             => [ '203.0.113.9', '203.0.113.9', true ],
			'v4 inside the block'        => [ '203.0.113.9', '203.0.113.0/24', true ],
			'v4 next block over'         => [ '203.0.114.9', '203.0.113.0/24', false ],
			'v6 exact match'             => [ '2001:db8::1', '2001:db8::1', true ],
			'v6 inside the block'        => [ '2001:db8::1', '2001:db8::/32', true ],
			'v6 outside'                 => [ '2001:dbf::1', '2001:db8::/32', false ],
			'v6 does not match v4 entry' => [ '2001:db8::1', '203.0.113.0/24', false ],
		];
	}

	public function test_an_address_not_on_the_list_is_unaffected(): void {
		$decision = Access_Policy::decide(
			$this->armed(
				[
					'country'  => 'CH',
					'deny_ips' => [ '198.51.100.0/24', '2001:db8::/32' ],
				]
			)
		);

		$this->assertSame( Access_Policy::ALLOW, $decision['action'] );
		$this->assertSame( 'country-allowed', $decision['rail'] );
	}

	public function test_the_trace_names_the_rule_that_decided(): void {
		$decision = Access_Policy::decide( $this->armed() );

		$this->assertNotEmpty( $decision['trace'] );
		$this->assertSame( 'blocked', end( $decision['trace'] ) );
	}
}
