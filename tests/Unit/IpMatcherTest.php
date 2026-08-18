<?php
/**
 * CIDR matching and address normalisation.
 *
 * These assertions decide whether the safety rails fire. If in_cidr() is wrong
 * about a loopback address, an administrator is locked out of their own site.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPSecurityCenter\Ip_Matcher;

final class IpMatcherTest extends TestCase {

	/**
	 * @dataProvider boundary_provider
	 */
	public function test_cidr_boundaries( string $ip, string $cidr, bool $expected ): void {
		$this->assertSame( $expected, Ip_Matcher::in_cidr( $ip, $cidr ), "{$ip} in {$cidr}" );
	}

	/**
	 * @return array<string, array{0:string, 1:string, 2:bool}>
	 */
	public static function boundary_provider(): array {
		return [
			// The classic off-by-one: the last address of a /8 is inside it,
			// the first of the next block is not.
			'10.255.255.255 is inside 10/8' => [ '10.255.255.255', '10.0.0.0/8', true ],
			'11.0.0.0 is outside 10/8'      => [ '11.0.0.0', '10.0.0.0/8', false ],
			'9.255.255.255 is outside 10/8' => [ '9.255.255.255', '10.0.0.0/8', false ],

			// /12 has a non-byte-aligned boundary, which is where naive
			// implementations break.
			'172.16.0.0 inside 172.16/12'   => [ '172.16.0.0', '172.16.0.0/12', true ],
			'172.31.255.255 inside /12'     => [ '172.31.255.255', '172.16.0.0/12', true ],
			'172.32.0.0 outside /12'        => [ '172.32.0.0', '172.16.0.0/12', false ],
			'172.15.255.255 outside /12'    => [ '172.15.255.255', '172.16.0.0/12', false ],

			'/32 matches exactly'           => [ '1.2.3.4', '1.2.3.4/32', true ],
			'/32 rejects a neighbour'       => [ '1.2.3.5', '1.2.3.4/32', false ],
			'/0 matches everything v4'      => [ '203.0.113.9', '0.0.0.0/0', true ],

			// IPv6.
			'::1 inside ::1/128'            => [ '::1', '::1/128', true ],
			'fc00::1 inside fc00::/7'       => [ 'fc00::1', 'fc00::/7', true ],
			'fdff::1 inside fc00::/7'       => [ 'fdff::1', 'fc00::/7', true ],
			'fe00::1 outside fc00::/7'      => [ 'fe00::1', 'fc00::/7', false ],
			'fe80::1 inside fe80::/10'      => [ 'fe80::1', 'fe80::/10', true ],
			'/0 matches everything v6'      => [ '2001:db8::1', '::/0', true ],

			// Address families must never match across.
			'v4 is not inside a v6 network' => [ '1.2.3.4', '2001:db8::/32', false ],
			'v6 is not inside a v4 network' => [ '2001:db8::1', '10.0.0.0/8', false ],

			// A bare address behaves as a single-host match.
			'bare address matches'          => [ '8.8.8.8', '8.8.8.8', true ],
			'bare address rejects other'    => [ '8.8.4.4', '8.8.8.8', false ],
		];
	}

	/**
	 * Malformed input must never match and never throw. A typo in an allow list
	 * has to fail closed.
	 *
	 * @dataProvider malformed_provider
	 */
	public function test_malformed_input_never_matches( string $ip, string $cidr ): void {
		$this->assertFalse( Ip_Matcher::in_cidr( $ip, $cidr ) );
	}

	/**
	 * @return array<string, array{0:string, 1:string}>
	 */
	public static function malformed_provider(): array {
		return [
			'octet out of range' => [ '1.2.3.256', '1.2.3.0/24' ],
			'empty address'      => [ '', '10.0.0.0/8' ],
			'empty cidr'         => [ '10.0.0.1', '' ],
			'not an address'     => [ 'not-an-ip', '10.0.0.0/8' ],
			'prefix too large'   => [ '::1', '::/129' ],
			'negative prefix'    => [ '10.0.0.1', '10.0.0.0/-1' ],
			'garbage prefix'     => [ '10.0.0.1', '10.0.0.0/abc' ],
			'garbage subnet'     => [ '10.0.0.1', 'nope/8' ],
		];
	}

	/**
	 * Every range the private-IP rail relies on.
	 *
	 * @dataProvider private_provider
	 */
	public function test_private_ranges_are_recognised( string $ip ): void {
		$this->assertTrue( Ip_Matcher::is_private( $ip ), "{$ip} should count as private" );
	}

	/**
	 * @return array<string, array{0:string}>
	 */
	public static function private_provider(): array {
		return [
			'loopback v4'   => [ '127.0.0.1' ],
			'loopback high' => [ '127.255.255.254' ],
			'rfc1918 10'    => [ '10.1.2.3' ],
			'rfc1918 172'   => [ '172.20.5.5' ],
			'rfc1918 192'   => [ '192.168.1.1' ],
			'link local'    => [ '169.254.10.10' ],
			'cgnat'         => [ '100.64.0.1' ],
			'loopback v6'   => [ '::1' ],
			'unique local'  => [ 'fd00::1' ],
			'link local v6' => [ 'fe80::1' ],
		];
	}

	public function test_public_addresses_are_not_private(): void {
		foreach ( [ '8.8.8.8', '1.1.1.1', '203.0.113.9', '2001:4860:4860::8888' ] as $ip ) {
			$this->assertFalse( Ip_Matcher::is_private( $ip ), "{$ip} must not count as private" );
		}
	}

	/**
	 * An IPv4-mapped IPv6 loopback must still hit the loopback rail. Some proxy
	 * stacks present addresses this way, and treating them as unknown would
	 * block a local login under a fail-closed policy.
	 */
	public function test_ipv4_mapped_addresses_collapse_to_ipv4(): void {
		$this->assertSame( '192.168.1.1', Ip_Matcher::normalise( '::ffff:192.168.1.1' ) );
		$this->assertTrue( Ip_Matcher::is_private( '::ffff:127.0.0.1' ) );
	}

	/**
	 * @dataProvider normalise_provider
	 */
	public function test_normalise( string $input, ?string $expected ): void {
		$this->assertSame( $expected, Ip_Matcher::normalise( $input ) );
	}

	/**
	 * @return array<string, array{0:string, 1:?string}>
	 */
	public static function normalise_provider(): array {
		return [
			'plain v4'            => [ '1.2.3.4', '1.2.3.4' ],
			'v4 with port'        => [ '1.2.3.4:8080', '1.2.3.4' ],
			'bracketed v6'        => [ '[2001:db8::1]', '2001:db8::1' ],
			'bracketed v6 + port' => [ '[2001:db8::1]:443', '2001:db8::1' ],
			'v6 with zone'        => [ 'fe80::1%eth0', 'fe80::1' ],
			'surrounding spaces'  => [ '  10.0.0.1  ', '10.0.0.1' ],
			'empty'               => [ '', null ],
			'garbage'             => [ 'hello', null ],
			'truncated v4'        => [ '1.2.3', null ],
		];
	}

	public function test_sanitize_list_drops_invalid_entries(): void {
		$clean = Ip_Matcher::sanitize_list(
			[ '10.0.0.0/8', 'nonsense', '192.168.1.1', '1.2.3.4/33', '', 'fc00::/7', '2001:db8::/129' ]
		);

		$this->assertSame( [ '10.0.0.0/8', '192.168.1.1', 'fc00::/7' ], $clean );
	}

	public function test_sanitize_list_deduplicates(): void {
		$this->assertSame( [ '10.0.0.0/8' ], Ip_Matcher::sanitize_list( [ '10.0.0.0/8', '10.0.0.0/8' ] ) );
	}
}
