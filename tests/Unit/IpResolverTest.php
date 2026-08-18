<?php
/**
 * Client IP resolution behind proxies.
 *
 * The first test in this file is the security property the whole class exists
 * for: with an untrusted connecting address, forwarding headers are ignored
 * completely. If that ever regresses, anyone can choose their own apparent
 * country by sending a header.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPSecurityCenter\Ip_Resolver;

final class IpResolverTest extends TestCase {

	public function test_forwarding_headers_are_ignored_when_no_proxies_are_trusted(): void {
		$resolver = new Ip_Resolver( [] );

		$result = $resolver->resolve(
			[
				'REMOTE_ADDR'           => '203.0.113.9',
				'HTTP_X_FORWARDED_FOR'  => '1.2.3.4',
				'HTTP_CF_CONNECTING_IP' => '5.6.7.8',
			]
		);

		$this->assertSame( '203.0.113.9', $result['ip'], 'An unconfigured site must never believe a forwarding header.' );
		$this->assertFalse( $result['remote_trusted'] );
		$this->assertSame( 'REMOTE_ADDR', $result['source'] );
	}

	public function test_forwarding_headers_are_ignored_when_the_peer_is_not_a_trusted_proxy(): void {
		$resolver = new Ip_Resolver( [ '10.0.0.0/8' ] );

		$result = $resolver->resolve(
			[
				'REMOTE_ADDR'          => '203.0.113.9',
				'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
			]
		);

		$this->assertSame( '203.0.113.9', $result['ip'], 'Spoofing must fail when the request did not come through the proxy.' );
	}

	public function test_single_value_header_is_used_behind_a_trusted_proxy(): void {
		$resolver = new Ip_Resolver( [ '10.0.0.0/8' ] );

		$result = $resolver->resolve(
			[
				'REMOTE_ADDR'           => '10.1.1.1',
				'HTTP_CF_CONNECTING_IP' => '198.51.100.7',
			]
		);

		$this->assertSame( '198.51.100.7', $result['ip'] );
		$this->assertSame( 'HTTP_CF_CONNECTING_IP', $result['source'] );
		$this->assertTrue( $result['remote_trusted'] );
	}

	public function test_chain_is_walked_right_to_left_to_the_first_untrusted_hop(): void {
		$resolver = new Ip_Resolver( [ '10.0.0.0/8' ] );

		$result = $resolver->resolve(
			[
				'REMOTE_ADDR'          => '10.0.0.1',
				'HTTP_X_FORWARDED_FOR' => '198.51.100.7, 10.0.0.2, 10.0.0.1',
			]
		);

		$this->assertSame( '198.51.100.7', $result['ip'] );
	}

	public function test_client_supplied_hops_to_the_left_are_not_believed(): void {
		$resolver = new Ip_Resolver( [ '10.0.0.0/8' ] );

		// The real client is 198.51.100.7 but it forged an extra hop of its own
		// on the left. The rightmost untrusted entry is still the true client.
		$result = $resolver->resolve(
			[
				'REMOTE_ADDR'          => '10.0.0.1',
				'HTTP_X_FORWARDED_FOR' => '9.9.9.9, 198.51.100.7, 10.0.0.1',
			]
		);

		$this->assertSame( '198.51.100.7', $result['ip'] );
		$this->assertNotSame( '9.9.9.9', $result['ip'] );
	}

	public function test_all_trusted_chain_falls_back_to_the_leftmost_hop(): void {
		$resolver = new Ip_Resolver( [ '10.0.0.0/8' ] );

		$result = $resolver->resolve(
			[
				'REMOTE_ADDR'          => '10.0.0.1',
				'HTTP_X_FORWARDED_FOR' => '10.0.0.5, 10.0.0.2',
			]
		);

		$this->assertSame( '10.0.0.5', $result['ip'] );
	}

	public function test_garbage_entries_in_the_chain_are_dropped(): void {
		$resolver = new Ip_Resolver( [ '10.0.0.0/8' ] );

		$result = $resolver->resolve(
			[
				'REMOTE_ADDR'          => '10.0.0.1',
				'HTTP_X_FORWARDED_FOR' => 'unknown, <script>, 198.51.100.7, 10.0.0.1',
			]
		);

		$this->assertSame( '198.51.100.7', $result['ip'] );
	}

	public function test_ipv6_with_port_and_zone_is_normalised(): void {
		$resolver = new Ip_Resolver( [ 'fc00::/7' ] );

		$result = $resolver->resolve(
			[
				'REMOTE_ADDR'          => 'fd00::1',
				'HTTP_X_FORWARDED_FOR' => '[2001:db8::1]:443',
			]
		);

		$this->assertSame( '2001:db8::1', $result['ip'] );
	}

	public function test_missing_remote_addr_yields_null(): void {
		$resolver = new Ip_Resolver( [ '10.0.0.0/8' ] );

		$result = $resolver->resolve( [] );

		$this->assertNull( $result['ip'], 'WP-CLI and cron have no connecting address at all.' );
	}

	public function test_invalid_remote_addr_yields_null(): void {
		$resolver = new Ip_Resolver();

		$this->assertNull( $resolver->client_ip( [ 'REMOTE_ADDR' => 'not-an-ip' ] ) );
	}

	public function test_header_priority_is_respected(): void {
		$resolver = new Ip_Resolver(
			[ '10.0.0.0/8' ],
			[ 'HTTP_TRUE_CLIENT_IP', 'HTTP_CF_CONNECTING_IP' ]
		);

		$result = $resolver->resolve(
			[
				'REMOTE_ADDR'           => '10.0.0.1',
				'HTTP_CF_CONNECTING_IP' => '1.1.1.1',
				'HTTP_TRUE_CLIENT_IP'   => '2.2.2.2',
			]
		);

		$this->assertSame( '2.2.2.2', $result['ip'] );
	}

	public function test_falls_back_to_remote_addr_when_headers_are_unusable(): void {
		$resolver = new Ip_Resolver( [ '10.0.0.0/8' ] );

		$result = $resolver->resolve(
			[
				'REMOTE_ADDR'          => '10.0.0.1',
				'HTTP_X_FORWARDED_FOR' => 'garbage-only',
			]
		);

		$this->assertSame( '10.0.0.1', $result['ip'] );
	}
}
