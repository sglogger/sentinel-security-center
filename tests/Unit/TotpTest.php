<?php
/**
 * TOTP code generation, verification and the base32 it travels in.
 *
 * Checked against the vectors published in RFC 6238 and RFC 4648 rather than
 * against our own output: an implementation that is self-consistently wrong
 * hands out codes no authenticator app will ever produce.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPSecurityCenter\Totp;

final class TotpTest extends TestCase {

	/** The RFC 6238 test secret, "12345678901234567890", in base32. */
	private const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	/**
	 * @dataProvider rfc6238_provider
	 */
	public function test_rfc6238_vectors( int $timestamp, string $expected ): void {
		$this->assertSame(
			$expected,
			Totp::code_at( self::RFC_SECRET, $timestamp, 8 ),
			"code at T={$timestamp}"
		);
	}

	/**
	 * @return array<string, array{0:int, 1:string}>
	 */
	public static function rfc6238_provider(): array {
		return [
			'T=59'          => [ 59, '94287082' ],
			'T=1111111109'  => [ 1111111109, '07081804' ],
			'T=1111111111'  => [ 1111111111, '14050471' ],
			'T=1234567890'  => [ 1234567890, '89005924' ],
			'T=2000000000'  => [ 2000000000, '69279037' ],
			'T=20000000000' => [ 20000000000, '65353130' ],
		];
	}

	/**
	 * @dataProvider base32_provider
	 */
	public function test_base32_round_trip( string $plain, string $encoded ): void {
		$this->assertSame( $encoded, Totp::base32_encode( $plain ), "encode {$plain}" );
		$this->assertSame( $plain, Totp::base32_decode( $encoded ), "decode {$encoded}" );
	}

	/**
	 * RFC 4648 section 10.
	 *
	 * @return array<string, array{0:string, 1:string}>
	 */
	public static function base32_provider(): array {
		return [
			'empty'  => [ '', '' ],
			'f'      => [ 'f', 'MY======' ],
			'fo'     => [ 'fo', 'MZXQ====' ],
			'foo'    => [ 'foo', 'MZXW6===' ],
			'foob'   => [ 'foob', 'MZXW6YQ=' ],
			'fooba'  => [ 'fooba', 'MZXW6YTB' ],
			'foobar' => [ 'foobar', 'MZXW6YTBOI======' ],
		];
	}

	public function test_base32_tolerates_spaces_and_case(): void {
		$this->assertSame( 'foobar', Totp::base32_decode( 'mzxw 6ytb-oi======' ) );
	}

	public function test_base32_rejects_invalid_characters(): void {
		// 0, 1 and 8 are not in the alphabet; a typo must not silently decode
		// to a different secret.
		$this->assertSame( '', Totp::base32_decode( 'MZXW6YT1' ) );
	}

	public function test_verify_accepts_the_current_code(): void {
		$now = 1_700_000_000;

		$this->assertSame(
			intdiv( $now, Totp::PERIOD ),
			Totp::verify( self::RFC_SECRET, Totp::code_at( self::RFC_SECRET, $now ), $now )
		);
	}

	public function test_verify_absorbs_one_step_of_drift_in_both_directions(): void {
		$now = 1_700_000_000;

		foreach ( [ -Totp::PERIOD, Totp::PERIOD ] as $drift ) {
			$this->assertNotNull(
				Totp::verify( self::RFC_SECRET, Totp::code_at( self::RFC_SECRET, $now + $drift ), $now ),
				"drift of {$drift}s"
			);
		}
	}

	public function test_verify_rejects_beyond_the_window(): void {
		$now = 1_700_000_000;

		foreach ( [ -2 * Totp::PERIOD, 2 * Totp::PERIOD ] as $drift ) {
			$this->assertNull(
				Totp::verify( self::RFC_SECRET, Totp::code_at( self::RFC_SECRET, $now + $drift ), $now ),
				"drift of {$drift}s"
			);
		}
	}

	public function test_verify_returns_the_slot_so_replay_can_be_blocked(): void {
		$now  = 1_700_000_000;
		$slot = Totp::verify( self::RFC_SECRET, Totp::code_at( self::RFC_SECRET, $now ), $now );

		$this->assertSame( intdiv( $now, Totp::PERIOD ), $slot );
	}

	/**
	 * @dataProvider malformed_code_provider
	 */
	public function test_verify_rejects_malformed_input( string $code ): void {
		$this->assertNull( Totp::verify( self::RFC_SECRET, $code, 1_700_000_000 ) );
	}

	/**
	 * @return array<string, array{0:string}>
	 */
	public static function malformed_code_provider(): array {
		return [
			'empty'     => [ '' ],
			'too short' => [ '12345' ],
			'too long'  => [ '1234567' ],
			'letters'   => [ 'abcdef' ],
		];
	}

	public function test_verify_rejects_an_undecodable_secret(): void {
		$this->assertNull( Totp::verify( '!!!!', '123456', 1_700_000_000 ) );
	}

	public function test_generated_secrets_are_usable_and_unpadded(): void {
		$secret = Totp::generate_secret();

		$this->assertSame( 32, strlen( $secret ), 'a 20-byte secret is 32 base32 characters' );
		$this->assertStringNotContainsString( '=', $secret, 'padding breaks some authenticator apps' );
		$this->assertNotSame( '', Totp::base32_decode( $secret ) );
		$this->assertNotSame( $secret, Totp::generate_secret() );
	}

	public function test_provisioning_uri_carries_every_parameter(): void {
		$uri = Totp::provisioning_uri( self::RFC_SECRET, 'admin@example.com', 'Example Site' );

		$this->assertStringStartsWith( 'otpauth://totp/Example%20Site:admin%40example.com?', $uri );
		$this->assertStringContainsString( 'secret=' . self::RFC_SECRET, $uri );
		$this->assertStringContainsString( 'issuer=Example%20Site', $uri );
		$this->assertStringContainsString( 'algorithm=SHA1', $uri );
		$this->assertStringContainsString( 'digits=6', $uri );
		$this->assertStringContainsString( 'period=30', $uri );
	}

	public function test_format_secret_groups_for_typing(): void {
		$this->assertSame( 'MZXW 6YTB OI', Totp::format_secret( 'MZXW6YTBOI======' ) );
	}
}
