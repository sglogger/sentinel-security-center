<?php
/**
 * Fetches Cloudflare's published IP ranges for the trusted-proxy preset.
 *
 * Never applied automatically. Trusting a proxy network is a security decision
 * with real consequences — every address in it can then dictate the client IP —
 * so the administrator clicks to merge it.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Cloudflare_Ranges {

	private const V4_URL = 'https://www.cloudflare.com/ips-v4';
	private const V6_URL = 'https://www.cloudflare.com/ips-v6';

	/**
	 * Cached ranges, refetched when older than a week.
	 *
	 * @param bool $force Bypass the cache.
	 * @return array{v4:string[], v6:string[], fetched:int, error:string}
	 */
	public static function get( bool $force = false ): array {
		$stored = (array) get_option( Installer::OPTION_CF_RANGES, [] );

		$fresh = ! empty( $stored['fetched'] )
			&& ( time() - (int) $stored['fetched'] ) < WEEK_IN_SECONDS
			&& ! empty( $stored['v4'] );

		if ( $fresh && ! $force ) {
			return [
				'v4'      => (array) $stored['v4'],
				'v6'      => (array) ( $stored['v6'] ?? [] ),
				'fetched' => (int) $stored['fetched'],
				'error'   => '',
			];
		}

		$v4 = self::fetch( self::V4_URL );
		$v6 = self::fetch( self::V6_URL );

		if ( empty( $v4 ) ) {
			return [
				'v4'      => (array) ( $stored['v4'] ?? [] ),
				'v6'      => (array) ( $stored['v6'] ?? [] ),
				'fetched' => (int) ( $stored['fetched'] ?? 0 ),
				'error'   => __( 'The Cloudflare address list could not be retrieved.', 'wp-security-center' ),
			];
		}

		$result = [
			'v4'      => $v4,
			'v6'      => $v6,
			'fetched' => time(),
		];

		update_option( Installer::OPTION_CF_RANGES, $result, false );

		$result['error'] = '';

		return $result;
	}

	/**
	 * @return string[]
	 */
	private static function fetch( string $url ): array {
		$response = wp_remote_get( $url, [ 'timeout' => 15 ] );

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return [];
		}

		$lines = preg_split( '/\R/', (string) wp_remote_retrieve_body( $response ) ) ?: [];

		// Every line is validated as a CIDR: a mangled or hijacked response
		// must not be able to inject something that widens the trust list.
		return Ip_Matcher::sanitize_list( $lines );
	}

	/**
	 * Ready-made presets for the settings screen.
	 *
	 * @return array<string, array{label:string, ranges:string[]}>
	 */
	public static function presets(): array {
		$cf = self::get();

		return [
			'cloudflare' => [
				'label'  => __( 'Cloudflare', 'wp-security-center' ),
				'ranges' => array_merge( $cf['v4'], $cf['v6'] ),
			],
			'docker'     => [
				'label'  => __( 'Traefik / Docker / private networks', 'wp-security-center' ),
				'ranges' => [ '172.16.0.0/12', '10.0.0.0/8', '192.168.0.0/16', 'fc00::/7' ],
			],
			'loopback'   => [
				'label'  => __( 'Loopback only', 'wp-security-center' ),
				'ranges' => [ '127.0.0.0/8', '::1/128' ],
			],
		];
	}
}
