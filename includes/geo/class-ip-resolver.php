<?php
/**
 * Works out the real client IP behind a reverse proxy or CDN.
 *
 * The security property this class exists to provide: forwarding headers are
 * read ONLY when the connecting address is a proxy the administrator explicitly
 * trusted. Anyone who can reach the origin directly can put whatever they like
 * in X-Forwarded-For, so trusting it unconditionally would let an attacker
 * choose their own apparent country.
 *
 * WordPress-free by design — see tests/Unit/IpResolverTest.php.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Ip_Resolver {

	/** @var string[] Trusted proxy addresses/CIDRs. */
	private array $trusted;

	/** @var string[] Single-value forwarding headers, in priority order. */
	private array $header_priority;

	/**
	 * @param string[] $trusted         Trusted proxy addresses/CIDRs.
	 * @param string[] $header_priority $_SERVER keys to consult, in order.
	 */
	public function __construct( array $trusted = [], array $header_priority = [] ) {
		$this->trusted         = $trusted;
		$this->header_priority = $header_priority ?: [
			'HTTP_CF_CONNECTING_IP',
			'HTTP_TRUE_CLIENT_IP',
			'HTTP_X_FORWARDED_FOR',
		];
	}

	/**
	 * Resolve the client address.
	 *
	 * @param array<string, mixed> $server A $_SERVER-shaped array.
	 * @return array{ip:?string, source:string, remote:?string, remote_trusted:bool, chain:string[]}
	 */
	public function resolve( array $server ): array {
		$remote = isset( $server['REMOTE_ADDR'] )
			? Ip_Matcher::normalise( (string) $server['REMOTE_ADDR'] )
			: null;

		$result = [
			'ip'             => $remote,
			'source'         => 'REMOTE_ADDR',
			'remote'         => $remote,
			'remote_trusted' => false,
			'chain'          => [],
		];

		if ( null === $remote ) {
			// No connecting address at all: WP-CLI, cron, a unit test.
			$result['ip']     = null;
			$result['source'] = '';
			return $result;
		}

		// THE anti-spoofing guarantee. With no trusted proxies configured, or a
		// connection from somewhere that is not one, no header is read at all.
		if ( empty( $this->trusted ) || ! Ip_Matcher::in_any( $remote, $this->trusted ) ) {
			return $result;
		}

		$result['remote_trusted'] = true;

		foreach ( $this->header_priority as $header ) {
			$header = (string) $header;

			if ( ! isset( $server[ $header ] ) || '' === trim( (string) $server[ $header ] ) ) {
				continue;
			}

			$raw = (string) $server[ $header ];

			if ( 'HTTP_X_FORWARDED_FOR' === $header || false !== strpos( $raw, ',' ) ) {
				$chain = $this->walk_chain( $raw, $remote );

				$result['chain'] = $chain['chain'];

				if ( null !== $chain['ip'] ) {
					$result['ip']     = $chain['ip'];
					$result['source'] = $header;
					return $result;
				}

				continue;
			}

			// Single-value header such as CF-Connecting-IP.
			$candidate = Ip_Matcher::normalise( $raw );
			if ( null !== $candidate ) {
				$result['ip']     = $candidate;
				$result['source'] = $header;
				return $result;
			}
		}

		return $result;
	}

	/**
	 * Walk an X-Forwarded-For chain from right to left and return the first hop
	 * that is not itself a trusted proxy — that is the furthest address we can
	 * still vouch for. Entries to the left of it were supplied by an untrusted
	 * party and must not be believed.
	 *
	 * @return array{ip:?string, chain:string[]}
	 */
	private function walk_chain( string $raw, string $remote ): array {
		$parts = array_map( 'trim', explode( ',', $raw ) );
		$chain = [];

		foreach ( $parts as $part ) {
			$norm = Ip_Matcher::normalise( $part );
			if ( null !== $norm ) {
				$chain[] = $norm;
			}
		}

		if ( empty( $chain ) ) {
			return [
				'ip'    => null,
				'chain' => [],
			];
		}

		// The connecting address is the rightmost hop, whether or not the proxy
		// appended it.
		$walk = $chain;
		if ( end( $walk ) !== $remote ) {
			$walk[] = $remote;
		}

		for ( $i = count( $walk ) - 1; $i >= 0; $i-- ) {
			if ( ! Ip_Matcher::in_any( $walk[ $i ], $this->trusted ) ) {
				return [
					'ip'    => $walk[ $i ],
					'chain' => $chain,
				];
			}
		}

		// Every hop is a trusted proxy; the leftmost is the best answer.
		return [
			'ip'    => $walk[0],
			'chain' => $chain,
		];
	}

	/**
	 * Convenience wrapper returning just the address.
	 *
	 * @param array<string, mixed> $server A $_SERVER-shaped array.
	 */
	public function client_ip( array $server ): ?string {
		return $this->resolve( $server )['ip'];
	}
}
