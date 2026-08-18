<?php
/**
 * Extracts a single member from a .tar.gz.
 *
 * Deliberately not PharData: many hardened hosts disable the phar extension
 * outright, and a security plugin that needs phar to update its own database
 * is a security plugin that stops working on exactly the servers that care
 * most.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Tar_Reader {

	private const BLOCK = 512;

	/**
	 * Extract the first member whose name ends with $suffix.
	 *
	 * @param string $archive Path to a .tar.gz file.
	 * @param string $suffix  Member name suffix, e.g. "GeoLite2-Country.mmdb".
	 * @param string $target  Destination path.
	 * @return true|\WP_Error
	 */
	public static function extract_member( string $archive, string $suffix, string $target ) {
		if ( ! is_readable( $archive ) ) {
			return new \WP_Error( 'wpsec_tar_unreadable', __( 'The downloaded archive could not be read.', 'sentinel-security-center' ) );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading a local temporary file we just downloaded, not a remote resource.
		$raw = file_get_contents( $archive );

		if ( false === $raw || '' === $raw ) {
			return new \WP_Error( 'wpsec_tar_empty', __( 'The downloaded archive was empty.', 'sentinel-security-center' ) );
		}

		$tar = @gzdecode( $raw );

		if ( false === $tar ) {
			return new \WP_Error( 'wpsec_tar_gzip', __( 'The downloaded archive is not valid gzip data.', 'sentinel-security-center' ) );
		}

		unset( $raw );

		$length = strlen( $tar );
		$offset = 0;

		while ( $offset + self::BLOCK <= $length ) {
			$header  = substr( $tar, $offset, self::BLOCK );
			$offset += self::BLOCK;

			// Two consecutive zero blocks mark the end of the archive.
			if ( '' === trim( $header, "\0" ) ) {
				break;
			}

			$name = trim( substr( $header, 0, 100 ), " \0" );
			$size = octdec( trim( substr( $header, 124, 12 ), " \0" ) );
			$type = substr( $header, 156, 1 );

			$size = is_numeric( $size ) ? (int) $size : 0;

			// Reject anything that tries to escape the target directory. A
			// malicious archive must not be able to choose where we write.
			if ( str_contains( $name, '..' ) || str_starts_with( $name, '/' ) ) {
				return new \WP_Error(
					'wpsec_tar_traversal',
					__( 'The archive contains an unsafe file path and was rejected.', 'sentinel-security-center' )
				);
			}

			$padded = (int) ( ceil( $size / self::BLOCK ) * self::BLOCK );

			// '0' and "\0" are regular files; anything else is skipped.
			if ( ( '0' === $type || "\0" === $type ) && str_ends_with( $name, $suffix ) ) {
				if ( $offset + $size > $length ) {
					return new \WP_Error( 'wpsec_tar_truncated', __( 'The downloaded archive is truncated.', 'sentinel-security-center' ) );
				}

				$content = substr( $tar, $offset, $size );

				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- writing to our own private directory; WP_Filesystem is not initialised during cron.
				if ( false === file_put_contents( $target, $content ) ) {
					return new \WP_Error( 'wpsec_tar_write', __( 'The extracted database could not be written to disk.', 'sentinel-security-center' ) );
				}

				return true;
			}

			$offset += $padded;
		}

		return new \WP_Error(
			'wpsec_tar_not_found',
			__( 'The archive did not contain the expected database file.', 'sentinel-security-center' )
		);
	}
}
