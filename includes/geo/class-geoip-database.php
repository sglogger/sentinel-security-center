<?php
/**
 * Acquires, verifies and refreshes the local GeoLite2 country database.
 *
 * The file cannot be bundled with the plugin: MaxMind's licence forbids
 * redistribution. Downloading it with the site owner's own licence key is the
 * only lawful route, which is why first-run setup asks for one.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Geoip_Database {

	private const EDITION = 'GeoLite2-Country';
	private const FILE    = 'GeoLite2-Country.mmdb';

	public function register(): void {
		add_action( Installer::CRON_GEOIP, [ __CLASS__, 'refresh' ] );
	}

	/**
	 * The licence key, preferring the constant so it need not live in the
	 * database at all.
	 */
	public static function license_key(): string {
		if ( defined( 'WPSEC_MAXMIND_LICENSE_KEY' ) && WPSEC_MAXMIND_LICENSE_KEY ) {
			return (string) WPSEC_MAXMIND_LICENSE_KEY;
		}

		$geo = (array) get_option( Installer::OPTION_GEO, [] );

		return (string) ( $geo['maxmind_license_key'] ?? '' );
	}

	/**
	 * Absolute path to the active database, or '' when there is none.
	 */
	public static function path(): string {
		if ( defined( 'WPSEC_GEOIP_PATH' ) && WPSEC_GEOIP_PATH && is_readable( (string) WPSEC_GEOIP_PATH ) ) {
			return (string) WPSEC_GEOIP_PATH;
		}

		$state = (array) get_option( Installer::OPTION_GEOIP_STATE, [] );
		$path  = (string) ( $state['path'] ?? '' );

		return ( '' !== $path && is_readable( $path ) ) ? $path : '';
	}

	public static function exists(): bool {
		return '' !== self::path();
	}

	/**
	 * Directory the database lives in, created on first use.
	 *
	 * The name carries a random component because .htaccess does nothing on
	 * nginx; an unguessable path is the practical mitigation there. The README
	 * ships an nginx snippet, and WPSEC_GEOIP_PATH allows moving the file out
	 * of the webroot entirely.
	 */
	public static function directory(): string {
		$state = (array) get_option( Installer::OPTION_GEOIP_STATE, [] );
		$dir   = (string) ( $state['dir'] ?? '' );

		if ( '' !== $dir && is_dir( $dir ) ) {
			return trailingslashit( $dir );
		}

		$uploads = wp_upload_dir();
		$base    = trailingslashit( (string) ( $uploads['basedir'] ?? '' ) );

		if ( '' === $base ) {
			return '';
		}

		$dir = $base . 'wpsec-geoip-' . bin2hex( random_bytes( 4 ) ) . '/';

		wp_mkdir_p( $dir );
		self::protect( $dir );

		$state['dir'] = $dir;
		update_option( Installer::OPTION_GEOIP_STATE, $state, false );

		return $dir;
	}

	/**
	 * Drop the usual web-server denials into the directory.
	 */
	private static function protect( string $dir ): void {
		$files = [
			'index.php'  => "<?php\n// Silence is golden.\n",
			'.htaccess'  => "Order allow,deny\nDeny from all\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n",
			'web.config' => "<?xml version=\"1.0\"?>\n<configuration><system.webServer><security><requestFiltering><hiddenSegments><add segment=\".\" /></hiddenSegments></requestFiltering></security></system.webServer></configuration>\n",
		];

		foreach ( $files as $name => $contents ) {
			if ( ! file_exists( $dir . $name ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- our own private directory; runs during cron where WP_Filesystem is unavailable.
				@file_put_contents( $dir . $name, $contents );
			}
		}
	}

	/**
	 * Download and install the database.
	 *
	 * @return true|\WP_Error
	 */
	public static function refresh() {
		$state               = (array) get_option( Installer::OPTION_GEOIP_STATE, [] );
		$state['last_check'] = time();

		$key = self::license_key();

		if ( '' === $key ) {
			$state['last_error'] = __( 'No MaxMind licence key is configured.', 'wp-security-center' );
			update_option( Installer::OPTION_GEOIP_STATE, $state, false );

			return new \WP_Error( 'wpsec_geoip_no_key', $state['last_error'] );
		}

		$dir = self::directory();

		if ( '' === $dir ) {
			$state['last_error'] = __( 'The uploads directory is not writable.', 'wp-security-center' );
			update_option( Installer::OPTION_GEOIP_STATE, $state, false );

			return new \WP_Error( 'wpsec_geoip_no_dir', $state['last_error'] );
		}

		$base = add_query_arg(
			[
				'edition_id'  => self::EDITION,
				'license_key' => $key,
			],
			'https://download.maxmind.com/app/geoip_download'
		);

		$tmp = $dir . 'download.tar.gz';

		// Streamed to a file rather than held in memory — the archive is a few
		// megabytes and shared hosts have small memory limits.
		$response = wp_remote_get(
			add_query_arg( 'suffix', 'tar.gz', $base ),
			[
				'timeout'  => 60,
				'stream'   => true,
				'filename' => $tmp,
			]
		);

		$error = self::response_error( $response );

		if ( null !== $error ) {
			@unlink( $tmp );
			return self::fail( $state, $error );
		}

		// Verify the checksum MaxMind publishes alongside the archive before
		// unpacking anything.
		$sum_response = wp_remote_get( add_query_arg( 'suffix', 'tar.gz.sha256', $base ), [ 'timeout' => 30 ] );
		$sum_error    = self::response_error( $sum_response );

		if ( null === $sum_error ) {
			$expected = strtok( trim( (string) wp_remote_retrieve_body( $sum_response ) ), " \t" );
			$actual   = hash_file( 'sha256', $tmp );

			if ( is_string( $expected ) && '' !== $expected && ! hash_equals( $expected, (string) $actual ) ) {
				@unlink( $tmp );
				return self::fail( $state, __( 'The downloaded database failed its checksum verification.', 'wp-security-center' ) );
			}
		}

		// Extract next to the live file, then swap atomically, so a concurrent
		// login lookup never sees a half-written database.
		$staged = $dir . self::FILE . '.new';
		$result = Tar_Reader::extract_member( $tmp, self::FILE, $staged );

		@unlink( $tmp );

		if ( is_wp_error( $result ) ) {
			@unlink( $staged );
			return self::fail( $state, $result->get_error_message() );
		}

		if ( ! self::looks_valid( $staged ) ) {
			@unlink( $staged );
			return self::fail( $state, __( 'The extracted file does not look like a MaxMind database.', 'wp-security-center' ) );
		}

		$live = $dir . self::FILE;

		if ( ! @rename( $staged, $live ) ) {
			@unlink( $staged );
			return self::fail( $state, __( 'The new database could not replace the existing one.', 'wp-security-center' ) );
		}

		$state['path']         = $live;
		$state['sha256']       = (string) hash_file( 'sha256', $live );
		$state['build_epoch']  = (int) filemtime( $live );
		$state['last_success'] = time();
		$state['last_error']   = '';
		$state['source']       = 'maxmind';

		update_option( Installer::OPTION_GEOIP_STATE, $state, false );

		Country_Resolver::flush();

		Logger::log(
			'geoip.db_updated',
			[
				'object_id' => self::EDITION,
				'message'   => sprintf( 'The GeoLite2 country database was updated (%s).', size_format( (int) filesize( $live ) ) ),
				'data'      => [ 'size' => (int) filesize( $live ) ],
			]
		);

		return true;
	}

	/**
	 * @param array<string, mixed>|\WP_Error $response wp_remote_get result.
	 */
	private static function response_error( $response ): ?string {
		if ( is_wp_error( $response ) ) {
			return $response->get_error_message();
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( 401 === $code || 403 === $code ) {
			return __( 'MaxMind rejected the licence key.', 'wp-security-center' );
		}

		if ( 200 !== $code ) {
			/* translators: %d: HTTP status code */
			return sprintf( __( 'MaxMind returned HTTP %d.', 'wp-security-center' ), $code );
		}

		return null;
	}

	/**
	 * @param array<string, mixed> $state   Current state option.
	 * @param string               $message Failure reason.
	 */
	private static function fail( array $state, string $message ): \WP_Error {
		$state['last_error'] = $message;
		update_option( Installer::OPTION_GEOIP_STATE, $state, false );

		Logger::log(
			'geoip.db_update_failed',
			[
				'object_id' => self::EDITION,
				'message'   => sprintf( 'The GeoIP database could not be updated: %s', $message ),
				'data'      => [ 'error' => $message ],
			]
		);

		return new \WP_Error( 'wpsec_geoip_failed', $message );
	}

	/**
	 * Cheap sanity checks before a downloaded file is trusted as the database.
	 */
	private static function looks_valid( string $path ): bool {
		if ( ! is_readable( $path ) ) {
			return false;
		}

		$size = (int) filesize( $path );

		if ( $size < 100000 ) {
			return false;
		}

		// The MaxMind metadata marker lives near the end of the file.
		$handle = @fopen( $path, 'rb' );

		if ( ! $handle ) {
			return false;
		}

		fseek( $handle, max( 0, $size - 131072 ) );
		$tail = (string) fread( $handle, 131072 );
		fclose( $handle );

		return false !== strpos( $tail, "\xAB\xCD\xEFMaxMind.com" );
	}

	/**
	 * Is the database old enough to warn about?
	 */
	public static function is_stale(): bool {
		$geo   = (array) get_option( Installer::OPTION_GEO, [] );
		$state = (array) get_option( Installer::OPTION_GEOIP_STATE, [] );

		$days  = (int) ( $geo['db_stale_days'] ?? 45 );
		$built = (int) ( $state['build_epoch'] ?? 0 );

		if ( $days <= 0 || 0 === $built ) {
			return false;
		}

		return ( time() - $built ) > ( $days * DAY_IN_SECONDS );
	}

	/**
	 * Check whether the database is reachable over HTTP, which it must not be.
	 * Shown on the Status screen because .htaccess is ignored by nginx.
	 *
	 * @return array{tested:bool, exposed:bool, url:string}
	 */
	public static function exposure_check(): array {
		$state = (array) get_option( Installer::OPTION_GEOIP_STATE, [] );
		$dir   = (string) ( $state['dir'] ?? '' );
		$path  = self::path();

		$uploads = wp_upload_dir();
		$basedir = trailingslashit( (string) ( $uploads['basedir'] ?? '' ) );
		$baseurl = trailingslashit( (string) ( $uploads['baseurl'] ?? '' ) );

		if ( '' === $path || '' === $dir || '' === $basedir || ! str_starts_with( $path, $basedir ) ) {
			return [
				'tested'  => false,
				'exposed' => false,
				'url'     => '',
			];
		}

		$url = $baseurl . ltrim( substr( $path, strlen( $basedir ) ), '/' );

		$response = wp_remote_head( $url, [ 'timeout' => 5 ] );

		if ( is_wp_error( $response ) ) {
			return [
				'tested'  => false,
				'exposed' => false,
				'url'     => $url,
			];
		}

		return [
			'tested'  => true,
			'exposed' => 200 === (int) wp_remote_retrieve_response_code( $response ),
			'url'     => $url,
		];
	}
}
