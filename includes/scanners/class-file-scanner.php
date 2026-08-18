<?php
/**
 * Filesystem integrity for the two places attackers actually drop code.
 *
 * mu-plugins load before every other plugin and are invisible in the normal
 * plugin list; a PHP file under uploads has no legitimate reason to exist. Both
 * are compared against a stored baseline of hashes.
 *
 * THIS SCANNER NEVER WRITES, MOVES, QUARANTINES OR DELETES A FILE. Everything
 * is opened read-only. A false positive must never be able to break a working
 * site — recovery is the administrator's decision.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class File_Scanner {

	private const SCOPE_MU       = 'mu_plugins';
	private const SCOPE_UPLOADS  = 'uploads_php';
	private const SCOPE_HTACCESS = 'uploads_htaccess';
	private const SCOPE_CONFIG   = 'config';

	/** Directory prefix this plugin uses for its own storage under uploads. */
	private const OWN_DIR_PREFIX = 'wpsec-geoip-';

	/** Extensions that can be executed by a PHP handler. */
	private const PHP_EXTENSIONS = [ 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phps', 'phar', 'pht' ];

	public function register(): void {
		add_action( Installer::CRON_FILE_SCAN, [ __CLASS__, 'run' ] );
	}

	/**
	 * Run a full scan.
	 *
	 * @return array{scanned:int, findings:int}
	 */
	public static function run(): array {
		$settings = (array) get_option( Installer::OPTION_INTEGRITY, [] );

		$scanned  = 0;
		$findings = 0;
		$seen     = [];

		if ( ! empty( $settings['scan_muplugins'] ) ) {
			$result    = self::scan_mu_plugins( $settings );
			$scanned  += $result['scanned'];
			$findings += $result['findings'];
			$seen      = array_merge( $seen, $result['seen'] );
		}

		if ( ! empty( $settings['scan_uploads'] ) ) {
			$result    = self::scan_uploads( $settings );
			$scanned  += $result['scanned'];
			$findings += $result['findings'];
			$seen      = array_merge( $seen, $result['seen'] );
		}

		if ( ! empty( $settings['scan_config_files'] ) ) {
			$result    = self::scan_config_files();
			$scanned  += $result['scanned'];
			$findings += $result['findings'];
			$seen      = array_merge( $seen, $result['seen'] );
		}

		self::report_removals( $seen );

		return [
			'scanned'  => $scanned,
			'findings' => $findings,
		];
	}

	/**
	 * @param array<string, mixed> $settings Integrity settings.
	 * @return array{scanned:int, findings:int, seen:string[]}
	 */
	private static function scan_mu_plugins( array $settings ): array {
		$dir = defined( 'WPMU_PLUGIN_DIR' ) ? (string) WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';

		return self::walk(
			$dir,
			self::SCOPE_MU,
			$settings,
			static fn( string $path ): bool => true,
			'file.new_in_muplugins',
			'file.changed_in_muplugins'
		);
	}

	/**
	 * @param array<string, mixed> $settings Integrity settings.
	 * @return array{scanned:int, findings:int, seen:string[]}
	 */
	private static function scan_uploads( array $settings ): array {
		$uploads = wp_upload_dir();
		$dir     = (string) ( $uploads['basedir'] ?? '' );

		if ( '' === $dir ) {
			return [
				'scanned'  => 0,
				'findings' => 0,
				'seen'     => [],
			];
		}

		// A PHP file and a .htaccess are different findings with different
		// answers, so they are walked separately. Lumping them together
		// reported every .htaccess as "an executable file appeared", which is
		// wrong on both counts: it is not executable and it is not PHP.
		$php = self::walk(
			$dir,
			self::SCOPE_UPLOADS,
			$settings,
			static fn( string $path ): bool => self::is_php( $path ) && ! self::is_own_file( $path ),
			'file.php_in_uploads',
			'file.changed_in_uploads'
		);

		$htaccess = self::walk(
			$dir,
			self::SCOPE_HTACCESS,
			$settings,
			static fn( string $path ): bool => '.htaccess' === basename( $path ) && ! self::is_own_file( $path ),
			'file.uploads_htaccess_changed',
			'file.uploads_htaccess_changed'
		);

		return [
			'scanned'  => $php['scanned'] + $htaccess['scanned'],
			'findings' => $php['findings'] + $htaccess['findings'],
			'seen'     => array_merge( $php['seen'], $htaccess['seen'] ),
		];
	}

	/**
	 * One of the guard files this plugin writes into its own uploads directory.
	 *
	 * The plugin keeps its GeoIP database under uploads behind an index.php and
	 * a .htaccess. Reporting those would be the scanner alarming about itself
	 * on every run. The exemption is deliberately narrow: the directory has to
	 * carry our prefix, the name has to be one of ours, and the contents have
	 * to be byte-for-byte what we wrote. Anything else in there — a shell named
	 * something else, or a shell written over our own index.php — is reported
	 * like any other file.
	 */
	private static function is_own_file( string $path ): bool {
		$uploads = wp_upload_dir();
		$base    = trailingslashit( wp_normalize_path( (string) ( $uploads['basedir'] ?? '' ) ) );
		$path    = wp_normalize_path( $path );

		if ( '/' === $base || ! str_starts_with( $path, $base ) ) {
			return false;
		}

		$segment = strtok( substr( $path, strlen( $base ) ), '/' );

		if ( ! is_string( $segment ) || ! str_starts_with( $segment, self::OWN_DIR_PREFIX ) ) {
			return false;
		}

		return Geoip_Database::is_guard_file( $path );
	}

	/**
	 * @return array{scanned:int, findings:int, seen:string[]}
	 */
	private static function scan_config_files(): array {
		$candidates = array_unique(
			array_filter(
				[
					ABSPATH . 'wp-config.php',
					dirname( ABSPATH ) . '/wp-config.php',
					ABSPATH . '.htaccess',
				],
				'is_readable'
			)
		);

		$scanned  = 0;
		$findings = 0;
		$seen     = [];

		foreach ( $candidates as $path ) {
			$relative = self::relative( $path );
			$seen[]   = $relative;
			++$scanned;

			$hash     = (string) hash_file( 'sha256', $path );
			$existing = self::baseline_row( $relative );

			if ( null === $existing ) {
				self::store( self::SCOPE_CONFIG, $relative, $path, $hash, 0, [] );
				continue;
			}

			if ( $existing['sha256'] === $hash ) {
				self::touch( $relative );
				continue;
			}

			self::store( self::SCOPE_CONFIG, $relative, $path, $hash, 0, [] );
			++$findings;

			$type = str_ends_with( $path, '.htaccess' ) ? 'config.htaccess_changed' : 'config.wpconfig_changed';

			Logger::log(
				$type,
				[
					'object_id'    => $relative,
					'object_label' => basename( $path ),
					'message'      => sprintf(
						'The file %s changed. It was last recorded with a different content hash.',
						$relative
					),
					'data'         => [
						'path'     => $relative,
						'old_hash' => $existing['sha256'],
						'new_hash' => $hash,
						'modified' => gmdate( 'Y-m-d H:i:s', (int) filemtime( $path ) ),
					],
				]
			);
		}

		return [
			'scanned'  => $scanned,
			'findings' => $findings,
			'seen'     => $seen,
		];
	}

	/**
	 * Walk a directory tree and compare against the baseline.
	 *
	 * @param array<string, mixed> $settings   Integrity settings.
	 * @param callable             $filter     Returns true for files worth hashing.
	 * @return array{scanned:int, findings:int, seen:string[]}
	 */
	private static function walk(
		string $dir,
		string $scope,
		array $settings,
		callable $filter,
		string $new_event,
		string $changed_event
	): array {
		$scanned  = 0;
		$findings = 0;
		$seen     = [];

		if ( ! is_dir( $dir ) || ! is_readable( $dir ) ) {
			return [
				'scanned'  => $scanned,
				'findings' => $findings,
				'seen'     => $seen,
			];
		}

		$budget     = max( 100, (int) ( $settings['max_files_per_run'] ?? 20000 ) );
		$max_bytes  = max( 4096, (int) ( $settings['max_hash_bytes'] ?? 2097152 ) );
		$heuristics = ! empty( $settings['heuristics'] );
		$threshold  = max( 1, (int) ( $settings['signature_threshold'] ?? 60 ) );
		$exclusions = (array) ( $settings['exclusions'] ?? [] );

		// Never follow symlinks: a link pointing outside the tree would let a
		// scan wander into the whole filesystem.
		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::LEAVES_ONLY,
			\RecursiveIteratorIterator::CATCH_GET_CHILD
		);

		foreach ( $iterator as $file ) {
			if ( $scanned >= $budget ) {
				Logger::log(
					'scan.budget_exceeded',
					[
						'object_id' => $scope,
						'message'   => sprintf(
							'The %s scan stopped after %d files. Raise the per-run limit or narrow the scope; the remainder is covered by the next run.',
							$scope,
							$budget
						),
						'data'      => [
							'scope' => $scope,
							'limit' => $budget,
						],
					]
				);
				break;
			}

			if ( ! $file->isFile() || $file->isLink() ) {
				continue;
			}

			$path = (string) $file->getPathname();

			if ( ! $filter( $path ) ) {
				continue;
			}

			$relative = self::relative( $path );

			if ( self::excluded( $relative, $exclusions ) ) {
				continue;
			}

			$seen[] = $relative;
			++$scanned;

			$size = (int) $file->getSize();
			$hash = $size <= $max_bytes ? (string) hash_file( 'sha256', $path ) : '';

			$suspicion  = 0;
			$signatures = [];

			if ( $heuristics && self::is_php( $path ) && $size <= $max_bytes ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors -- read-only inspection of a local file; WP_Filesystem adds nothing here and is unavailable during cron. Silenced because a file may vanish between being listed and being read, which the empty string handles.
				$code = (string) @file_get_contents( $path );
				$scan = Signature_Scanner::scan( $code );

				$suspicion  = $scan['score'];
				$signatures = $scan['matches'];
			}

			$existing = self::baseline_row( $relative );

			if ( null === $existing ) {
				self::store( $scope, $relative, $path, $hash, $suspicion, $signatures );
				++$findings;

				Logger::log(
					$new_event,
					[
						'object_id'    => $relative,
						'object_label' => basename( $path ),
						'message'      => self::new_file_message( $scope, $relative, $size ),
						'data'         => [
							'path'      => $relative,
							'size'      => $size,
							'modified'  => gmdate( 'Y-m-d H:i:s', (int) $file->getMTime() ),
							'sha256'    => $hash,
							'suspicion' => $suspicion,
						],
					]
				);

				self::maybe_report_signature( $relative, $path, $suspicion, $signatures, $threshold );
				continue;
			}

			if ( $existing['sha256'] === $hash ) {
				self::touch( $relative );
				continue;
			}

			self::store( $scope, $relative, $path, $hash, $suspicion, $signatures );
			++$findings;

			Logger::log(
				$changed_event,
				[
					'object_id'    => $relative,
					'object_label' => basename( $path ),
					'message'      => sprintf( 'The file %s changed since the last scan.', $relative ),
					'data'         => [
						'path'      => $relative,
						'old_hash'  => $existing['sha256'],
						'new_hash'  => $hash,
						'modified'  => gmdate( 'Y-m-d H:i:s', (int) $file->getMTime() ),
						'suspicion' => $suspicion,
					],
				]
			);

			self::maybe_report_signature( $relative, $path, $suspicion, $signatures, $threshold );
		}

		return [
			'scanned'  => $scanned,
			'findings' => $findings,
			'seen'     => $seen,
		];
	}

	private static function new_file_message( string $scope, string $relative, int $size ): string {
		if ( self::SCOPE_UPLOADS === $scope ) {
			return sprintf(
				'An executable file appeared in the uploads directory: %s (%s). The uploads directory should never contain PHP.',
				$relative,
				size_format( $size )
			);
		}

		if ( self::SCOPE_HTACCESS === $scope ) {
			return sprintf(
				'A .htaccess appeared in the uploads directory: %s (%s). Plugins and hardening tools add these routinely, but one can also be used to make uploaded files executable — check what it contains.',
				$relative,
				size_format( $size )
			);
		}

		return sprintf(
			'A new must-use plugin file appeared: %s (%s). Must-use plugins load before everything else and cannot be deactivated from the dashboard.',
			$relative,
			size_format( $size )
		);
	}

	/**
	 * @param string[] $signatures Matched rule ids.
	 */
	private static function maybe_report_signature( string $relative, string $path, int $suspicion, array $signatures, int $threshold ): void {
		if ( $suspicion < $threshold || empty( $signatures ) ) {
			return;
		}

		Logger::log(
			'file.backdoor_signature',
			[
				'object_id'    => $relative,
				'object_label' => basename( $path ),
				'message'      => sprintf(
					'The file %s matches patterns commonly found in web shells (score %d/100): %s.',
					$relative,
					$suspicion,
					implode( '; ', Signature_Scanner::describe( $signatures ) )
				),
				'data'         => [
					'path'       => $relative,
					'score'      => $suspicion,
					'signatures' => $signatures,
					'reasons'    => Signature_Scanner::describe( $signatures ),
				],
			]
		);
	}

	/**
	 * Report baseline entries that were not seen in this run.
	 *
	 * @param string[] $seen Relative paths encountered.
	 */
	private static function report_removals( array $seen ): void {
		global $wpdb;

		$table = Installer::table_file_baseline();
		$stamp = gmdate( 'Y-m-d H:i:s', time() - 300 );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name from $wpdb->prefix; the timestamp IS bound through prepare().
		$gone = $wpdb->get_results(
			$wpdb->prepare( "SELECT path, path_hash, scope FROM `{$table}` WHERE last_seen < %s", $stamp ),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		if ( empty( $gone ) ) {
			return;
		}

		foreach ( $gone as $row ) {
			Logger::log(
				'file.removed',
				[
					'object_id'    => (string) $row['path'],
					'object_label' => basename( (string) $row['path'] ),
					'message'      => sprintf( 'The previously recorded file %s is no longer present.', (string) $row['path'] ),
					'data'         => [
						'path'  => (string) $row['path'],
						'scope' => (string) $row['scope'],
					],
				]
			);
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter -- our own table; value prepared.
		$wpdb->query( $wpdb->prepare( "DELETE FROM `{$table}` WHERE last_seen < %s", $stamp ) );
	}

	// -------------------------------------------------------------------------
	// Baseline storage
	// -------------------------------------------------------------------------

	/**
	 * @return array<string, mixed>|null
	 */
	private static function baseline_row( string $relative ): ?array {
		global $wpdb;

		$table = Installer::table_file_baseline();

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name from $wpdb->prefix; the path hash IS bound through prepare().
		$row = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM `{$table}` WHERE path_hash = %s", hash( 'sha256', $relative ) ),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return is_array( $row ) ? $row : null;
	}

	/**
	 * @param string[] $signatures Matched rule ids.
	 */
	private static function store( string $scope, string $relative, string $path, string $hash, int $suspicion, array $signatures ): void {
		global $wpdb;

		$now = gmdate( 'Y-m-d H:i:s' );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.PHP.NoSilencedErrors -- the table name is built from $wpdb->prefix and cannot be a placeholder; every value below is one. filesize() and filemtime() are silenced because a file can be gone between the scan listing it and this row being written, which is ordinary on a live site and is answered by the cast to int.
		$wpdb->query(
			$wpdb->prepare(
				'INSERT INTO `' . Installer::table_file_baseline() . '` '
				. '(scope, path, path_hash, size, mtime, sha256, suspicion, signatures, first_seen, last_seen) '
				. 'VALUES (%s, %s, %s, %d, %d, %s, %d, %s, %s, %s) '
				. 'ON DUPLICATE KEY UPDATE scope = VALUES(scope), size = VALUES(size), mtime = VALUES(mtime), '
				. 'sha256 = VALUES(sha256), suspicion = VALUES(suspicion), signatures = VALUES(signatures), last_seen = VALUES(last_seen)',
				$scope,
				mb_substr( $relative, 0, 255 ),
				hash( 'sha256', $relative ),
				(int) @filesize( $path ),
				(int) @filemtime( $path ),
				$hash,
				$suspicion,
				mb_substr( implode( ',', $signatures ), 0, 255 ),
				$now,
				$now
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.PHP.NoSilencedErrors
	}

	private static function touch( string $relative ): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- our own table.
		$wpdb->update(
			Installer::table_file_baseline(),
			[ 'last_seen' => gmdate( 'Y-m-d H:i:s' ) ],
			[ 'path_hash' => hash( 'sha256', $relative ) ],
			[ '%s' ],
			[ '%s' ]
		);
	}

	// -------------------------------------------------------------------------

	private static function is_php( string $path ): bool {
		return in_array(
			strtolower( (string) pathinfo( $path, PATHINFO_EXTENSION ) ),
			self::PHP_EXTENSIONS,
			true
		);
	}

	private static function relative( string $path ): string {
		$root = wp_normalize_path( ABSPATH );
		$path = wp_normalize_path( $path );

		if ( str_starts_with( $path, $root ) ) {
			return substr( $path, strlen( $root ) );
		}

		return $path;
	}

	/**
	 * @param string[] $exclusions Substrings to ignore.
	 */
	private static function excluded( string $relative, array $exclusions ): bool {
		foreach ( $exclusions as $needle ) {
			$needle = trim( (string) $needle );

			if ( '' !== $needle && false !== stripos( $relative, $needle ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Adopt the current filesystem state as the baseline without alerting.
	 * Used on activation so an established site does not produce a wall of
	 * "new file" reports for things that have been there for years.
	 */
	public static function establish_baseline(): void {
		add_filter( 'wpsec_suppress_logging', '__return_true' );
		self::run();
		remove_filter( 'wpsec_suppress_logging', '__return_true' );
	}
}
