<?php
/**
 * Activation, schema creation, migration and uninstall.
 *
 * All schema and option defaults live here so there is exactly one place to
 * look when reasoning about what a fresh install produces.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Installer {

	// -------------------------------------------------------------------------
	// Option names
	// -------------------------------------------------------------------------
	public const OPTION_VERSION      = 'wpsec_version';
	public const OPTION_DATA_VERSION = 'wpsec_data_version';
	public const OPTION_SETTINGS     = 'wpsec_settings';
	public const OPTION_EVENTS       = 'wpsec_events';
	public const OPTION_GEO          = 'wpsec_geo';
	public const OPTION_GEOIP_STATE  = 'wpsec_geoip_state';
	public const OPTION_TEMP_ALLOW   = 'wpsec_temp_allowlist';
	public const OPTION_BYPASS       = 'wpsec_bypass_tokens';
	public const OPTION_INTEGRITY    = 'wpsec_integrity';
	public const OPTION_SNAPSHOT     = 'wpsec_config_snapshot';
	public const OPTION_LOG          = 'wpsec_log_settings';
	public const OPTION_SCAN_CURSOR  = 'wpsec_scan_cursor';
	public const OPTION_CF_RANGES    = 'wpsec_cf_ranges';
	public const OPTION_NOTICES      = 'wpsec_notices';
	public const OPTION_2FA          = 'wpsec_two_factor';

	/**
	 * Every option this plugin owns. Used by uninstall() so cleanup can never
	 * drift out of sync with the list above.
	 *
	 * @return string[]
	 */
	private static function all_options(): array {
		return [
			self::OPTION_VERSION,
			self::OPTION_DATA_VERSION,
			self::OPTION_SETTINGS,
			self::OPTION_EVENTS,
			self::OPTION_GEO,
			self::OPTION_GEOIP_STATE,
			self::OPTION_TEMP_ALLOW,
			self::OPTION_BYPASS,
			self::OPTION_INTEGRITY,
			self::OPTION_SNAPSHOT,
			self::OPTION_LOG,
			self::OPTION_SCAN_CURSOR,
			self::OPTION_CF_RANGES,
			self::OPTION_NOTICES,
			self::OPTION_2FA,
		];
	}

	// -------------------------------------------------------------------------
	// Cron hooks
	// -------------------------------------------------------------------------
	public const CRON_USER_SCAN   = 'wpsec_user_scan';
	public const CRON_FILE_SCAN   = 'wpsec_file_scan';
	public const CRON_CONFIG_SCAN = 'wpsec_config_scan';
	public const CRON_CORE_SCAN   = 'wpsec_core_scan';
	public const CRON_GEOIP       = 'wpsec_geoip_refresh';
	public const CRON_PRUNE       = 'wpsec_prune_log';

	/**
	 * Cron hook => recurrence. WP-Cron is request-driven, so on a quiet site
	 * these can run late — the Status screen warns when a job is overdue.
	 *
	 * @return array<string, string>
	 */
	public static function cron_schedule(): array {
		return [
			self::CRON_USER_SCAN   => 'hourly',
			self::CRON_FILE_SCAN   => 'daily',
			self::CRON_CONFIG_SCAN => 'twicedaily',
			self::CRON_CORE_SCAN   => 'daily',
			self::CRON_GEOIP       => 'weekly',
			self::CRON_PRUNE       => 'daily',
		];
	}

	// -------------------------------------------------------------------------
	// Table names
	// -------------------------------------------------------------------------

	public static function table_log(): string {
		global $wpdb;
		return $wpdb->prefix . 'wpsec_log';
	}

	public static function table_user_baseline(): string {
		global $wpdb;
		return $wpdb->prefix . 'wpsec_user_baseline';
	}

	public static function table_file_baseline(): string {
		global $wpdb;
		return $wpdb->prefix . 'wpsec_file_baseline';
	}

	// -------------------------------------------------------------------------
	// Lifecycle
	// -------------------------------------------------------------------------

	/**
	 * Runs on activation only.
	 *
	 * Deliberately no `current_user_can( 'activate_plugins' )` guard: reaching
	 * this hook already requires having activated the plugin, and WP-CLI
	 * activates with no logged-in user at all. Guarding here would silently
	 * skip schema creation on every `wp plugin activate`.
	 */
	public static function activate(): void {
		// Single-site only, by design. Bail loudly rather than misbehave
		// quietly: on multisite the log table, the settings and the
		// administrator concept would all need network-aware handling.
		if ( is_multisite() ) {
			deactivate_plugins( WPSEC_BASENAME );
			wp_die(
				esc_html__( 'Sentinel Security Center does not support WordPress Multisite. It has not been activated.', 'sentinel-security-center' ),
				esc_html__( 'Multisite is not supported', 'sentinel-security-center' ),
				[
					'back_link' => true,
					'response'  => 200,
				]
			);
		}

		self::create_tables();
		self::seed_options();
		self::schedule_cron();

		update_option( self::OPTION_VERSION, WPSEC_VERSION );
		update_option( self::OPTION_DATA_VERSION, WPSEC_DATA_VERSION );

		// Adopt the site as it is today. Without this an established install
		// would greet the administrator with a wall of "new file" and "unknown
		// user" reports for things that have been in place for years, and the
		// real signal would drown in it.
		User_Reconciler::establish_baseline();
		Config_Scanner::establish_baseline();
		File_Scanner::establish_baseline();

		Logger::log(
			'security_center.activated',
			[
				'object_id' => WPSEC_VERSION,
				'message'   => sprintf(
					'Sentinel Security Center %s was activated. The current state of users, files and configuration has been recorded as the baseline; changes from here on will be reported.',
					WPSEC_VERSION
				),
				'data'      => [ 'version' => WPSEC_VERSION ],
			]
		);
	}

	/**
	 * Runs on deactivation. Data is deliberately preserved — an admin who
	 * toggles the plugin off must not lose their audit trail. Removal happens
	 * in uninstall(), and only when explicitly opted into.
	 */
	public static function deactivate(): void {
		// Recorded before the cron jobs go, so the log shows that monitoring
		// stopped and when. A deactivation nobody noticed is how a compromise
		// stays invisible.
		Logger::log(
			'security_center.deactivated',
			[
				'object_id' => WPSEC_VERSION,
				'message'   => 'Sentinel Security Center was deactivated. Nothing is being monitored until it is switched back on.',
				'data'      => [ 'version' => WPSEC_VERSION ],
			]
		);

		foreach ( array_keys( self::cron_schedule() ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
	}

	/**
	 * Runs on every boot, not only on activation, so a site updated by
	 * uploading files (rather than through the updater) still converges.
	 */
	public static function maybe_migrate(): void {
		self::notice_version_change();

		$stored = (string) get_option( self::OPTION_DATA_VERSION, '0' );

		if ( version_compare( $stored, WPSEC_DATA_VERSION, '>=' ) ) {
			// Schema is current. Still make sure the cron jobs exist — they can
			// go missing if another plugin clears the cron array.
			self::schedule_cron();
			self::verify_tables();
			return;
		}

		self::create_tables();
		self::seed_options();
		self::schedule_cron();

		self::forget_own_baseline_rows();

		update_option( self::OPTION_DATA_VERSION, WPSEC_DATA_VERSION );
		update_option( self::OPTION_VERSION, WPSEC_VERSION );
	}

	/**
	 * Drop baseline rows for this plugin's own GeoIP guard files.
	 *
	 * Earlier versions could record those files — and reporting them was the
	 * bug. Left in place, the rows would now come back once as "no longer
	 * present" the moment the scanner stops walking into that directory.
	 */
	private static function forget_own_baseline_rows(): void {
		global $wpdb;

		$table = self::table_file_baseline();
		$like  = '%' . $wpdb->esc_like( 'wpsec-geoip-' ) . '%';

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared -- table name from $wpdb->prefix; the pattern IS bound through prepare().
		$wpdb->query( $wpdb->prepare( "DELETE FROM `{$table}` WHERE path LIKE %s", $like ) );
	}

	/**
	 * Notice that the files on disk are a different version than last time.
	 *
	 * An update applied through the updater ends in upgrader_process_complete,
	 * which clears the cached release lookup. An update applied any other way —
	 * git pull, rsync, an unzipped upload — ends in nothing at all, and both
	 * WordPress's twice-daily update check and our own six-hour release cache
	 * go on describing the copy that used to be here. The visible symptom is a
	 * plugins screen offering an update to the version already installed.
	 */
	private static function notice_version_change(): void {
		if ( (string) get_option( self::OPTION_VERSION, '' ) === WPSEC_VERSION ) {
			return;
		}

		update_option( self::OPTION_VERSION, WPSEC_VERSION );

		Updater::forget_release();
		delete_site_transient( 'update_plugins' );
	}

	/**
	 * Called from uninstall.php. Only destroys data when the admin opted in.
	 */
	public static function uninstall(): void {
		global $wpdb;

		$settings = (array) get_option( self::OPTION_SETTINGS, [] );

		foreach ( array_keys( self::cron_schedule() ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}

		if ( empty( $settings['delete_data_on_uninstall'] ) ) {
			return;
		}

		self::delete_geoip_directory();

		foreach ( self::all_options() as $option ) {
			delete_option( $option );
		}

		foreach ( [ self::table_log(), self::table_user_baseline(), self::table_file_baseline() ] as $table ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- a table name cannot be a placeholder; the value is built from $wpdb->prefix and our own constant.
			$wpdb->query( "DROP TABLE IF EXISTS `{$table}`" );
		}
	}

	/**
	 * Self-heal a version option that claims to be current while a table is
	 * actually missing — a partial restore, a half-finished manual import, or
	 * someone dropping a table by hand. Without this the plugin would silently
	 * stop logging, which is the worst possible failure mode for an audit tool.
	 *
	 * Probed at most once a day so the common path stays free of extra queries.
	 */
	private static function verify_tables(): void {
		if ( get_transient( 'wpsec_tables_verified' ) ) {
			return;
		}

		set_transient( 'wpsec_tables_verified', 1, DAY_IN_SECONDS );

		global $wpdb;

		foreach ( [ self::table_log(), self::table_user_baseline(), self::table_file_baseline() ] as $table ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- table name built from $wpdb->prefix; result is not cacheable by design.
			$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );

			if ( $found !== $table ) {
				self::create_tables();
				return;
			}
		}
	}

	// -------------------------------------------------------------------------
	// Schema
	// -------------------------------------------------------------------------

	/**
	 * dbDelta is picky: two spaces after PRIMARY KEY, `KEY` never `INDEX`,
	 * lowercase types, one field per line, and no prefix-length index syntax
	 * (which would make it re-issue ALTER TABLE on every single load).
	 */
	private static function create_tables(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$log     = self::table_log();
		$users   = self::table_user_baseline();
		$files   = self::table_file_baseline();

		dbDelta(
			"CREATE TABLE {$log} (
	id bigint(20) unsigned NOT NULL auto_increment,
	event_time datetime NOT NULL default '0000-00-00 00:00:00',
	event_type varchar(64) NOT NULL default '',
	severity tinyint(3) unsigned NOT NULL default 10,
	object_type varchar(32) NOT NULL default '',
	object_id varchar(191) NOT NULL default '',
	object_label varchar(191) NOT NULL default '',
	actor_user_id bigint(20) unsigned NOT NULL default 0,
	actor_login varchar(60) NOT NULL default '',
	actor_roles varchar(191) NOT NULL default '',
	target_user_id bigint(20) unsigned NOT NULL default 0,
	target_login varchar(60) NOT NULL default '',
	ip_bin varbinary(16) default NULL,
	ip_text varchar(45) NOT NULL default '',
	country char(2) NOT NULL default '',
	context varchar(16) NOT NULL default '',
	request_uri varchar(255) NOT NULL default '',
	user_agent varchar(255) NOT NULL default '',
	message text NOT NULL,
	data longtext NOT NULL,
	alert_state tinyint(3) unsigned NOT NULL default 0,
	PRIMARY KEY  (id),
	KEY idx_time (event_time),
	KEY idx_type_time (event_type, event_time),
	KEY idx_sev_time (severity, event_time),
	KEY idx_actor_time (actor_user_id, event_time),
	KEY idx_ip_time (ip_bin, event_time),
	KEY idx_object (object_type, object_id),
	KEY idx_alert_state (alert_state)
) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$users} (
	user_id bigint(20) unsigned NOT NULL,
	user_login varchar(60) NOT NULL default '',
	user_email varchar(100) NOT NULL default '',
	user_nicename varchar(50) NOT NULL default '',
	display_name varchar(250) NOT NULL default '',
	pass_hash char(64) NOT NULL default '',
	roles varchar(191) NOT NULL default '',
	caps_hash char(64) NOT NULL default '',
	row_hash char(64) NOT NULL default '',
	registered datetime NOT NULL default '0000-00-00 00:00:00',
	updated_at datetime NOT NULL default '0000-00-00 00:00:00',
	PRIMARY KEY  (user_id),
	KEY idx_row_hash (row_hash),
	KEY idx_updated (updated_at)
) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$files} (
	id bigint(20) unsigned NOT NULL auto_increment,
	scope varchar(20) NOT NULL default '',
	path varchar(255) NOT NULL default '',
	path_hash char(64) NOT NULL default '',
	size bigint(20) unsigned NOT NULL default 0,
	mtime bigint(20) unsigned NOT NULL default 0,
	sha256 char(64) NOT NULL default '',
	suspicion smallint(5) unsigned NOT NULL default 0,
	signatures varchar(255) NOT NULL default '',
	first_seen datetime NOT NULL default '0000-00-00 00:00:00',
	last_seen datetime NOT NULL default '0000-00-00 00:00:00',
	PRIMARY KEY  (id),
	UNIQUE KEY uniq_path (path_hash),
	KEY idx_scope (scope),
	KEY idx_last_seen (last_seen),
	KEY idx_suspicion (suspicion)
) {$charset};"
		);
	}

	// -------------------------------------------------------------------------
	// Option defaults
	// -------------------------------------------------------------------------

	/**
	 * add_option() never overwrites, so re-running this on upgrade is safe and
	 * preserves whatever the admin has configured.
	 */
	private static function seed_options(): void {
		// The defaults themselves are pure data (so they can be unit-tested
		// without WordPress); the site-specific values are filled in here.
		$settings               = self::default_settings();
		$settings['recipients'] = array_filter( [ (string) get_option( 'admin_email' ) ] );
		$settings['from_name']  = (string) get_bloginfo( 'name' );

		add_option( self::OPTION_SETTINGS, $settings );
		add_option( self::OPTION_EVENTS, [] );
		add_option( self::OPTION_GEO, self::default_geo() );
		add_option( self::OPTION_INTEGRITY, self::default_integrity() );
		add_option( self::OPTION_LOG, self::default_log_settings() );
		add_option( self::OPTION_2FA, self::default_two_factor() );

		// Non-autoloaded working state. These are written on every scan or
		// lookup, so keeping them out of the autoload set matters.
		add_option( self::OPTION_GEOIP_STATE, self::default_geoip_state(), '', false );
		add_option( self::OPTION_TEMP_ALLOW, [], '', false );
		add_option( self::OPTION_BYPASS, [], '', false );
		add_option( self::OPTION_SNAPSHOT, [], '', false );
		add_option( self::OPTION_SCAN_CURSOR, [], '', false );
		add_option( self::OPTION_CF_RANGES, [], '', false );
		add_option( self::OPTION_NOTICES, [], '', false );
	}

	/**
	 * Pure defaults — deliberately free of WordPress calls so they can be
	 * asserted in a unit test. `recipients` and `from_name` are filled in from
	 * the site in seed_options().
	 *
	 * @return array<string, mixed>
	 */
	public static function default_settings(): array {
		return [
			'recipients'               => [],
			'from_name'                => '',
			'from_email'               => '',
			// Alerts are sent immediately and are never digested. This is
			// purely a safety valve: a mass finding (say 500 planted PHP files)
			// must not turn into 500 outbound mails and a blacklisted mail
			// server. Above the budget, delivery is throttled and one summary
			// is sent — every event is still written to the log.
			'mail_budget_per_hour'     => 50,
			'delete_data_on_uninstall' => false,
		];
	}

	/**
	 * Safe-by-default: evaluation and logging are on, blocking is not.
	 *
	 * The country allow list starts EMPTY on purpose. This plugin ships to
	 * arbitrary sites, so guessing a country would be wrong for most of them.
	 * An empty list never blocks anything (see Access_Policy rail D) and the
	 * settings screen prompts for setup with a one-click "add my current
	 * country" action.
	 *
	 * @return array<string, mixed>
	 */
	public static function default_geo(): array {
		return [
			'enabled'              => true,
			'mode'                 => 'monitor',
			'countries'            => [],
			'allow_ips'            => [],
			'trusted_proxies'      => [],
			'header_priority'      => [ 'HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_FORWARDED_FOR' ],
			'country_headers'      => [ 'HTTP_CF_IPCOUNTRY' ],
			'use_country_header'   => true,
			'apply_to_api_auth'    => false,
			'bypass_enabled'       => true,
			'bypass_token_ttl_min' => 60,
			'bypass_grant_hours'   => 8,
			'deny_ips'             => [],
			'maxmind_license_key'  => '',
			'maxmind_account_id'   => '',
			'db_stale_days'        => 45,
		];
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function default_integrity(): array {
		return [
			'scan_muplugins'      => true,
			'scan_uploads'        => true,
			'scan_config_files'   => true,
			'core_checksums'      => true,
			'heuristics'          => true,
			'signature_threshold' => 60,
			'max_files_per_run'   => 20000,
			'max_hash_bytes'      => 2097152,
			'exclusions'          => [],
		];
	}

	/**
	 * Two-factor defaults.
	 *
	 * Available but never imposed: the feature is on, nobody is required to
	 * use it, and the e-mail fallback — which reduces the second factor to
	 * whoever can read the mailbox — starts switched off.
	 *
	 * @return array<string, mixed>
	 */
	public static function default_two_factor(): array {
		return [
			'enabled'        => true,
			'require_admins' => false,
			'required_since' => 0,
			'grace_days'     => 7,
			'email_fallback' => false,
			'email_ttl_min'  => 10,
		];
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function default_log_settings(): array {
		return [
			'retention_days' => 180,
			'per_page'       => 50,
		];
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function default_geoip_state(): array {
		return [
			'path'         => '',
			'dir'          => '',
			'build_epoch'  => 0,
			'sha256'       => '',
			'last_check'   => 0,
			'last_success' => 0,
			'last_error'   => '',
			'source'       => '',
		];
	}

	// -------------------------------------------------------------------------
	// Cron
	// -------------------------------------------------------------------------

	private static function schedule_cron(): void {
		foreach ( self::cron_schedule() as $hook => $recurrence ) {
			if ( wp_next_scheduled( $hook ) ) {
				continue;
			}

			// Spread the first run out so a fleet of sites installed from the
			// same image does not stampede api.wordpress.org or MaxMind in the
			// same minute.
			$offset = self::CRON_GEOIP === $hook
				? wp_rand( 0, WEEK_IN_SECONDS )
				: wp_rand( 0, HOUR_IN_SECONDS );

			wp_schedule_event( time() + $offset, $recurrence, $hook );
		}
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Remove the randomly-named GeoIP directory created under uploads.
	 */
	private static function delete_geoip_directory(): void {
		$state = (array) get_option( self::OPTION_GEOIP_STATE, [] );
		$dir   = (string) ( $state['dir'] ?? '' );

		if ( '' === $dir || ! is_dir( $dir ) ) {
			return;
		}

		// Only ever delete inside the uploads directory, and only a path that
		// carries our own marker. A corrupted option must not be able to point
		// a recursive delete at something else.
		$uploads = wp_upload_dir();
		$base    = trailingslashit( (string) ( $uploads['basedir'] ?? '' ) );

		if ( '' === $base || ! str_starts_with( $dir, $base ) || ! str_contains( $dir, 'wpsec-geoip-' ) ) {
			return;
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';
		global $wp_filesystem;
		WP_Filesystem();

		if ( $wp_filesystem ) {
			$wp_filesystem->delete( $dir, true );
		}
	}
}
