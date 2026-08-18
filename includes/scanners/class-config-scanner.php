<?php
/**
 * Periodic snapshot of configuration that has no change hook.
 *
 * Some things simply cannot be observed in real time: must-use plugins load
 * before any plugin can hook anything, a plugin dropped over SFTP never touches
 * the plugin API, and constants and the cron array have no change actions at
 * all. This compares a stored snapshot instead.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Config_Scanner {

	public function register(): void {
		add_action( Installer::CRON_CONFIG_SCAN, [ __CLASS__, 'run' ] );
	}

	/**
	 * @param bool $silent Adopt the current state without reporting.
	 */
	public static function run( bool $silent = false ): void {
		$previous = (array) get_option( Installer::OPTION_SNAPSHOT, [] );
		$current  = self::snapshot();

		// Nothing recorded yet: adopt, do not shout.
		if ( empty( $previous ) || $silent ) {
			update_option( Installer::OPTION_SNAPSHOT, $current, false );
			return;
		}

		self::compare_plugins( $previous, $current );
		self::compare_mu_plugins( $previous, $current );
		self::compare_constants( $previous, $current );
		self::compare_xmlrpc( $previous, $current );
		self::compare_cron( $previous, $current );

		update_option( Installer::OPTION_SNAPSHOT, $current, false );
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function snapshot(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$cron = (array) get_option( 'cron', [] );
		$map  = [];

		// Timestamps are stripped: only the set of scheduled hooks and their
		// arguments matters, otherwise every run would look like a change.
		foreach ( $cron as $timestamp => $hooks ) {
			if ( ! is_array( $hooks ) ) {
				continue;
			}

			foreach ( $hooks as $hook => $events ) {
				if ( ! is_array( $events ) ) {
					continue;
				}

				foreach ( $events as $event ) {
					$schedule = is_array( $event ) ? (string) ( $event['schedule'] ?? 'single' ) : 'single';
					$map[]    = $hook . '|' . $schedule;
				}
			}
		}

		$map = array_values( array_unique( $map ) );
		sort( $map );

		return [
			'plugins'    => array_keys( get_plugins() ),
			'mu_plugins' => array_keys( get_mu_plugins() ),
			'cron'       => $map,
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- xmlrpc_enabled is a WordPress core filter, not a hook of ours. Reading it is the point: whatever a security plugin or the host has done to XML-RPC is exactly what this snapshot needs to record.
			'xmlrpc'     => (bool) apply_filters( 'xmlrpc_enabled', true ),
			'constants'  => [
				'DISALLOW_FILE_EDIT'         => defined( 'DISALLOW_FILE_EDIT' ) ? (bool) DISALLOW_FILE_EDIT : false,
				'DISALLOW_FILE_MODS'         => defined( 'DISALLOW_FILE_MODS' ) ? (bool) DISALLOW_FILE_MODS : false,
				'AUTOMATIC_UPDATER_DISABLED' => defined( 'AUTOMATIC_UPDATER_DISABLED' ) ? (bool) AUTOMATIC_UPDATER_DISABLED : false,
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- not debug output: WP_AUTO_UPDATE_CORE may be bool or string, and this renders it to one comparable form so a change between `true` and `'minor'` is detected rather than lost to a cast.
				'WP_AUTO_UPDATE_CORE'        => defined( 'WP_AUTO_UPDATE_CORE' ) ? (string) var_export( WP_AUTO_UPDATE_CORE, true ) : 'undefined',
				'WP_DEBUG_DISPLAY'           => defined( 'WP_DEBUG_DISPLAY' ) ? (bool) WP_DEBUG_DISPLAY : false,
			],
			'taken_at'   => time(),
		];
	}

	/**
	 * @param array<string, mixed> $previous Old snapshot.
	 * @param array<string, mixed> $current  New snapshot.
	 */
	private static function compare_plugins( array $previous, array $current ): void {
		$added = array_diff( (array) $current['plugins'], (array) $previous['plugins'] );

		if ( empty( $added ) ) {
			return;
		}

		// A plugin that appeared without an install event was put there by
		// something other than WordPress — SFTP, a file manager, or an attacker.
		$recent = self::recent_event_objects( [ 'plugin.installed', 'plugin.updated' ], DAY_IN_SECONDS );

		foreach ( $added as $file ) {
			if ( in_array( $file, $recent, true ) ) {
				continue;
			}

			Logger::log(
				'plugin.appeared_out_of_band',
				[
					'object_id'    => (string) $file,
					'object_label' => (string) $file,
					'message'      => sprintf(
						'The plugin "%s" appeared on disk without any installation being recorded. It may have been uploaded directly.',
						(string) $file
					),
					'data'         => [ 'plugin' => (string) $file ],
				]
			);
		}
	}

	/**
	 * @param array<string, mixed> $previous Old snapshot.
	 * @param array<string, mixed> $current  New snapshot.
	 */
	private static function compare_mu_plugins( array $previous, array $current ): void {
		$added = array_diff( (array) $current['mu_plugins'], (array) $previous['mu_plugins'] );

		foreach ( $added as $file ) {
			Logger::log(
				'config.muplugin_appeared',
				[
					'object_id'    => (string) $file,
					'object_label' => (string) $file,
					'message'      => sprintf(
						'A new must-use plugin "%s" is present. Must-use plugins load before everything else and cannot be deactivated from the dashboard.',
						(string) $file
					),
					'data'         => [ 'mu_plugin' => (string) $file ],
				]
			);
		}
	}

	/**
	 * @param array<string, mixed> $previous Old snapshot.
	 * @param array<string, mixed> $current  New snapshot.
	 */
	private static function compare_constants( array $previous, array $current ): void {
		$old = (array) ( $previous['constants'] ?? [] );
		$new = (array) ( $current['constants'] ?? [] );

		foreach ( $new as $name => $value ) {
			$before = $old[ $name ] ?? null;

			if ( $before === $value ) {
				continue;
			}

			$type = in_array( $name, [ 'DISALLOW_FILE_EDIT', 'DISALLOW_FILE_MODS' ], true )
				? 'config.file_edit_constant_changed'
				: 'config.autoupdate_constant_changed';

			Logger::log(
				$type,
				[
					'object_id'    => (string) $name,
					'object_label' => (string) $name,
					'message'      => sprintf(
						'The constant %s changed from %s to %s in wp-config.php.',
						(string) $name,
						self::render( $before ),
						self::render( $value )
					),
					'data'         => [
						'constant'  => (string) $name,
						'old_value' => self::render( $before ),
						'new_value' => self::render( $value ),
					],
				]
			);
		}
	}

	/**
	 * @param array<string, mixed> $previous Old snapshot.
	 * @param array<string, mixed> $current  New snapshot.
	 */
	private static function compare_xmlrpc( array $previous, array $current ): void {
		if ( (bool) ( $previous['xmlrpc'] ?? true ) === (bool) ( $current['xmlrpc'] ?? true ) ) {
			return;
		}

		Logger::log(
			'config.xmlrpc_changed',
			[
				'object_id'    => 'xmlrpc',
				'object_label' => 'XML-RPC',
				'message'      => sprintf(
					'XML-RPC is now %s.',
					! empty( $current['xmlrpc'] ) ? 'enabled' : 'disabled'
				),
				'data'         => [ 'enabled' => (bool) $current['xmlrpc'] ],
			]
		);
	}

	/**
	 * @param array<string, mixed> $previous Old snapshot.
	 * @param array<string, mixed> $current  New snapshot.
	 */
	private static function compare_cron( array $previous, array $current ): void {
		$old = (array) ( $previous['cron'] ?? [] );
		$new = (array) ( $current['cron'] ?? [] );

		foreach ( array_diff( $new, $old ) as $entry ) {
			[ $hook, $schedule ] = array_pad( explode( '|', (string) $entry, 2 ), 2, '' );

			Logger::log(
				'config.cron_job_added',
				[
					'object_id'    => $hook,
					'object_label' => $hook,
					'message'      => sprintf(
						'A new scheduled task "%s" (%s) was registered. Scheduled tasks are a common way to make a backdoor survive cleanup.',
						$hook,
						$schedule
					),
					'data'         => [
						'hook'     => $hook,
						'schedule' => $schedule,
					],
				]
			);
		}

		foreach ( array_diff( $old, $new ) as $entry ) {
			[ $hook, $schedule ] = array_pad( explode( '|', (string) $entry, 2 ), 2, '' );

			Logger::log(
				'config.cron_job_removed',
				[
					'object_id'    => $hook,
					'object_label' => $hook,
					'message'      => sprintf( 'The scheduled task "%s" (%s) is no longer registered.', $hook, $schedule ),
					'data'         => [
						'hook'     => $hook,
						'schedule' => $schedule,
					],
				]
			);
		}
	}

	/**
	 * Object identifiers seen for the given event types within a window.
	 *
	 * @param string[] $types  Event types.
	 * @param int      $window Seconds to look back.
	 * @return string[]
	 */
	private static function recent_event_objects( array $types, int $window ): array {
		global $wpdb;

		if ( empty( $types ) ) {
			return [];
		}

		$table        = Installer::table_log();
		$placeholders = implode( ',', array_fill( 0, count( $types ), '%s' ) );
		$values       = array_merge( $types, [ gmdate( 'Y-m-d H:i:s', time() - $window ) ] );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name from $wpdb->prefix; $placeholders is a generated run of %s, one per value, and all values are bound.
		$rows = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT object_id FROM `{$table}` WHERE event_type IN ({$placeholders}) AND event_time >= %s",
				$values
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return is_array( $rows ) ? array_map( 'strval', $rows ) : [];
	}

	/**
	 * @param mixed $value Any snapshot value.
	 */
	private static function render( $value ): string {
		if ( is_bool( $value ) ) {
			return $value ? 'true' : 'false';
		}

		if ( null === $value ) {
			return 'unset';
		}

		return (string) $value;
	}

	public static function establish_baseline(): void {
		self::run( true );
	}
}
