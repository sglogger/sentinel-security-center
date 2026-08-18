<?php
/**
 * Reports plugins that have an update waiting.
 *
 * An out-of-date plugin is the most common way a site is taken over: once a
 * release is out, what it fixed is public, and the gap between "an update
 * exists" and "somebody applied it" is the window an attacker works in. The
 * Hardening screen already shows a count; this turns the same fact into a
 * logged event that can be e-mailed, so nobody has to remember to look.
 *
 * Strictly read-only with respect to updating. This reads the update
 * information WordPress has already collected on its own schedule, and does
 * not check for, offer, download, or install anything.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Update_Scanner {

	public function register(): void {
		add_action( Installer::CRON_UPDATE_SCAN, [ __CLASS__, 'run' ] );
	}

	/**
	 * @return int Number of updates reported this run.
	 */
	public static function run(): int {
		$pending = self::pending();
		$seen    = (array) get_option( Installer::OPTION_UPDATES_SEEN, [] );
		$run     = 0;

		foreach ( $pending as $file => $info ) {
			// Report a plugin once per available version. Without this the
			// event would repeat every day for as long as the update is
			// ignored, which is exactly how an alert becomes wallpaper.
			if ( isset( $seen[ $file ] ) && (string) $seen[ $file ] === $info['new_version'] ) {
				continue;
			}

			Logger::log(
				'plugin.update_available',
				[
					'object_id'    => $file,
					'object_label' => $info['name'],
					'message'      => sprintf(
						'Plugin "%s" has an update available: %s is installed, %s is available.',
						$info['name'],
						'' !== $info['version'] ? $info['version'] : '?',
						$info['new_version']
					),
					'data'         => [
						'plugin'      => $file,
						'version'     => $info['version'],
						'new_version' => $info['new_version'],
						'active'      => $info['active'],
					],
				]
			);

			++$run;
		}

		// Keep only what is still outstanding, so a plugin updated and later
		// out of date again is reported afresh rather than staying silent.
		$state = [];

		foreach ( $pending as $file => $info ) {
			$state[ $file ] = $info['new_version'];
		}

		update_option( Installer::OPTION_UPDATES_SEEN, $state, false );

		return $run;
	}

	/**
	 * Plugins with a newer version waiting, as WordPress currently sees it.
	 *
	 * Nothing here asks WordPress to look for updates: core refreshes this
	 * information twice a day by itself, and forcing a check from a background
	 * job would put an api.wordpress.org round trip on the site's critical path
	 * for no benefit.
	 *
	 * @return array<string, array{name:string, version:string, new_version:string, active:bool}>
	 */
	private static function pending(): array {
		$updates = get_site_transient( 'update_plugins' );

		if ( ! is_object( $updates ) || empty( $updates->response ) || ! is_array( $updates->response ) ) {
			return [];
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$installed = get_plugins();
		$pending   = [];

		foreach ( $updates->response as $file => $offer ) {
			$file        = (string) $file;
			$new_version = (string) ( is_object( $offer ) ? ( $offer->new_version ?? '' ) : '' );

			if ( '' === $new_version || ! isset( $installed[ $file ] ) ) {
				continue;
			}

			$version = (string) ( $installed[ $file ]['Version'] ?? '' );

			// The transient can outlive the files it describes — an update
			// applied by hand leaves the old offer in place until the next
			// check. Comparing versions keeps that out of the log.
			if ( '' !== $version && version_compare( $new_version, $version, '<=' ) ) {
				continue;
			}

			$pending[ $file ] = [
				'name'        => (string) ( $installed[ $file ]['Name'] ?? $file ),
				'version'     => $version,
				'new_version' => $new_version,
				'active'      => is_plugin_active( $file ),
			];
		}

		return $pending;
	}
}
