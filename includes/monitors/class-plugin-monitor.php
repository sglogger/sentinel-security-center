<?php
/**
 * Plugin and theme lifecycle monitoring.
 *
 * Two WordPress facts shape this class:
 *
 * 1. `upgrader_process_complete` fires for an install but does NOT carry the
 *    slug of what was installed. The upgrader object knows, so we ask it, and
 *    fall back to diffing against a snapshot taken before the install.
 * 2. By the time `deleted_plugin` / `deleted_theme` fire, the files are gone and
 *    the header can no longer be read. The metadata has to be captured on the
 *    pre-delete hook.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin_Monitor {

	/** @var array<string, array<string, mixed>> Headers captured before deletion. */
	private array $pending_delete = [];

	/** @var array<string, string> Plugin file => version, captured before an upgrade. */
	private array $pre_versions = [];

	/** @var string[] Plugin files present before an install. */
	private array $pre_install_plugins = [];

	public function register(): void {
		add_filter( 'upgrader_pre_install', [ $this, 'snapshot_before' ], 10, 2 );
		add_action( 'upgrader_process_complete', [ $this, 'after_upgrade' ], 10, 2 );

		add_action( 'activated_plugin', [ $this, 'on_activate' ], 10, 1 );
		add_action( 'deactivated_plugin', [ $this, 'on_deactivate' ], 10, 1 );

		add_action( 'delete_plugin', [ $this, 'capture_plugin' ], 10, 1 );
		add_action( 'deleted_plugin', [ $this, 'on_plugin_deleted' ], 10, 2 );

		add_action( 'switch_theme', [ $this, 'on_switch_theme' ], 10, 3 );
		add_action( 'delete_theme', [ $this, 'capture_theme' ], 10, 1 );
		add_action( 'deleted_theme', [ $this, 'on_theme_deleted' ], 10, 2 );

		add_action( 'automatic_updates_complete', [ $this, 'on_auto_update' ], 10, 1 );
	}

	// -------------------------------------------------------------------------
	// Install / update
	// -------------------------------------------------------------------------

	/**
	 * Take a "before" picture so an install can be identified by difference and
	 * an update can report the version it came from.
	 *
	 * @param bool|\WP_Error       $response   Upgrader response, passed through untouched.
	 * @param array<string, mixed> $hook_extra Context for the operation.
	 * @return bool|\WP_Error
	 */
	public function snapshot_before( $response, $hook_extra ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins                   = get_plugins();
		$this->pre_install_plugins = array_keys( $plugins );

		foreach ( $plugins as $file => $data ) {
			$this->pre_versions[ $file ] = (string) ( $data['Version'] ?? '' );
		}

		return $response;
	}

	/**
	 * @param \WP_Upgrader         $upgrader   The upgrader instance.
	 * @param array<string, mixed> $hook_extra What was processed.
	 */
	public function after_upgrade( $upgrader, $hook_extra ): void {
		$type   = (string) ( $hook_extra['type'] ?? '' );
		$action = (string) ( $hook_extra['action'] ?? '' );

		if ( 'plugin' === $type ) {
			'install' === $action
				? $this->plugin_installed( $upgrader )
				: $this->plugins_updated( $hook_extra );
			return;
		}

		if ( 'theme' === $type ) {
			'install' === $action
				? $this->theme_installed( $upgrader )
				: $this->themes_updated( $hook_extra );
		}
	}

	/**
	 * @param \WP_Upgrader $upgrader The upgrader instance.
	 */
	private function plugin_installed( $upgrader ): void {
		$file = '';

		// Undocumented but stable, and the only in-request answer.
		if ( is_object( $upgrader ) && method_exists( $upgrader, 'plugin_info' ) ) {
			$file = (string) $upgrader->plugin_info();
		}

		if ( '' === $file ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$new  = array_diff( array_keys( get_plugins() ), $this->pre_install_plugins );
			$file = (string) ( reset( $new ) ?: '' );
		}

		if ( '' === $file ) {
			return;
		}

		$data = $this->plugin_data( $file );

		Logger::log(
			'plugin.installed',
			[
				'object_id'    => $file,
				'object_label' => $data['Name'] ?: $file,
				'message'      => sprintf(
					'Plugin "%s" version %s was installed. It is not active yet.',
					$data['Name'] ?: $file,
					$data['Version'] ?: '?'
				),
				'data'         => [
					'plugin'  => $file,
					'version' => $data['Version'],
					'author'  => $data['Author'],
				],
			]
		);
	}

	/**
	 * @param array<string, mixed> $hook_extra What was processed.
	 */
	private function plugins_updated( array $hook_extra ): void {
		$files = [];

		if ( ! empty( $hook_extra['plugins'] ) && is_array( $hook_extra['plugins'] ) ) {
			$files = array_map( 'strval', $hook_extra['plugins'] );
		} elseif ( ! empty( $hook_extra['plugin'] ) ) {
			$files = [ (string) $hook_extra['plugin'] ];
		}

		foreach ( $files as $file ) {
			$data = $this->plugin_data( $file );
			$from = $this->pre_versions[ $file ] ?? '';

			Logger::log(
				'plugin.updated',
				[
					'object_id'    => $file,
					'object_label' => $data['Name'] ?: $file,
					'message'      => sprintf(
						'Plugin "%s" was updated%s to version %s.',
						$data['Name'] ?: $file,
						'' !== $from ? ' from version ' . $from : '',
						$data['Version'] ?: '?'
					),
					'data'         => [
						'plugin'      => $file,
						'old_version' => $from,
						'new_version' => $data['Version'],
					],
				]
			);
		}
	}

	/**
	 * @param \WP_Upgrader $upgrader The upgrader instance.
	 */
	private function theme_installed( $upgrader ): void {
		$slug = '';

		if ( is_object( $upgrader ) && method_exists( $upgrader, 'theme_info' ) ) {
			$theme = $upgrader->theme_info();
			if ( $theme instanceof \WP_Theme ) {
				$slug = (string) $theme->get_stylesheet();
			}
		}

		if ( '' === $slug ) {
			return;
		}

		$theme = wp_get_theme( $slug );

		Logger::log(
			'theme.installed',
			[
				'object_id'    => $slug,
				'object_label' => (string) $theme->get( 'Name' ),
				'message'      => sprintf(
					'Theme "%s" version %s was installed. It is not active yet.',
					(string) $theme->get( 'Name' ),
					(string) $theme->get( 'Version' )
				),
				'data'         => [
					'theme'   => $slug,
					'version' => (string) $theme->get( 'Version' ),
				],
			]
		);
	}

	/**
	 * @param array<string, mixed> $hook_extra What was processed.
	 */
	private function themes_updated( array $hook_extra ): void {
		$slugs = [];

		if ( ! empty( $hook_extra['themes'] ) && is_array( $hook_extra['themes'] ) ) {
			$slugs = array_map( 'strval', $hook_extra['themes'] );
		} elseif ( ! empty( $hook_extra['theme'] ) ) {
			$slugs = [ (string) $hook_extra['theme'] ];
		}

		foreach ( $slugs as $slug ) {
			$theme = wp_get_theme( $slug );

			Logger::log(
				'theme.updated',
				[
					'object_id'    => $slug,
					'object_label' => (string) $theme->get( 'Name' ),
					'message'      => sprintf(
						'Theme "%s" was updated to version %s.',
						(string) $theme->get( 'Name' ),
						(string) $theme->get( 'Version' )
					),
					'data'         => [
						'theme'   => $slug,
						'version' => (string) $theme->get( 'Version' ),
					],
				]
			);
		}
	}

	/**
	 * Auto-updates run under cron with nobody logged in; the actor is the
	 * system. That is inherent, not a gap in attribution.
	 *
	 * @param array<string, mixed> $results Update results by type.
	 */
	public function on_auto_update( $results ): void {
		foreach ( (array) ( $results['plugin'] ?? [] ) as $result ) {
			$item = $result->item ?? null;
			$file = is_object( $item ) ? (string) ( $item->plugin ?? '' ) : '';

			if ( '' === $file ) {
				continue;
			}

			$data = $this->plugin_data( $file );

			Logger::log(
				'plugin.auto_updated',
				[
					'object_id'    => $file,
					'object_label' => $data['Name'] ?: $file,
					'message'      => sprintf(
						'Plugin "%s" was automatically updated to version %s.',
						$data['Name'] ?: $file,
						$data['Version'] ?: '?'
					),
					'data'         => [ 'plugin' => $file ],
				]
			);
		}
	}

	// -------------------------------------------------------------------------
	// Activation state
	// -------------------------------------------------------------------------

	public function on_activate( string $plugin ): void {
		$data = $this->plugin_data( $plugin );

		// Activation matters more than installation: inert files on disk do
		// nothing, whereas activation is the moment code starts running.
		Logger::log(
			'plugin.activated',
			[
				'object_id'    => $plugin,
				'object_label' => $data['Name'] ?: $plugin,
				'message'      => sprintf(
					'Plugin "%s" version %s was activated and its code is now running.',
					$data['Name'] ?: $plugin,
					$data['Version'] ?: '?'
				),
				'data'         => [
					'plugin'  => $plugin,
					'version' => $data['Version'],
					'author'  => $data['Author'],
				],
			]
		);
	}

	public function on_deactivate( string $plugin ): void {
		$data = $this->plugin_data( $plugin );

		Logger::log(
			'plugin.deactivated',
			[
				'object_id'    => $plugin,
				'object_label' => $data['Name'] ?: $plugin,
				'message'      => sprintf( 'Plugin "%s" was deactivated.', $data['Name'] ?: $plugin ),
				'data'         => [ 'plugin' => $plugin ],
			]
		);
	}

	// -------------------------------------------------------------------------
	// Deletion — metadata must be captured before the files disappear
	// -------------------------------------------------------------------------

	public function capture_plugin( string $plugin ): void {
		$this->pending_delete[ 'plugin:' . $plugin ] = $this->plugin_data( $plugin );
	}

	/**
	 * @param string $plugin  Plugin file.
	 * @param bool   $deleted Whether deletion actually succeeded.
	 */
	public function on_plugin_deleted( $plugin, $deleted ): void {
		if ( ! $deleted ) {
			return;
		}

		$plugin = (string) $plugin;
		$data   = $this->pending_delete[ 'plugin:' . $plugin ] ?? [
			'Name'    => '',
			'Version' => '',
			'Author'  => '',
		];

		Logger::log(
			'plugin.deleted',
			[
				'object_id'    => $plugin,
				'object_label' => $data['Name'] ?: $plugin,
				'message'      => sprintf(
					'Plugin "%s" version %s was deleted from the server.',
					$data['Name'] ?: $plugin,
					$data['Version'] ?: '?'
				),
				'data'         => [
					'plugin'  => $plugin,
					'version' => $data['Version'],
					'author'  => $data['Author'],
				],
			]
		);

		unset( $this->pending_delete[ 'plugin:' . $plugin ] );
	}

	public function capture_theme( string $stylesheet ): void {
		$theme = wp_get_theme( $stylesheet );

		$this->pending_delete[ 'theme:' . $stylesheet ] = [
			'Name'    => (string) $theme->get( 'Name' ),
			'Version' => (string) $theme->get( 'Version' ),
			'Author'  => (string) $theme->get( 'Author' ),
		];
	}

	/**
	 * @param string $stylesheet Theme slug.
	 * @param bool   $deleted    Whether deletion actually succeeded.
	 */
	public function on_theme_deleted( $stylesheet, $deleted ): void {
		if ( ! $deleted ) {
			return;
		}

		$stylesheet = (string) $stylesheet;
		$data       = $this->pending_delete[ 'theme:' . $stylesheet ] ?? [
			'Name'    => '',
			'Version' => '',
		];

		Logger::log(
			'theme.deleted',
			[
				'object_id'    => $stylesheet,
				'object_label' => $data['Name'] ?: $stylesheet,
				'message'      => sprintf( 'Theme "%s" was deleted from the server.', $data['Name'] ?: $stylesheet ),
				'data'         => [ 'theme' => $stylesheet ],
			]
		);

		unset( $this->pending_delete[ 'theme:' . $stylesheet ] );
	}

	/**
	 * @param string     $new_name  New theme name.
	 * @param \WP_Theme  $new_theme New theme object.
	 * @param \WP_Theme  $old_theme Previous theme object.
	 */
	public function on_switch_theme( $new_name, $new_theme = null, $old_theme = null ): void {
		$old = ( $old_theme instanceof \WP_Theme ) ? (string) $old_theme->get( 'Name' ) : '';

		Logger::log(
			'theme.activated',
			[
				'object_id'    => ( $new_theme instanceof \WP_Theme ) ? (string) $new_theme->get_stylesheet() : '',
				'object_label' => (string) $new_name,
				'message'      => sprintf(
					'The active theme was switched to "%s"%s.',
					(string) $new_name,
					'' !== $old ? ' from "' . $old . '"' : ''
				),
				'data'         => [
					'new_theme' => (string) $new_name,
					'old_theme' => $old,
				],
			]
		);
	}

	// -------------------------------------------------------------------------

	/**
	 * @return array{Name:string, Version:string, Author:string}
	 */
	private function plugin_data( string $file ): array {
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$path = WP_PLUGIN_DIR . '/' . $file;

		if ( ! is_readable( $path ) ) {
			return [
				'Name'    => '',
				'Version' => '',
				'Author'  => '',
			];
		}

		$data = get_plugin_data( $path, false, false );

		return [
			'Name'    => (string) ( $data['Name'] ?? '' ),
			'Version' => (string) ( $data['Version'] ?? '' ),
			'Author'  => wp_strip_all_tags( (string) ( $data['Author'] ?? '' ) ),
		];
	}
}
