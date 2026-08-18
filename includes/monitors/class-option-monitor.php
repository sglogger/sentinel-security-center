<?php
/**
 * Watches the options an attacker changes to keep or widen a foothold.
 *
 * `updated_option` only fires when the value actually changed, so no diffing
 * guard is needed here.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Option_Monitor {

	/** @var array<int, string> Options handled by a real activation hook this request. */
	private array $plugin_hook_fired = [];

	/**
	 * option name => event type.
	 *
	 * @return array<string, string>
	 */
	private function watchlist(): array {
		return [
			'siteurl'            => 'option.siteurl_changed',
			'home'               => 'option.home_changed',
			'admin_email'        => 'option.admin_email_changed',
			'new_admin_email'    => 'option.admin_email_change_requested',
			'users_can_register' => 'option.users_can_register_changed',
			'default_role'       => 'option.default_role_changed',
			'blog_public'        => 'option.blog_public_changed',
		];
	}

	public function register(): void {
		add_action( 'updated_option', [ $this, 'on_updated' ], 10, 3 );
		add_action( 'added_option', [ $this, 'on_added' ], 10, 2 );

		// Used to tell a legitimate activation from a direct write. These must
		// be the PRE hooks: activated_plugin / deactivated_plugin fire after
		// active_plugins has already been written, which is too late to mark
		// the write as legitimate.
		add_action( 'activate_plugin', [ $this, 'note_plugin_hook' ], 1 );
		add_action( 'deactivate_plugin', [ $this, 'note_plugin_hook' ], 1 );

		add_action( 'wp_create_application_password', [ $this, 'on_apppass_created' ], 10, 4 );
		add_action( 'wp_delete_application_password', [ $this, 'on_apppass_deleted' ], 10, 2 );

		// Core has no "file was saved" action, so the AJAX action is caught at
		// priority 0 — before core writes the file — to record what was touched.
		add_action( 'wp_ajax_edit-theme-plugin-file', [ $this, 'on_file_editor' ], 0 );
	}

	public function note_plugin_hook(): void {
		$this->plugin_hook_fired[] = 'active_plugins';
	}

	/**
	 * @param string $option    Option name.
	 * @param mixed  $old_value Value before.
	 * @param mixed  $value     Value after.
	 */
	public function on_updated( $option, $old_value, $value ): void {
		$option = (string) $option;

		if ( 'active_plugins' === $option ) {
			$this->check_active_plugins( $old_value, $value );
			return;
		}

		$map = $this->watchlist();

		if ( ! isset( $map[ $option ] ) ) {
			return;
		}

		$type = $map[ $option ];

		Logger::log(
			$type,
			[
				'object_id'    => $option,
				'object_label' => $option,
				'message'      => sprintf(
					'The option "%s" changed from "%s" to "%s".',
					$option,
					$this->scalar( $old_value ),
					$this->scalar( $value )
				),
				'data'         => [
					'option'    => $option,
					'old_value' => $this->scalar( $old_value ),
					'new_value' => $this->scalar( $value ),
				],
			]
		);

		// A changed administrator address is exactly the change that would stop
		// the alerts arriving, so the old address is told as well.
		if ( 'admin_email' === $option ) {
			$this->notify_old_admin_email( (string) $this->scalar( $old_value ), (string) $this->scalar( $value ) );
		}
	}

	/**
	 * @param string $option Option name.
	 * @param mixed  $value  Value.
	 */
	public function on_added( $option, $value ): void {
		$map = $this->watchlist();

		if ( ! isset( $map[ (string) $option ] ) ) {
			return;
		}

		$this->on_updated( $option, '', $value );
	}

	/**
	 * The active plugin list being rewritten without an activation hook firing
	 * means something bypassed the plugin API.
	 *
	 * @param mixed $old Previous list.
	 * @param mixed $new New list.
	 */
	private function check_active_plugins( $old, $new ): void {
		// Consume one marker per write. It cannot be cleared from a separate
		// hook: WordPress fires update_option_{$option} BEFORE updated_option,
		// so anything hanging off the former would clear the marker before this
		// check ever sees it. Consuming here also means a bulk action that
		// legitimately activates one plugin cannot vouch for a second, direct
		// write later in the same request.
		if ( ! empty( $this->plugin_hook_fired ) ) {
			array_pop( $this->plugin_hook_fired );
			return;
		}

		$old = (array) $old;
		$new = (array) $new;

		$added   = array_values( array_diff( $new, $old ) );
		$removed = array_values( array_diff( $old, $new ) );

		if ( empty( $added ) && empty( $removed ) ) {
			return;
		}

		Logger::log(
			'option.active_plugins_direct',
			[
				'object_id'    => 'active_plugins',
				'object_label' => 'active_plugins',
				'message'      => 'The list of active plugins was written directly, without a plugin activation or deactivation taking place.',
				'data'         => [
					'added'   => $added,
					'removed' => $removed,
				],
			]
		);
	}

	private function notify_old_admin_email( string $old, string $new ): void {
		if ( '' === $old || ! is_email( $old ) ) {
			return;
		}

		$settings = (array) get_option( Installer::OPTION_SETTINGS, [] );

		// Only worth a separate message if the old address is not already on
		// the alert list.
		if ( in_array( $old, Alerts::recipients( $settings ), true ) ) {
			return;
		}

		Mailer::send_event(
			[ $old ],
			'option.admin_email_changed',
			[
				'event_type' => 'option.admin_email_changed',
				'severity'   => Event_Registry::CRITICAL,
				'event_time' => gmdate( 'Y-m-d H:i:s' ),
				'message'    => sprintf(
					'The administrator e-mail address for this site was changed from %s to %s. You are receiving this at the previous address because such a change can be used to take over account recovery.',
					$old,
					$new
				),
				'data'       => wp_json_encode(
					[
						'old_email' => $old,
						'new_email' => $new,
					]
				),
			]
		);
	}

	// -------------------------------------------------------------------------
	// Application passwords
	// -------------------------------------------------------------------------

	/**
	 * @param int                  $user_id      Owner.
	 * @param array<string, mixed> $new_item     The created item.
	 * @param string               $new_password The password. Never logged.
	 * @param array<string, mixed> $args         Creation args.
	 */
	public function on_apppass_created( $user_id, $new_item, $new_password = '', $args = [] ): void {
		$user  = get_userdata( (int) $user_id );
		$login = $user ? (string) $user->user_login : (string) $user_id;
		$name  = (string) ( $new_item['name'] ?? '' );

		Logger::log(
			'apppass.created',
			[
				'object_id'    => (string) ( $new_item['uuid'] ?? '' ),
				'object_label' => $name,
				'target_user'  => (int) $user_id,
				'message'      => sprintf(
					'An application password named "%s" was created for "%s". It grants API access without the account password.',
					$name,
					$login
				),
				'data'         => [ 'name' => $name ],
			]
		);
	}

	/**
	 * @param int                  $user_id Owner.
	 * @param array<string, mixed> $item    The removed item.
	 */
	public function on_apppass_deleted( $user_id, $item ): void {
		$user  = get_userdata( (int) $user_id );
		$login = $user ? (string) $user->user_login : (string) $user_id;

		Logger::log(
			'apppass.revoked',
			[
				'object_id'    => (string) ( $item['uuid'] ?? '' ),
				'object_label' => (string) ( $item['name'] ?? '' ),
				'target_user'  => (int) $user_id,
				'message'      => sprintf(
					'The application password "%s" for "%s" was revoked.',
					(string) ( $item['name'] ?? '' ),
					$login
				),
				'data'         => [ 'name' => (string) ( $item['name'] ?? '' ) ],
			]
		);
	}

	// -------------------------------------------------------------------------

	/**
	 * Editing plugin or theme code from the dashboard is how a compromised
	 * administrator session becomes a persistent backdoor.
	 */
	public function on_file_editor(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- core verifies the nonce; this handler only observes and does not act on the request.
		$file   = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['file'] ) ) : '';
		$plugin = isset( $_POST['plugin'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['plugin'] ) ) : '';
		$theme  = isset( $_POST['theme'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['theme'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( '' === $file ) {
			return;
		}

		Logger::log(
			'config.file_editor_used',
			[
				'object_id'    => $file,
				'object_label' => $file,
				'message'      => sprintf(
					'The file "%s" was edited through the built-in code editor.',
					$file
				),
				'data'         => [
					'file'   => $file,
					'plugin' => $plugin,
					'theme'  => $theme,
				],
			]
		);
	}

	/**
	 * Render a value as a short readable string for the log.
	 *
	 * @param mixed $value Any option value.
	 */
	private function scalar( $value ): string {
		if ( is_bool( $value ) ) {
			return $value ? 'true' : 'false';
		}

		if ( is_scalar( $value ) || null === $value ) {
			return mb_substr( (string) $value, 0, 300 );
		}

		return mb_substr( (string) wp_json_encode( $value ), 0, 300 );
	}
}
