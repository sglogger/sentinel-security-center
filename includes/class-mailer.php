<?php
/**
 * Renders and sends alert e-mails.
 *
 * Plain text, deliberately. An alert has to be readable on a phone lock screen
 * at 3am, must survive every mail client, and must not look like the HTML
 * marketing mail people have trained themselves to ignore.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Mailer {

	/**
	 * @param string[]             $recipients Validated addresses.
	 * @param string               $type       Event type.
	 * @param array<string, mixed> $row        The stored log row.
	 */
	public static function send_event( array $recipients, string $type, array $row ): bool {
		if ( empty( $recipients ) ) {
			return false;
		}

		$subject = self::subject( $type, $row );
		$body    = self::body( $type, $row );
		$headers = self::headers();

		$sent = wp_mail( $recipients, $subject, $body, $headers );

		return (bool) $sent;
	}

	private static function subject( string $type, array $row ): string {
		$severity = (int) ( $row['severity'] ?? Event_Registry::severity_of( $type ) );
		$site     = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );

		// The severity and the site name go first so the alert is triageable
		// from a notification preview alone, without opening it.
		return sprintf(
			'[%s] %s — %s',
			Event_Registry::severity_label( $severity ),
			$site,
			self::describe( $type, $row )
		);
	}

	private static function body( string $type, array $row ): string {
		$lines   = [];
		$lines[] = self::describe( $type, $row );
		$lines[] = '';

		$message = trim( (string) ( $row['message'] ?? '' ) );
		if ( '' !== $message ) {
			$lines[] = $message;
			$lines[] = '';
		}

		$lines[] = str_repeat( '-', 60 );

		$facts = [
			__( 'Site', 'wp-security-center' )       => home_url(),
			__( 'Event', 'wp-security-center' )      => $type,
			__( 'Severity', 'wp-security-center' )   => Event_Registry::severity_label(
				(int) ( $row['severity'] ?? 0 )
			),
			__( 'Time (UTC)', 'wp-security-center' ) => (string) ( $row['event_time'] ?? gmdate( 'Y-m-d H:i:s' ) ),
		];

		$actor = trim( (string) ( $row['actor_login'] ?? '' ) );
		if ( '' !== $actor ) {
			$roles = trim( (string) ( $row['actor_roles'] ?? '' ) );
			$facts[ __( 'Performed by', 'wp-security-center' ) ] = '' !== $roles
				? $actor . ' (' . $roles . ')'
				: $actor;
		}

		$target = trim( (string) ( $row['target_login'] ?? '' ) );
		if ( '' !== $target ) {
			$facts[ __( 'Affected user', 'wp-security-center' ) ] = $target;
		}

		$object = trim( (string) ( $row['object_label'] ?? '' ) );
		if ( '' === $object ) {
			$object = trim( (string) ( $row['object_id'] ?? '' ) );
		}
		if ( '' !== $object ) {
			$facts[ __( 'Object', 'wp-security-center' ) ] = $object;
		}

		$ip = trim( (string) ( $row['ip_text'] ?? '' ) );
		if ( '' !== $ip ) {
			$country = trim( (string) ( $row['country'] ?? '' ) );
			$facts[ __( 'IP address', 'wp-security-center' ) ] = '' !== $country
				? $ip . ' (' . $country . ')'
				: $ip;
		}

		$context = trim( (string) ( $row['context'] ?? '' ) );
		if ( '' !== $context ) {
			$facts[ __( 'Request context', 'wp-security-center' ) ] = $context;
		}

		foreach ( $facts as $label => $value ) {
			$lines[] = sprintf( '%-18s %s', $label . ':', $value );
		}

		$data = $row['data'] ?? '';
		if ( is_string( $data ) && '' !== $data && '[]' !== $data ) {
			$decoded = json_decode( $data, true );
			if ( is_array( $decoded ) && ! empty( $decoded ) ) {
				$lines[] = '';
				$lines[] = __( 'Details', 'wp-security-center' ) . ':';
				foreach ( self::flatten( $decoded ) as $key => $value ) {
					$lines[] = sprintf( '  %s: %s', $key, $value );
				}
			}
		}

		$lines[] = str_repeat( '-', 60 );
		$lines[] = '';
		$lines[] = __( 'Full log:', 'wp-security-center' ) . ' ' . admin_url( 'admin.php?page=' . Admin::MENU_LOG );
		$lines[] = __( 'Alert settings:', 'wp-security-center' ) . ' ' . admin_url( 'admin.php?page=' . Admin::MENU_SETTINGS );
		$lines[] = '';
		$lines[] = __( 'Sent by WP Security Center. If this alert is noise, the event type can be switched to log-only on the settings screen.', 'wp-security-center' );

		return implode( "\n", $lines );
	}

	/**
	 * Flatten nested detail data into readable single lines.
	 *
	 * @param array<string, mixed> $data   Detail payload.
	 * @param string               $prefix Key prefix during recursion.
	 * @return array<string, string>
	 */
	private static function flatten( array $data, string $prefix = '' ): array {
		$out = [];

		foreach ( $data as $key => $value ) {
			$label = '' === $prefix ? (string) $key : $prefix . '.' . $key;

			if ( is_array( $value ) ) {
				if ( empty( $value ) ) {
					continue;
				}
				// A flat list reads better inline than as numbered lines.
				if ( array_is_list( $value ) && ! is_array( reset( $value ) ) ) {
					$out[ $label ] = implode( ', ', array_map( 'strval', $value ) );
					continue;
				}
				$out += self::flatten( $value, $label );
				continue;
			}

			if ( is_bool( $value ) ) {
				$out[ $label ] = $value ? 'yes' : 'no';
				continue;
			}

			$out[ $label ] = mb_substr( (string) $value, 0, 300 );
		}

		return $out;
	}

	/**
	 * A one-line human description of the event.
	 *
	 * @param array<string, mixed> $row The stored log row.
	 */
	public static function describe( string $type, array $row ): string {
		$object = trim( (string) ( $row['object_label'] ?? '' ) );
		if ( '' === $object ) {
			$object = trim( (string) ( $row['object_id'] ?? '' ) );
		}

		$target = trim( (string) ( $row['target_login'] ?? '' ) );
		$actor  = trim( (string) ( $row['actor_login'] ?? '' ) );
		$name   = '' !== $target ? $target : $object;

		$map = self::descriptions();

		if ( isset( $map[ $type ] ) ) {
			return trim( sprintf( $map[ $type ], $name, $actor ) );
		}

		return '' !== $name ? $type . ': ' . $name : $type;
	}

	/**
	 * Templates keyed by event type. %1$s is the object or affected user,
	 * %2$s the acting user.
	 *
	 * @return array<string, string>
	 */
	private static function descriptions(): array {
		return [
			'plugin.installed'                    => __( 'Plugin installed: %1$s', 'wp-security-center' ),
			'plugin.activated'                    => __( 'Plugin activated: %1$s', 'wp-security-center' ),
			'plugin.deactivated'                  => __( 'Plugin deactivated: %1$s', 'wp-security-center' ),
			'plugin.updated'                      => __( 'Plugin updated: %1$s', 'wp-security-center' ),
			'plugin.deleted'                      => __( 'Plugin deleted: %1$s', 'wp-security-center' ),
			'plugin.auto_updated'                 => __( 'Plugin auto-updated: %1$s', 'wp-security-center' ),
			'plugin.appeared_out_of_band'         => __( 'Plugin appeared without an install: %1$s', 'wp-security-center' ),
			'theme.installed'                     => __( 'Theme installed: %1$s', 'wp-security-center' ),
			'theme.activated'                     => __( 'Theme activated: %1$s', 'wp-security-center' ),
			'theme.updated'                       => __( 'Theme updated: %1$s', 'wp-security-center' ),
			'theme.deleted'                       => __( 'Theme deleted: %1$s', 'wp-security-center' ),
			'user.created'                        => __( 'New user created: %1$s', 'wp-security-center' ),
			'user.created_admin'                  => __( 'New ADMINISTRATOR created: %1$s', 'wp-security-center' ),
			'user.deleted'                        => __( 'User deleted: %1$s', 'wp-security-center' ),
			'user.deleted_admin'                  => __( 'ADMINISTRATOR deleted: %1$s', 'wp-security-center' ),
			'user.role_changed'                   => __( 'Role changed for %1$s', 'wp-security-center' ),
			'user.promoted_admin'                 => __( '%1$s was promoted to ADMINISTRATOR', 'wp-security-center' ),
			'user.demoted_admin'                  => __( '%1$s was demoted from administrator', 'wp-security-center' ),
			'user.email_changed'                  => __( 'E-mail address changed for %1$s', 'wp-security-center' ),
			'user.email_change_requested'         => __( 'E-mail change requested for %1$s', 'wp-security-center' ),
			'user.password_changed'               => __( 'Password changed for %1$s', 'wp-security-center' ),
			'user.password_reset_requested'       => __( 'Password reset requested for %1$s', 'wp-security-center' ),
			'user.password_reset_completed'       => __( 'Password reset completed for %1$s', 'wp-security-center' ),
			'user.self_admin_modified'            => __( 'Administrator %1$s modified their own account', 'wp-security-center' ),
			'user.login_changed'                  => __( 'Login name changed: %1$s', 'wp-security-center' ),
			'user.db_created_out_of_band'         => __( 'User created directly in the database: %1$s', 'wp-security-center' ),
			'user.db_deleted_out_of_band'         => __( 'User deleted directly in the database: %1$s', 'wp-security-center' ),
			'user.db_modified_out_of_band'        => __( 'User modified directly in the database: %1$s', 'wp-security-center' ),
			'apppass.created'                     => __( 'Application password created for %1$s', 'wp-security-center' ),
			'apppass.revoked'                     => __( 'Application password revoked for %1$s', 'wp-security-center' ),
			'login.foreign_allowed'               => __( 'Login from a country that is not on the allow list: %1$s', 'wp-security-center' ),
			'login.would_block_geo'               => __( 'Login WOULD have been blocked (monitor mode): %1$s', 'wp-security-center' ),
			'login.blocked_geo'                   => __( 'Login BLOCKED from a disallowed country: %1$s', 'wp-security-center' ),
			'login.allowed_by_bypass'             => __( 'Login allowed by a bypass grant: %1$s', 'wp-security-center' ),
			'login.bypass_redeemed'               => __( 'Bypass link redeemed by %1$s', 'wp-security-center' ),
			'login.blocking_kill_switch'          => __( 'Login would have been blocked but the kill switch is active: %1$s', 'wp-security-center' ),
			'option.siteurl_changed'              => __( 'The site URL was changed', 'wp-security-center' ),
			'option.home_changed'                 => __( 'The home URL was changed', 'wp-security-center' ),
			'option.admin_email_changed'          => __( 'The site administrator e-mail address was changed', 'wp-security-center' ),
			'option.admin_email_change_requested' => __( 'A change of the administrator e-mail address was requested', 'wp-security-center' ),
			'option.users_can_register_changed'   => __( 'Open user registration was changed', 'wp-security-center' ),
			'option.default_role_changed'         => __( 'The default role for new users was changed', 'wp-security-center' ),
			'option.blog_public_changed'          => __( 'Search engine visibility was changed', 'wp-security-center' ),
			'option.auto_update_changed'          => __( 'Automatic update settings were changed', 'wp-security-center' ),
			'option.active_plugins_direct'        => __( 'The active plugin list was written directly', 'wp-security-center' ),
			'config.xmlrpc_changed'               => __( 'XML-RPC availability changed', 'wp-security-center' ),
			'config.file_edit_constant_changed'   => __( 'The file-editing configuration changed', 'wp-security-center' ),
			'config.file_editor_used'             => __( 'A file was edited through the built-in editor: %1$s', 'wp-security-center' ),
			'config.autoupdate_constant_changed'  => __( 'An automatic-update constant changed', 'wp-security-center' ),
			'config.cron_job_added'               => __( 'New scheduled task: %1$s', 'wp-security-center' ),
			'config.cron_job_removed'             => __( 'Scheduled task removed: %1$s', 'wp-security-center' ),
			'config.muplugin_appeared'            => __( 'New must-use plugin appeared: %1$s', 'wp-security-center' ),
			'config.wpconfig_changed'             => __( 'wp-config.php was modified', 'wp-security-center' ),
			'config.htaccess_changed'             => __( '.htaccess was modified', 'wp-security-center' ),
			'file.new_in_muplugins'               => __( 'New file in mu-plugins: %1$s', 'wp-security-center' ),
			'file.changed_in_muplugins'           => __( 'Changed file in mu-plugins: %1$s', 'wp-security-center' ),
			'file.php_in_uploads'                 => __( 'PHP file found in the uploads directory: %1$s', 'wp-security-center' ),
			'file.uploads_htaccess_changed'       => __( '.htaccess in the uploads directory changed: %1$s', 'wp-security-center' ),
			'file.changed_in_uploads'             => __( 'Known PHP file in uploads changed: %1$s', 'wp-security-center' ),
			'file.backdoor_signature'             => __( 'Possible backdoor signature: %1$s', 'wp-security-center' ),
			'core.file_modified'                  => __( 'Modified WordPress core file: %1$s', 'wp-security-center' ),
			'core.file_missing'                   => __( 'Missing WordPress core file: %1$s', 'wp-security-center' ),
			'core.unknown_file'                   => __( 'Unrecognised file in a core directory: %1$s', 'wp-security-center' ),
			'geoip.db_update_failed'              => __( 'The GeoIP database could not be updated', 'wp-security-center' ),
			'geoip.db_missing'                    => __( 'The GeoIP database is missing', 'wp-security-center' ),
			'geoip.blocking_auto_disarmed'        => __( 'Login blocking was automatically disarmed', 'wp-security-center' ),
			'alert.flood_suppressed'              => __( 'Alert e-mails are being throttled', 'wp-security-center' ),
			'security_center.activated'           => __( 'WP Security Center was activated', 'wp-security-center' ),
			'security_center.deactivated'         => __( 'WP Security Center was deactivated', 'wp-security-center' ),
		];
	}

	/**
	 * @return string[]
	 */
	private static function headers(): array {
		$settings = (array) get_option( Installer::OPTION_SETTINGS, [] );

		$from_email = sanitize_email( (string) ( $settings['from_email'] ?? '' ) );
		$from_name  = trim( (string) ( $settings['from_name'] ?? '' ) );

		if ( '' === $from_email || ! is_email( $from_email ) ) {
			return [ 'Content-Type: text/plain; charset=UTF-8' ];
		}

		if ( '' === $from_name ) {
			$from_name = (string) get_bloginfo( 'name' );
		}

		return [
			'Content-Type: text/plain; charset=UTF-8',
			sprintf( 'From: %s <%s>', $from_name, $from_email ),
		];
	}
}
