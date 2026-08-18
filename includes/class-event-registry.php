<?php
/**
 * The canonical catalogue of everything this plugin can report.
 *
 * One definition per event type drives four things at once: the severity shown
 * in the log, the default alert mode, the labels in the settings matrix, and
 * the filter dropdowns. Adding an event anywhere else in the codebase without
 * registering it here is a bug — Logger will reject it.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Event_Registry {

	// Severity levels. Stored as integers so the log can be sorted and
	// filtered by "at least this bad".
	public const INFO     = 10;
	public const NOTICE   = 20;
	public const WARNING  = 30;
	public const HIGH     = 40;
	public const CRITICAL = 50;

	// Alert modes.
	public const MODE_OFF   = 'off';
	public const MODE_LOG   = 'log';
	public const MODE_EMAIL = 'email';

	/** @var array<string, array{severity:int, mode:string, object:string, group:string}>|null */
	private static ?array $cache = null;

	/**
	 * @return array<string, array{severity:int, mode:string, object:string, group:string}>
	 */
	public static function all(): array {
		if ( null !== self::$cache ) {
			return self::$cache;
		}

		$e = static fn( int $sev, string $mode, string $object, string $group ): array => [
			'severity' => $sev,
			'mode'     => $mode,
			'object'   => $object,
			'group'    => $group,
		];

		$events = [
			// -----------------------------------------------------------------
			// Plugins
			// -----------------------------------------------------------------
			'plugin.installed'                    => $e( self::HIGH, self::MODE_EMAIL, 'plugin', 'plugins' ),
			'plugin.activated'                    => $e( self::HIGH, self::MODE_EMAIL, 'plugin', 'plugins' ),
			'plugin.deactivated'                  => $e( self::WARNING, self::MODE_LOG, 'plugin', 'plugins' ),
			'plugin.updated'                      => $e( self::NOTICE, self::MODE_LOG, 'plugin', 'plugins' ),
			'plugin.deleted'                      => $e( self::HIGH, self::MODE_EMAIL, 'plugin', 'plugins' ),
			'plugin.auto_updated'                 => $e( self::NOTICE, self::MODE_LOG, 'plugin', 'plugins' ),
			'plugin.appeared_out_of_band'         => $e( self::CRITICAL, self::MODE_EMAIL, 'plugin', 'plugins' ),

			// An update waiting is not an incident, so this starts at log
			// only — but it is the single most common way in, so it is worth
			// switching to e-mail on a site nobody watches daily.
			'plugin.update_available'             => $e( self::WARNING, self::MODE_LOG, 'plugin', 'plugins' ),

			// -----------------------------------------------------------------
			// Themes
			// -----------------------------------------------------------------
			'theme.installed'                     => $e( self::HIGH, self::MODE_EMAIL, 'theme', 'themes' ),
			'theme.activated'                     => $e( self::HIGH, self::MODE_EMAIL, 'theme', 'themes' ),
			'theme.updated'                       => $e( self::NOTICE, self::MODE_LOG, 'theme', 'themes' ),
			'theme.deleted'                       => $e( self::WARNING, self::MODE_LOG, 'theme', 'themes' ),

			// -----------------------------------------------------------------
			// Users and administrators
			// -----------------------------------------------------------------
			'user.created'                        => $e( self::HIGH, self::MODE_EMAIL, 'user', 'users' ),
			'user.created_admin'                  => $e( self::CRITICAL, self::MODE_EMAIL, 'user', 'users' ),
			'user.deleted'                        => $e( self::HIGH, self::MODE_EMAIL, 'user', 'users' ),
			'user.deleted_admin'                  => $e( self::CRITICAL, self::MODE_EMAIL, 'user', 'users' ),
			'user.role_changed'                   => $e( self::HIGH, self::MODE_EMAIL, 'user', 'users' ),
			'user.promoted_admin'                 => $e( self::CRITICAL, self::MODE_EMAIL, 'user', 'users' ),
			'user.demoted_admin'                  => $e( self::CRITICAL, self::MODE_EMAIL, 'user', 'users' ),
			'user.email_changed'                  => $e( self::HIGH, self::MODE_EMAIL, 'user', 'users' ),
			'user.email_change_requested'         => $e( self::WARNING, self::MODE_LOG, 'user', 'users' ),
			'user.password_changed'               => $e( self::HIGH, self::MODE_EMAIL, 'user', 'users' ),
			'user.password_reset_requested'       => $e( self::NOTICE, self::MODE_LOG, 'user', 'users' ),
			'user.password_reset_completed'       => $e( self::HIGH, self::MODE_EMAIL, 'user', 'users' ),
			'user.profile_updated'                => $e( self::INFO, self::MODE_OFF, 'user', 'users' ),
			'user.self_admin_modified'            => $e( self::CRITICAL, self::MODE_EMAIL, 'user', 'users' ),
			'user.login_changed'                  => $e( self::CRITICAL, self::MODE_EMAIL, 'user', 'users' ),
			'user.db_created_out_of_band'         => $e( self::CRITICAL, self::MODE_EMAIL, 'user', 'users' ),
			'user.db_deleted_out_of_band'         => $e( self::CRITICAL, self::MODE_EMAIL, 'user', 'users' ),
			'user.db_modified_out_of_band'        => $e( self::CRITICAL, self::MODE_EMAIL, 'user', 'users' ),

			// -----------------------------------------------------------------
			// Application passwords
			// -----------------------------------------------------------------
			'apppass.created'                     => $e( self::HIGH, self::MODE_EMAIL, 'user', 'apppass' ),
			'apppass.revoked'                     => $e( self::WARNING, self::MODE_LOG, 'user', 'apppass' ),
			'apppass.used'                        => $e( self::INFO, self::MODE_OFF, 'user', 'apppass' ),

			// -----------------------------------------------------------------
			// Logins. A failed attempt is recorded but deliberately starts at
			// Info / log only: on any public site the background noise of bots
			// guessing passwords is constant, and mailing it out is how a
			// mailbox gets trained to ignore this plugin.
			// -----------------------------------------------------------------
			'login.failed'                        => $e( self::INFO, self::MODE_LOG, 'login', 'login' ),
			'login.success'                       => $e( self::INFO, self::MODE_LOG, 'login', 'login' ),
			'login.allowed_private_ip'            => $e( self::INFO, self::MODE_LOG, 'login', 'login' ),
			'login.allowed_by_allowlist'          => $e( self::INFO, self::MODE_LOG, 'login', 'login' ),
			'login.allowed_by_bypass'             => $e( self::WARNING, self::MODE_EMAIL, 'login', 'login' ),
			'login.foreign_allowed'               => $e( self::HIGH, self::MODE_EMAIL, 'login', 'login' ),
			'login.would_block_geo'               => $e( self::HIGH, self::MODE_EMAIL, 'login', 'login' ),
			'login.blocked_geo'                   => $e( self::CRITICAL, self::MODE_EMAIL, 'login', 'login' ),
			'login.blocked_denylist'              => $e( self::HIGH, self::MODE_LOG, 'login', 'login' ),
			'login.bypass_issued'                 => $e( self::WARNING, self::MODE_LOG, 'login', 'login' ),
			'login.bypass_redeemed'               => $e( self::HIGH, self::MODE_EMAIL, 'login', 'login' ),
			'login.bypass_rejected'               => $e( self::WARNING, self::MODE_LOG, 'login', 'login' ),
			'login.blocking_kill_switch'          => $e( self::HIGH, self::MODE_EMAIL, 'login', 'login' ),
			'user.logout'                         => $e( self::INFO, self::MODE_OFF, 'login', 'login' ),

			// -----------------------------------------------------------------
			// Two-factor authentication. A failed challenge means someone had
			// the right password, which is why it is not filed as noise.
			// -----------------------------------------------------------------
			'2fa.enabled'                         => $e( self::NOTICE, self::MODE_LOG, 'user', 'twofactor' ),
			'2fa.disabled'                        => $e( self::HIGH, self::MODE_EMAIL, 'user', 'twofactor' ),
			'2fa.reset_by_admin'                  => $e( self::HIGH, self::MODE_EMAIL, 'user', 'twofactor' ),
			'2fa.challenge_issued'                => $e( self::INFO, self::MODE_LOG, 'user', 'twofactor' ),
			'2fa.challenge_passed'                => $e( self::INFO, self::MODE_LOG, 'user', 'twofactor' ),
			'2fa.challenge_failed'                => $e( self::WARNING, self::MODE_LOG, 'user', 'twofactor' ),
			'2fa.api_auth_refused'                => $e( self::WARNING, self::MODE_LOG, 'user', 'twofactor' ),
			'2fa.recovery_code_used'              => $e( self::HIGH, self::MODE_EMAIL, 'user', 'twofactor' ),
			'2fa.recovery_codes_regenerated'      => $e( self::NOTICE, self::MODE_LOG, 'user', 'twofactor' ),
			'2fa.email_code_sent'                 => $e( self::NOTICE, self::MODE_LOG, 'user', 'twofactor' ),
			'2fa.email_code_used'                 => $e( self::HIGH, self::MODE_EMAIL, 'user', 'twofactor' ),
			'2fa.policy_changed'                  => $e( self::HIGH, self::MODE_EMAIL, 'system', 'twofactor' ),

			// -----------------------------------------------------------------
			// Options and configuration
			// -----------------------------------------------------------------
			'option.siteurl_changed'              => $e( self::CRITICAL, self::MODE_EMAIL, 'option', 'config' ),
			'option.home_changed'                 => $e( self::CRITICAL, self::MODE_EMAIL, 'option', 'config' ),
			'option.admin_email_changed'          => $e( self::CRITICAL, self::MODE_EMAIL, 'option', 'config' ),
			'option.admin_email_change_requested' => $e( self::HIGH, self::MODE_EMAIL, 'option', 'config' ),
			'option.users_can_register_changed'   => $e( self::HIGH, self::MODE_EMAIL, 'option', 'config' ),
			'option.default_role_changed'         => $e( self::CRITICAL, self::MODE_EMAIL, 'option', 'config' ),
			'option.blog_public_changed'          => $e( self::WARNING, self::MODE_LOG, 'option', 'config' ),
			'option.active_plugins_direct'        => $e( self::CRITICAL, self::MODE_EMAIL, 'option', 'config' ),
			'config.xmlrpc_changed'               => $e( self::HIGH, self::MODE_EMAIL, 'config', 'config' ),
			'config.file_edit_constant_changed'   => $e( self::HIGH, self::MODE_EMAIL, 'config', 'config' ),
			'config.file_editor_used'             => $e( self::CRITICAL, self::MODE_EMAIL, 'config', 'config' ),
			'config.autoupdate_constant_changed'  => $e( self::WARNING, self::MODE_LOG, 'config', 'config' ),
			'config.cron_job_added'               => $e( self::HIGH, self::MODE_EMAIL, 'cron', 'config' ),
			'config.cron_job_removed'             => $e( self::WARNING, self::MODE_LOG, 'cron', 'config' ),
			'config.muplugin_appeared'            => $e( self::CRITICAL, self::MODE_EMAIL, 'file', 'config' ),
			'config.wpconfig_changed'             => $e( self::CRITICAL, self::MODE_EMAIL, 'file', 'config' ),
			'config.htaccess_changed'             => $e( self::HIGH, self::MODE_EMAIL, 'file', 'config' ),

			// -----------------------------------------------------------------
			// Filesystem and core integrity
			// -----------------------------------------------------------------
			'file.new_in_muplugins'               => $e( self::CRITICAL, self::MODE_EMAIL, 'file', 'files' ),
			'file.changed_in_muplugins'           => $e( self::CRITICAL, self::MODE_EMAIL, 'file', 'files' ),
			'file.php_in_uploads'                 => $e( self::CRITICAL, self::MODE_EMAIL, 'file', 'files' ),
			'file.uploads_htaccess_changed'       => $e( self::HIGH, self::MODE_EMAIL, 'file', 'files' ),
			'file.changed_in_uploads'             => $e( self::CRITICAL, self::MODE_EMAIL, 'file', 'files' ),
			'file.removed'                        => $e( self::NOTICE, self::MODE_LOG, 'file', 'files' ),
			'file.backdoor_signature'             => $e( self::CRITICAL, self::MODE_EMAIL, 'file', 'files' ),
			'core.file_modified'                  => $e( self::CRITICAL, self::MODE_EMAIL, 'core', 'files' ),
			'core.file_missing'                   => $e( self::HIGH, self::MODE_EMAIL, 'core', 'files' ),
			'core.unknown_file'                   => $e( self::CRITICAL, self::MODE_EMAIL, 'core', 'files' ),
			'core.checksums_unavailable'          => $e( self::NOTICE, self::MODE_LOG, 'core', 'files' ),
			'scan.budget_exceeded'                => $e( self::WARNING, self::MODE_LOG, 'system', 'files' ),

			// -----------------------------------------------------------------
			// The plugin talking about itself
			// -----------------------------------------------------------------
			'geoip.db_updated'                    => $e( self::INFO, self::MODE_LOG, 'system', 'system' ),
			'geoip.db_update_failed'              => $e( self::HIGH, self::MODE_EMAIL, 'system', 'system' ),
			'geoip.db_missing'                    => $e( self::CRITICAL, self::MODE_EMAIL, 'system', 'system' ),
			'geoip.blocking_auto_disarmed'        => $e( self::CRITICAL, self::MODE_EMAIL, 'system', 'system' ),
			'alert.mail_failed'                   => $e( self::HIGH, self::MODE_LOG, 'system', 'system' ),
			'alert.flood_suppressed'              => $e( self::WARNING, self::MODE_EMAIL, 'system', 'system' ),
			'security_center.activated'           => $e( self::HIGH, self::MODE_EMAIL, 'system', 'system' ),
			'security_center.deactivated'         => $e( self::HIGH, self::MODE_EMAIL, 'system', 'system' ),
			'log.pruned'                          => $e( self::INFO, self::MODE_OFF, 'system', 'system' ),
		];

		self::$cache = $events;

		return $events;
	}

	public static function exists( string $type ): bool {
		return isset( self::all()[ $type ] );
	}

	/**
	 * @return array{severity:int, mode:string, object:string, group:string}|null
	 */
	public static function get( string $type ): ?array {
		return self::all()[ $type ] ?? null;
	}

	public static function severity_of( string $type ): int {
		return self::all()[ $type ]['severity'] ?? self::INFO;
	}

	public static function object_of( string $type ): string {
		return self::all()[ $type ]['object'] ?? 'system';
	}

	/**
	 * The effective alert mode for an event: the admin's choice if they made
	 * one, otherwise the registry default. New event types introduced by an
	 * update therefore inherit a sensible default rather than falling silent.
	 */
	public static function mode_of( string $type ): string {
		$configured = (array) get_option( Installer::OPTION_EVENTS, [] );

		$mode = $configured[ $type ] ?? ( self::all()[ $type ]['mode'] ?? self::MODE_LOG );

		return in_array( $mode, [ self::MODE_OFF, self::MODE_LOG, self::MODE_EMAIL ], true )
			? $mode
			: self::MODE_LOG;
	}

	/**
	 * Human-readable severity name.
	 */
	public static function severity_label( int $severity ): string {
		switch ( true ) {
			case $severity >= self::CRITICAL:
				return __( 'Critical', 'sentinel-security-center' );
			case $severity >= self::HIGH:
				return __( 'High', 'sentinel-security-center' );
			case $severity >= self::WARNING:
				return __( 'Warning', 'sentinel-security-center' );
			case $severity >= self::NOTICE:
				return __( 'Notice', 'sentinel-security-center' );
			default:
				return __( 'Info', 'sentinel-security-center' );
		}
	}

	/**
	 * Group headings for the settings matrix.
	 *
	 * @return array<string, string>
	 */
	public static function groups(): array {
		return [
			'plugins'   => __( 'Plugins', 'sentinel-security-center' ),
			'themes'    => __( 'Themes', 'sentinel-security-center' ),
			'users'     => __( 'Users & administrators', 'sentinel-security-center' ),
			'apppass'   => __( 'Application passwords', 'sentinel-security-center' ),
			'login'     => __( 'Logins', 'sentinel-security-center' ),
			'twofactor' => __( 'Two-factor authentication', 'sentinel-security-center' ),
			'config'    => __( 'Configuration', 'sentinel-security-center' ),
			'files'     => __( 'Files & integrity', 'sentinel-security-center' ),
			'system'    => __( 'Plugin status', 'sentinel-security-center' ),
		];
	}
}
