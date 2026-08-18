<?php
/**
 * A read-only report on how hard this installation is to attack.
 *
 * The rest of the plugin answers "what changed?". This answers "what is the
 * posture right now, and what would improve it" — the checklist an
 * administrator would otherwise run from memory. Nothing here writes, and
 * nothing here changes behaviour: it reads the installation and grades it.
 *
 * The recommendations follow the official WordPress hardening guide, and each
 * check links to the section it comes from so the advice can be checked
 * against the source rather than taken on trust:
 * https://developer.wordpress.org/advanced-administration/security/hardening/
 *
 * Where this plugin's own opinion differs from the guide — DISALLOW_FILE_MODS
 * being the clearest case — the difference is stated in the check itself
 * rather than hidden behind a pass/fail badge.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Hardening {

	/** The official guide these recommendations are drawn from. */
	public const DOC = 'https://developer.wordpress.org/advanced-administration/security/hardening/';

	// Verdicts. INFO is not a failure: it marks a decision that depends on how
	// the site is run, where a badge would be dishonest.
	public const OK   = 'ok';
	public const WARN = 'warn';
	public const FAIL = 'fail';
	public const INFO = 'info';

	/**
	 * The placeholder wp-config-sample.php ships with.
	 */
	private const SALT_PLACEHOLDER = 'put your unique phrase here';

	/**
	 * @return array<string, string>
	 */
	public static function groups(): array {
		return [
			'code'       => __( 'Code execution', 'wp-security-center' ),
			'config'     => __( 'wp-config.php, secrets and files', 'wp-security-center' ),
			'updates'    => __( 'Staying current', 'wp-security-center' ),
			'access'     => __( 'Accounts and access', 'wp-security-center' ),
			'monitoring' => __( 'Monitoring and recovery', 'wp-security-center' ),
		];
	}

	public static function doc_url( string $anchor = '' ): string {
		return '' === $anchor ? self::DOC : self::DOC . '#' . $anchor;
	}

	/**
	 * Every check, in display order.
	 *
	 * @return array<int, array{id:string, group:string, label:string, status:string, value:string, advice:string, doc:string}>
	 */
	public static function checks(): array {
		return array_merge(
			self::code_checks(),
			self::config_checks(),
			self::update_checks(),
			self::access_checks(),
			self::monitoring_checks()
		);
	}

	/**
	 * @return array{ok:int, warn:int, fail:int, info:int, total:int}
	 */
	public static function summary(): array {
		$counts = [
			'ok'    => 0,
			'warn'  => 0,
			'fail'  => 0,
			'info'  => 0,
			'total' => 0,
		];

		foreach ( self::checks() as $check ) {
			++$counts['total'];
			++$counts[ $check['status'] ];
		}

		return $counts;
	}

	// -------------------------------------------------------------------------
	// Code execution
	// -------------------------------------------------------------------------

	/**
	 * @return array<int, array<string, string>>
	 */
	private static function code_checks(): array {
		$checks = [];

		$edit_off = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;

		$checks[] = self::check(
			'disallow_file_edit',
			'code',
			__( 'Dashboard file editor', 'wp-security-center' ),
			$edit_off ? self::OK : self::FAIL,
			$edit_off
				? __( 'DISALLOW_FILE_EDIT is set. The theme and plugin editors are gone.', 'wp-security-center' )
				: __( 'DISALLOW_FILE_EDIT is not set, so any administrator can edit PHP from the dashboard.', 'wp-security-center' ),
			$edit_off
				? ''
				: __( "Add define( 'DISALLOW_FILE_EDIT', true ); to wp-config.php. This is the single cheapest hardening step there is: the editor turns a stolen administrator password into arbitrary code execution, and it is the first tool an attacker reaches for. Almost nobody edits theme files from the dashboard on purpose.", 'wp-security-center' ),
			'disable-file-editing'
		);

		$mods_off = defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS;

		$checks[] = self::check(
			'disallow_file_mods',
			'code',
			__( 'Installing and updating from the dashboard', 'wp-security-center' ),
			$mods_off ? self::OK : self::INFO,
			$mods_off
				? __( 'DISALLOW_FILE_MODS is set. Nothing can be installed, updated or deleted through the dashboard.', 'wp-security-center' )
				: __( 'DISALLOW_FILE_MODS is not set. An administrator session can install and update plugins and themes.', 'wp-security-center' ),
			$mods_off
				? __( 'Check that updates really are arriving another way. This constant also blocks every security update, so a site with it set and no deployment pipeline behind it gets steadily less safe, not more. It implies DISALLOW_FILE_EDIT.', 'wp-security-center' )
				: __( "Worth setting — define( 'DISALLOW_FILE_MODS', true ); — but only if code reaches this site by another route: WP-CLI, Composer, or a deployment pipeline. It closes the \"install a plugin that is really a shell\" path entirely, and it disables the update screens along with it. On a site that updates itself from the dashboard, leaving it unset and watching the log is the better trade.", 'wp-security-center' ),
			'disable-file-editing'
		);

		$writable = self::world_writable_paths();

		$checks[] = self::check(
			'file_permissions',
			'code',
			__( 'File permissions', 'wp-security-center' ),
			empty( $writable ) ? self::OK : self::FAIL,
			empty( $writable )
				? __( 'No core directory is writable by everyone.', 'wp-security-center' )
				: sprintf(
					/* translators: %s: comma-separated list of paths */
					__( 'World-writable: %s', 'wp-security-center' ),
					implode( ', ', $writable )
				),
			empty( $writable )
				? ''
				: __( 'Anything mode 0777 or 0666 can be rewritten by any process on the server, which on shared hosting means any other customer. The guide recommends 0755 for directories and 0644 for files, with write access granted only where WordPress genuinely needs it.', 'wp-security-center' ),
			'file-permissions'
		);

		return $checks;
	}

	// -------------------------------------------------------------------------
	// wp-config.php, secrets and files
	// -------------------------------------------------------------------------

	/**
	 * @return array<int, array<string, string>>
	 */
	private static function config_checks(): array {
		$checks = [];

		$in_root  = file_exists( ABSPATH . 'wp-config.php' );
		$above    = ! $in_root && file_exists( dirname( ABSPATH ) . '/wp-config.php' );
		$location = $above ? self::OK : self::INFO;

		$checks[] = self::check(
			'wpconfig_location',
			'config',
			__( 'Where wp-config.php lives', 'wp-security-center' ),
			$location,
			$above
				? __( 'One directory above the WordPress install, outside the document root.', 'wp-security-center' )
				: __( 'In the WordPress root directory.', 'wp-security-center' ),
			$above
				? ''
				: __( 'It can be moved one level up, out of the web root. The guide notes that opinions differ on how much this actually buys you, and that a careless move can make things worse — so treat it as optional. Denying direct access to the file in the server config achieves most of the same thing with less risk.', 'wp-security-center' ),
			'securing-wp-config-php'
		);

		$path  = $in_root ? ABSPATH . 'wp-config.php' : dirname( ABSPATH ) . '/wp-config.php';
		$perms = file_exists( $path ) ? ( fileperms( $path ) & 0777 ) : 0;
		$loose = 0 !== ( $perms & 0044 );

		$checks[] = self::check(
			'wpconfig_permissions',
			'config',
			__( 'wp-config.php permissions', 'wp-security-center' ),
			$loose ? self::WARN : self::OK,
			sprintf(
				/* translators: %s: octal file mode, e.g. 0644 */
				__( 'Mode %s', 'wp-security-center' ),
				'0' . decoct( $perms )
			),
			$loose
				? __( 'The file holds the database credentials and every authentication salt, and it is readable by other accounts on this server. The guide suggests 0400 or 0440 — readable by you, and by the web server only if your setup needs it.', 'wp-security-center' )
				: '',
			'securing-wp-config-php'
		);

		$salts = self::salt_problems();

		$checks[] = self::check(
			'salts',
			'config',
			__( 'Authentication keys and salts', 'wp-security-center' ),
			empty( $salts ) ? self::OK : self::FAIL,
			empty( $salts )
				? __( 'All eight keys and salts are defined, unique and long.', 'wp-security-center' )
				: implode( ' ', $salts ),
			empty( $salts )
				? ''
				: __( 'Generate a fresh set at https://api.wordpress.org/secret-key/1.1/salt/ and paste them into wp-config.php. Weak or shared salts mean session cookies can be forged without ever knowing a password. Everyone, including you, is signed out when they change — and on this site the two-factor secrets stop decrypting, so users fall back to their recovery codes.', 'wp-security-center' ),
			'securing-wp-config-php'
		);

		$debug_leak = defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY;

		$checks[] = self::check(
			'debug_display',
			'config',
			__( 'Error output', 'wp-security-center' ),
			$debug_leak ? self::FAIL : self::OK,
			$debug_leak
				? __( 'WP_DEBUG and WP_DEBUG_DISPLAY are both on: PHP errors are being printed to visitors.', 'wp-security-center' )
				: __( 'Errors are not printed to the page.', 'wp-security-center' ),
			$debug_leak
				? __( "Set define( 'WP_DEBUG_DISPLAY', false ); and log to a file instead. Error output hands out absolute paths, database structure and sometimes credentials, and it is indexed by search engines like any other text.", 'wp-security-center' )
				: '',
			'logging'
		);

		global $wpdb;
		$default_prefix = 'wp_' === $wpdb->prefix;

		$checks[] = self::check(
			'table_prefix',
			'config',
			__( 'Database table prefix', 'wp-security-center' ),
			self::INFO,
			sprintf(
				/* translators: %s: database table prefix */
				__( 'Tables are prefixed %s', 'wp-security-center' ),
				$wpdb->prefix
			),
			$default_prefix
				? __( 'Changing it is often recommended and rarely worth it. The guide files this under security through obscurity: it does not stop an attacker who can already run SQL, and the migration itself can break a working site. Left as it is, it costs you nothing.', 'wp-security-center' )
				: __( 'Non-default. This is obscurity rather than security, so it changes little either way — but it costs nothing now that it is done.', 'wp-security-center' ),
			'security-through-obscurity'
		);

		return $checks;
	}

	// -------------------------------------------------------------------------
	// Staying current
	// -------------------------------------------------------------------------

	/**
	 * @return array<int, array<string, string>>
	 */
	private static function update_checks(): array {
		$checks = [];

		$core    = get_site_transient( 'update_core' );
		$pending = '';

		if ( is_object( $core ) && ! empty( $core->updates ) ) {
			foreach ( (array) $core->updates as $update ) {
				if ( isset( $update->response ) && 'upgrade' === $update->response ) {
					$pending = (string) ( $update->current ?? '' );
					break;
				}
			}
		}

		$checks[] = self::check(
			'core_current',
			'updates',
			__( 'WordPress version', 'wp-security-center' ),
			'' === $pending ? self::OK : self::FAIL,
			'' === $pending
				? sprintf(
					/* translators: %s: WordPress version */
					__( 'Running %s, which is current.', 'wp-security-center' ),
					(string) get_bloginfo( 'version' )
				)
				: sprintf(
					/* translators: 1: installed version, 2: available version */
					__( 'Running %1$s; %2$s is available.', 'wp-security-center' ),
					(string) get_bloginfo( 'version' ),
					$pending
				),
			'' === $pending
				? ''
				: __( 'Update now. Once a release is out, the information needed to exploit what it fixed is effectively public — which is exactly what makes an old version worth attacking.', 'wp-security-center' ),
			'updating-wordpress'
		);

		$auto_disabled = defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED;
		$core_policy   = defined( 'WP_AUTO_UPDATE_CORE' ) ? WP_AUTO_UPDATE_CORE : 'minor';
		$minor_on      = ! $auto_disabled && false !== $core_policy;

		$checks[] = self::check(
			'auto_updates',
			'updates',
			__( 'Automatic core updates', 'wp-security-center' ),
			$minor_on ? self::OK : self::WARN,
			$auto_disabled
				? __( 'AUTOMATIC_UPDATER_DISABLED is set: nothing updates itself.', 'wp-security-center' )
				: sprintf(
					/* translators: %s: the configured value of WP_AUTO_UPDATE_CORE */
					__( 'WP_AUTO_UPDATE_CORE is %s.', 'wp-security-center' ),
					self::readable( $core_policy )
				),
			$minor_on
				? ''
				: __( 'Minor releases are almost entirely security and bug fixes, and WordPress has shipped them automatically since 3.7. Unless something downstream depends on a pinned version, let them through — a site that waits for someone to notice a release is a site that stays vulnerable for as long as nobody looks.', 'wp-security-center' ),
			'regarding-automatic-updates'
		);

		$plugin_updates = self::count_transient_updates( 'update_plugins' );
		$theme_updates  = self::count_transient_updates( 'update_themes' );
		$outdated       = $plugin_updates + $theme_updates;

		$checks[] = self::check(
			'extension_updates',
			'updates',
			__( 'Plugin and theme updates', 'wp-security-center' ),
			0 === $outdated ? self::OK : self::WARN,
			0 === $outdated
				? __( 'Everything is up to date.', 'wp-security-center' )
				: sprintf(
					/* translators: 1: number of plugins, 2: number of themes */
					__( '%1$d plugin and %2$d theme updates waiting.', 'wp-security-center' ),
					$plugin_updates,
					$theme_updates
				),
			0 === $outdated
				? ''
				: __( 'Outdated extensions are the most common way a WordPress site is taken over — far more common than a flaw in core. Every update this plugin sees is written to the event log, so you can tell an update you made from one you did not.', 'wp-security-center' ),
			'plugins'
		);

		$unused = self::unused_extensions();

		$checks[] = self::check(
			'unused_extensions',
			'updates',
			__( 'Unused plugins and themes', 'wp-security-center' ),
			0 === $unused['total'] ? self::OK : self::WARN,
			0 === $unused['total']
				? __( 'Nothing installed that is not in use.', 'wp-security-center' )
				: sprintf(
					/* translators: 1: number of inactive plugins, 2: number of inactive themes */
					__( '%1$d inactive plugins, %2$d unused themes.', 'wp-security-center' ),
					$unused['plugins'],
					$unused['themes']
				),
			0 === $unused['total']
				? ''
				: __( 'Delete what you are not using. Deactivated code still sits on disk, is still reachable by a direct request in some cases, and still stops getting updates the moment you forget it is there. The guide is blunt about it: if you are not using a plugin, remove it.', 'wp-security-center' ),
			'plugins'
		);

		return $checks;
	}

	// -------------------------------------------------------------------------
	// Accounts and access
	// -------------------------------------------------------------------------

	/**
	 * @return array<int, array<string, string>>
	 */
	private static function access_checks(): array {
		$checks = [];

		$admins = self::administrators();
		$count  = count( $admins );

		$checks[] = self::check(
			'admin_count',
			'access',
			__( 'Administrator accounts', 'wp-security-center' ),
			$count > 3 ? self::WARN : self::INFO,
			sprintf(
				/* translators: %d: number of administrator accounts */
				_n( '%d account can manage options.', '%d accounts can manage options.', $count, 'wp-security-center' ),
				$count
			),
			$count > 3
				? __( 'Every administrator is a full compromise of the site if their password leaks. Demote the ones who only need to write, and delete the ones nobody uses — an account that nobody logs into is an account nobody notices being used.', 'wp-security-center' )
				: __( 'Keep it that way. Editors and authors can do their work without being able to install code.', 'wp-security-center' ),
			'passwords'
		);

		$named_admin = self::has_login( 'admin' );

		$checks[] = self::check(
			'admin_username',
			'access',
			__( 'The "admin" username', 'wp-security-center' ),
			$named_admin ? self::INFO : self::OK,
			$named_admin
				? __( 'An account called "admin" exists.', 'wp-security-center' )
				: __( 'No account is called "admin".', 'wp-security-center' ),
			$named_admin
				? __( 'Renaming it is obscurity, not security — but it does mean every automated brute-force run has to guess the name as well as the password, and those runs overwhelmingly try "admin" first. On this site those attempts are recorded as login.failed, so you can see for yourself how much of it there is.', 'wp-security-center' )
				: '',
			'security-through-obscurity'
		);

		$open_registration = (bool) get_option( 'users_can_register' );
		$default_role      = (string) get_option( 'default_role', 'subscriber' );
		$privileged        = ! in_array( $default_role, [ 'subscriber', '' ], true );

		$checks[] = self::check(
			'registration',
			'access',
			__( 'Open registration', 'wp-security-center' ),
			$open_registration && $privileged ? self::FAIL : ( $open_registration ? self::INFO : self::OK ),
			$open_registration
				? sprintf(
					/* translators: %s: role slug new users receive */
					__( 'Anyone can register, and new accounts get the "%s" role.', 'wp-security-center' ),
					$default_role
				)
				: __( 'Registration is closed.', 'wp-security-center' ),
			$open_registration && $privileged
				? __( 'This is a self-service route to a privileged account. Set the default role back to Subscriber, or close registration. Both options are on Settings → General, and this plugin alerts immediately if either one changes.', 'wp-security-center' )
				: '',
			'securing-wp-admin'
		);

		$ssl_admin = is_ssl() || ( defined( 'FORCE_SSL_ADMIN' ) && FORCE_SSL_ADMIN );
		$https     = str_starts_with( (string) get_option( 'home' ), 'https://' );

		$checks[] = self::check(
			'ssl',
			'access',
			__( 'Administration over HTTPS', 'wp-security-center' ),
			$ssl_admin && $https ? self::OK : self::FAIL,
			$ssl_admin && $https
				? __( 'The site and the dashboard are served over HTTPS.', 'wp-security-center' )
				: __( 'The dashboard is reachable over plain HTTP.', 'wp-security-center' ),
			$ssl_admin && $https
				? ''
				: __( "Get a certificate, move the site to https:// and add define( 'FORCE_SSL_ADMIN', true ); to wp-config.php. Without it the session cookie crosses every network between the browser and the server in the clear, and a second factor does not help — the cookie is what gets stolen, not the password.", 'wp-security-center' ),
			'securing-wp-admin'
		);

		$covered = 0;

		foreach ( $admins as $admin_id ) {
			if ( Two_Factor::is_active_for( $admin_id ) ) {
				++$covered;
			}
		}

		$all_covered = $count > 0 && $covered === $count;

		$checks[] = self::check(
			'two_factor',
			'access',
			__( 'Two-factor authentication', 'wp-security-center' ),
			$all_covered ? self::OK : ( $covered > 0 ? self::WARN : self::FAIL ),
			sprintf(
				/* translators: 1: administrators with a second factor, 2: total administrators */
				__( '%1$d of %2$d administrators have a second factor.', 'wp-security-center' ),
				$covered,
				$count
			),
			$all_covered
				? ''
				: __( 'The guide recommends a second factor alongside a strong password, and it is the one control that survives a password being stolen outright. Set it up on the Two-factor screen, or require it for administrators on Settings → Two-Factor.', 'wp-security-center' ),
			'passwords'
		);

		$xmlrpc = (bool) apply_filters( 'xmlrpc_enabled', true );

		$checks[] = self::check(
			'xmlrpc',
			'access',
			__( 'XML-RPC', 'wp-security-center' ),
			$xmlrpc ? self::INFO : self::OK,
			$xmlrpc
				? __( 'Enabled.', 'wp-security-center' )
				: __( 'Disabled.', 'wp-security-center' ),
			$xmlrpc
				? __( 'It is a second front door for authentication, and one that can test many passwords in a single request. Turn it off unless something needs it — the Jetpack plugin and the official mobile apps do. This plugin alerts if the setting changes either way.', 'wp-security-center' )
				: '',
			'securing-wp-admin'
		);

		return $checks;
	}

	// -------------------------------------------------------------------------
	// Monitoring and recovery
	// -------------------------------------------------------------------------

	/**
	 * @return array<int, array<string, string>>
	 */
	private static function monitoring_checks(): array {
		$checks     = [];
		$settings   = (array) get_option( Installer::OPTION_SETTINGS, [] );
		$recipients = Alerts::recipients( $settings );

		$checks[] = self::check(
			'alert_recipients',
			'monitoring',
			__( 'Somewhere for alerts to go', 'wp-security-center' ),
			empty( $recipients ) ? self::FAIL : self::OK,
			empty( $recipients )
				? __( 'No alert recipients are configured.', 'wp-security-center' )
				: sprintf(
					/* translators: %d: number of alert recipients */
					_n( '%d recipient configured.', '%d recipients configured.', count( $recipients ), 'wp-security-center' ),
					count( $recipients )
				),
			empty( $recipients )
				? __( 'Everything is still being written to the log, but nothing will reach you. Add at least one address on Settings → General and send yourself a test message — an alerting system nobody has ever seen work is not an alerting system.', 'wp-security-center' )
				: '',
			'monitoring'
		);

		$integrity = (array) get_option( Installer::OPTION_INTEGRITY, [] );
		$watching  = ! empty( $integrity['core_checksums'] ) && ! empty( $integrity['scan_muplugins'] ) && ! empty( $integrity['scan_uploads'] );

		$checks[] = self::check(
			'file_monitoring',
			'monitoring',
			__( 'Watching the filesystem', 'wp-security-center' ),
			$watching ? self::OK : self::WARN,
			$watching
				? __( 'Core checksums, mu-plugins and uploads are all being scanned.', 'wp-security-center' )
				: __( 'Some filesystem checks are switched off.', 'wp-security-center' ),
			$watching
				? ''
				: __( 'The guide treats file monitoring as a core part of hardening, because a backdoor that nobody looks for stays for years. Switch the missing scans back on under Settings → File Integrity.', 'wp-security-center' ),
			'monitoring-your-files-for-changes'
		);

		$overdue = self::overdue_jobs();

		$checks[] = self::check(
			'scans_running',
			'monitoring',
			__( 'Scans actually running', 'wp-security-center' ),
			empty( $overdue ) ? self::OK : self::WARN,
			empty( $overdue )
				? __( 'Every scheduled job is on time.', 'wp-security-center' )
				: sprintf(
					/* translators: %d: number of overdue scheduled jobs */
					_n( '%d scheduled job is overdue.', '%d scheduled jobs are overdue.', count( $overdue ), 'wp-security-center' ),
					count( $overdue )
				),
			empty( $overdue )
				? ''
				: __( 'WP-Cron only fires when someone visits the site, so a quiet site scans late — and a site that has stopped receiving visitors is exactly when you want the scan to run. Drive wp-cron.php from a real system cron. The Status screen lists which jobs are behind.', 'wp-security-center' ),
			'monitoring'
		);

		$checks[] = self::check(
			'backups',
			'monitoring',
			__( 'Backups', 'wp-security-center' ),
			self::INFO,
			__( 'Not something this plugin can see.', 'wp-security-center' ),
			__( 'No security plugin can tell you whether your backups work — only a restore can. The guide puts backups alongside hardening for a reason: everything here reduces the odds of a compromise, and none of it helps you recover from one. Keep backups off this server, and restore one somewhere harmless from time to time to prove they are real.', 'wp-security-center' ),
			'data-backups'
		);

		return $checks;
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * @return array<string, string>
	 */
	private static function check( string $id, string $group, string $label, string $status, string $value, string $advice, string $doc ): array {
		return [
			'id'     => $id,
			'group'  => $group,
			'label'  => $label,
			'status' => $status,
			'value'  => $value,
			'advice' => $advice,
			'doc'    => $doc,
		];
	}

	/**
	 * @return string[] Paths that anyone on the server can write to.
	 */
	private static function world_writable_paths(): array {
		$found = [];

		$candidates = [
			'/'             => ABSPATH,
			'wp-includes'   => ABSPATH . 'wp-includes',
			'wp-admin'      => ABSPATH . 'wp-admin',
			'wp-content'    => WP_CONTENT_DIR,
			'plugins'       => WP_PLUGIN_DIR,
			'wp-config.php' => file_exists( ABSPATH . 'wp-config.php' ) ? ABSPATH . 'wp-config.php' : dirname( ABSPATH ) . '/wp-config.php',
		];

		foreach ( $candidates as $label => $path ) {
			if ( ! file_exists( $path ) ) {
				continue;
			}

			if ( 0 !== ( ( fileperms( $path ) & 0777 ) & 0002 ) ) {
				$found[] = $label;
			}
		}

		return $found;
	}

	/**
	 * @return string[] One sentence per problem found, or an empty array.
	 */
	private static function salt_problems(): array {
		$names = [
			'AUTH_KEY',
			'SECURE_AUTH_KEY',
			'LOGGED_IN_KEY',
			'NONCE_KEY',
			'AUTH_SALT',
			'SECURE_AUTH_SALT',
			'LOGGED_IN_SALT',
			'NONCE_SALT',
		];

		$problems = [];
		$missing  = [];
		$weak     = [];
		$values   = [];

		foreach ( $names as $name ) {
			if ( ! defined( $name ) ) {
				$missing[] = $name;
				continue;
			}

			$value = (string) constant( $name );

			if ( '' === $value || str_contains( $value, self::SALT_PLACEHOLDER ) || strlen( $value ) < 32 ) {
				$weak[] = $name;
				continue;
			}

			$values[] = $value;
		}

		if ( ! empty( $missing ) ) {
			$problems[] = sprintf(
				/* translators: %s: comma-separated constant names */
				__( 'Not defined: %s.', 'wp-security-center' ),
				implode( ', ', $missing )
			);
		}

		if ( ! empty( $weak ) ) {
			$problems[] = sprintf(
				/* translators: %s: comma-separated constant names */
				__( 'Still the sample value, empty or too short: %s.', 'wp-security-center' ),
				implode( ', ', $weak )
			);
		}

		if ( count( $values ) !== count( array_unique( $values ) ) ) {
			$problems[] = __( 'Two or more of them are identical, which defeats the point of having eight.', 'wp-security-center' );
		}

		return $problems;
	}

	private static function count_transient_updates( string $transient ): int {
		$data = get_site_transient( $transient );

		return is_object( $data ) && ! empty( $data->response ) ? count( (array) $data->response ) : 0;
	}

	/**
	 * @return array{plugins:int, themes:int, total:int}
	 */
	private static function unused_extensions(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$inactive = 0;

		foreach ( array_keys( get_plugins() ) as $file ) {
			if ( ! is_plugin_active( (string) $file ) ) {
				++$inactive;
			}
		}

		$active_theme = wp_get_theme();
		$parent       = $active_theme->parent();
		$in_use       = array_filter( [ $active_theme->get_stylesheet(), $parent ? $parent->get_stylesheet() : '' ] );
		$unused       = 0;

		foreach ( array_keys( wp_get_themes() ) as $slug ) {
			if ( ! in_array( (string) $slug, $in_use, true ) ) {
				++$unused;
			}
		}

		return [
			'plugins' => $inactive,
			'themes'  => $unused,
			'total'   => $inactive + $unused,
		];
	}

	/**
	 * @return int[] Administrator user IDs.
	 */
	private static function administrators(): array {
		$query = new \WP_User_Query(
			[
				'role'   => 'administrator',
				'fields' => 'ID',
				'number' => 200,
			]
		);

		return array_map( 'intval', (array) $query->get_results() );
	}

	private static function has_login( string $login ): bool {
		return (bool) get_user_by( 'login', $login );
	}

	/**
	 * @return string[] Cron hooks that are late or missing.
	 */
	private static function overdue_jobs(): array {
		$late = [];

		foreach ( array_keys( Installer::cron_schedule() ) as $hook ) {
			$next = wp_next_scheduled( $hook );

			if ( false === $next || $next < ( time() - DAY_IN_SECONDS ) ) {
				$late[] = $hook;
			}
		}

		return $late;
	}

	/**
	 * @param mixed $value Constant value of any type.
	 */
	private static function readable( $value ): string {
		if ( is_bool( $value ) ) {
			return $value ? 'true' : 'false';
		}

		return (string) $value;
	}
}
