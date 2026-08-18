<?php
/**
 * Detects user changes made outside WordPress.
 *
 * Hooks cannot see a direct SQL write, so this compares the users table against
 * a stored baseline of per-row hashes. It is the only way to catch a login name
 * being changed (core refuses to do it, so any change means something bypassed
 * the API), an administrator injected straight into the database, or a password
 * hash swapped by hand.
 *
 * Necessarily after the fact: findings are up to one scan interval late.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class User_Reconciler {

	private const ADMIN = 'administrator';

	public function register(): void {
		add_action( Installer::CRON_USER_SCAN, [ __CLASS__, 'run' ] );

		// Refresh the baseline straight after a legitimate change so the next
		// scan does not report it as an out-of-band edit.
		foreach ( [ 'user_register', 'profile_update', 'set_user_role', 'add_user_role', 'remove_user_role' ] as $hook ) {
			add_action( $hook, [ __CLASS__, 'refresh_user' ], 99, 1 );
		}

		add_action( 'deleted_user', [ __CLASS__, 'forget_user' ], 99, 1 );
	}

	/**
	 * Compare every user against the baseline.
	 *
	 * @param bool $silent Adopt the current state without reporting.
	 * @return array{checked:int, findings:int}
	 */
	public static function run( bool $silent = false ): array {
		global $wpdb;

		$table    = Installer::table_user_baseline();
		$findings = 0;

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- table name from $wpdb->prefix, no user input.
		$baseline = $wpdb->get_results( "SELECT * FROM `{$table}`", ARRAY_A );
		$baseline = is_array( $baseline ) ? $baseline : [];

		$known = [];
		foreach ( $baseline as $row ) {
			$known[ (int) $row['user_id'] ] = $row;
		}

		$users   = get_users( [ 'fields' => 'ID' ] );
		$current = [];

		foreach ( $users as $user_id ) {
			$user_id   = (int) $user_id;
			$current[] = $user_id;

			$snapshot = self::snapshot( $user_id );

			if ( null === $snapshot ) {
				continue;
			}

			$previous = $known[ $user_id ] ?? null;

			if ( null === $previous ) {
				// Unknown user. On a first run everything is unknown, so the
				// baseline is simply adopted; afterwards it is a real finding.
				if ( ! $silent && ! empty( $baseline ) ) {
					++$findings;
					self::report_new( $snapshot );
				}

				self::store( $snapshot );
				continue;
			}

			if ( hash_equals( (string) $previous['row_hash'], (string) $snapshot['row_hash'] ) ) {
				continue;
			}

			if ( ! $silent ) {
				++$findings;
				self::report_change( $previous, $snapshot );
			}

			self::store( $snapshot );
		}

		// Rows in the baseline with no matching user.
		foreach ( $known as $user_id => $row ) {
			if ( in_array( $user_id, $current, true ) ) {
				continue;
			}

			if ( ! $silent ) {
				++$findings;

				Logger::log(
					'user.db_deleted_out_of_band',
					[
						'object_id'    => (string) $user_id,
						'object_label' => (string) $row['user_login'],
						'target_user'  => $user_id,
						'target_login' => (string) $row['user_login'],
						'message'      => sprintf(
							'The user "%s" (%s) is gone from the database, but no deletion was recorded through WordPress.',
							(string) $row['user_login'],
							(string) $row['user_email']
						),
						'data'         => [
							'login' => (string) $row['user_login'],
							'email' => (string) $row['user_email'],
							'roles' => (string) $row['roles'],
						],
					]
				);
			}

			self::forget_user( $user_id );
		}

		return [
			'checked'  => count( $current ),
			'findings' => $findings,
		];
	}

	/**
	 * @param array<string, mixed> $snapshot Current user state.
	 */
	private static function report_new( array $snapshot ): void {
		$is_admin = false !== strpos( (string) $snapshot['roles'], self::ADMIN );

		Logger::log(
			'user.db_created_out_of_band',
			[
				'object_id'    => (string) $snapshot['user_id'],
				'object_label' => (string) $snapshot['user_login'],
				'target_user'  => (int) $snapshot['user_id'],
				'message'      => sprintf(
					'The user "%s" (%s, role %s) exists but was never created through WordPress.%s',
					(string) $snapshot['user_login'],
					(string) $snapshot['user_email'],
					(string) $snapshot['roles'] ?: 'none',
					$is_admin ? ' This account has administrator rights.' : ''
				),
				'data'         => [
					'login'            => (string) $snapshot['user_login'],
					'email'            => (string) $snapshot['user_email'],
					'roles'            => (string) $snapshot['roles'],
					'registered'       => (string) $snapshot['registered'],
					'is_administrator' => $is_admin,
				],
			]
		);
	}

	/**
	 * @param array<string, mixed> $previous Baseline row.
	 * @param array<string, mixed> $snapshot Current state.
	 */
	private static function report_change( array $previous, array $snapshot ): void {
		$diff = [];

		$fields = [
			'user_login'    => __( 'login name', 'wp-security-center' ),
			'user_email'    => __( 'e-mail address', 'wp-security-center' ),
			'user_nicename' => __( 'nicename', 'wp-security-center' ),
			'display_name'  => __( 'display name', 'wp-security-center' ),
			'roles'         => __( 'roles', 'wp-security-center' ),
		];

		foreach ( $fields as $field => $label ) {
			if ( (string) $previous[ $field ] !== (string) $snapshot[ $field ] ) {
				$diff[ $field ] = [
					'from' => (string) $previous[ $field ],
					'to'   => (string) $snapshot[ $field ],
				];
			}
		}

		// The password hash itself is never stored or logged, only a hash of it,
		// so this reports the fact of a change without leaking material.
		if ( (string) $previous['pass_hash'] !== (string) $snapshot['pass_hash'] ) {
			$diff['password'] = [
				'from' => '(changed)',
				'to'   => '(changed)',
			];
		}

		if ( (string) $previous['caps_hash'] !== (string) $snapshot['caps_hash'] ) {
			$diff['capabilities'] = [
				'from' => '(changed)',
				'to'   => '(changed)',
			];
		}

		if ( empty( $diff ) ) {
			return;
		}

		// A login-name change deserves its own event: core has no code path
		// that can produce it.
		if ( isset( $diff['user_login'] ) ) {
			Logger::log(
				'user.login_changed',
				[
					'object_id'    => (string) $snapshot['user_id'],
					'object_label' => (string) $snapshot['user_login'],
					'target_user'  => (int) $snapshot['user_id'],
					'message'      => sprintf(
						'The login name of user %d changed from "%s" to "%s" without going through WordPress. Core provides no way to do this.',
						(int) $snapshot['user_id'],
						$diff['user_login']['from'],
						$diff['user_login']['to']
					),
					'data'         => $diff,
				]
			);
		}

		$changed = array_map(
			static fn( string $key ): string => $fields[ $key ] ?? $key,
			array_keys( $diff )
		);

		Logger::log(
			'user.db_modified_out_of_band',
			[
				'object_id'    => (string) $snapshot['user_id'],
				'object_label' => (string) $snapshot['user_login'],
				'target_user'  => (int) $snapshot['user_id'],
				'message'      => sprintf(
					'The user "%s" changed in the database without a corresponding WordPress action. Changed: %s.',
					(string) $snapshot['user_login'],
					implode( ', ', $changed )
				),
				'data'         => $diff,
			]
		);
	}

	/**
	 * Current state of one user, with the row hash.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function snapshot( int $user_id ): ?array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- must read the raw row: get_userdata() is cached and would hide a direct write, which is the entire point of this scanner.
		$row = $wpdb->get_row(
			$wpdb->prepare( "SELECT ID, user_login, user_email, user_nicename, display_name, user_pass, user_registered FROM {$wpdb->users} WHERE ID = %d", $user_id ),
			ARRAY_A
		);

		if ( ! is_array( $row ) ) {
			return null;
		}

		$caps = get_user_meta( $user_id, $wpdb->get_blog_prefix() . 'capabilities', true );
		$caps = is_array( $caps ) ? $caps : [];

		ksort( $caps );

		$roles = array_keys( array_filter( $caps ) );
		sort( $roles );

		$snapshot = [
			'user_id'       => $user_id,
			'user_login'    => (string) $row['user_login'],
			'user_email'    => (string) $row['user_email'],
			'user_nicename' => (string) $row['user_nicename'],
			'display_name'  => (string) $row['display_name'],
			// A hash OF the stored hash: enough to detect a change, useless to
			// an attacker who reads this table.
			'pass_hash'     => hash( 'sha256', (string) $row['user_pass'] ),
			'roles'         => implode( ',', $roles ),
			'caps_hash'     => hash( 'sha256', (string) wp_json_encode( $caps ) ),
			'registered'    => (string) $row['user_registered'],
		];

		$snapshot['row_hash'] = hash(
			'sha256',
			implode(
				'|',
				[
					$snapshot['user_id'],
					$snapshot['user_login'],
					$snapshot['user_email'],
					$snapshot['user_nicename'],
					$snapshot['display_name'],
					$snapshot['pass_hash'],
					$snapshot['roles'],
					$snapshot['caps_hash'],
				]
			)
		);

		return $snapshot;
	}

	/**
	 * @param array<string, mixed> $snapshot User state.
	 */
	private static function store( array $snapshot ): void {
		global $wpdb;

		$wpdb->replace(
			Installer::table_user_baseline(),
			[
				'user_id'       => (int) $snapshot['user_id'],
				'user_login'    => $snapshot['user_login'],
				'user_email'    => $snapshot['user_email'],
				'user_nicename' => $snapshot['user_nicename'],
				'display_name'  => $snapshot['display_name'],
				'pass_hash'     => $snapshot['pass_hash'],
				'roles'         => $snapshot['roles'],
				'caps_hash'     => $snapshot['caps_hash'],
				'row_hash'      => $snapshot['row_hash'],
				'registered'    => $snapshot['registered'],
				'updated_at'    => gmdate( 'Y-m-d H:i:s' ),
			],
			[ '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ]
		);
	}

	/**
	 * @param int $user_id User whose baseline should be refreshed.
	 */
	public static function refresh_user( $user_id ): void {
		$snapshot = self::snapshot( (int) $user_id );

		if ( null !== $snapshot ) {
			self::store( $snapshot );
		}
	}

	/**
	 * @param int $user_id User to drop from the baseline.
	 */
	public static function forget_user( $user_id ): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- our own table.
		$wpdb->delete( Installer::table_user_baseline(), [ 'user_id' => (int) $user_id ], [ '%d' ] );
	}

	/**
	 * Adopt the current users as the baseline, reporting nothing.
	 */
	public static function establish_baseline(): void {
		self::run( true );
	}
}
