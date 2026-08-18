<?php
/**
 * User and administrator monitoring.
 *
 * This is the fiddliest monitor in the plugin, because WordPress does not
 * report user changes as cleanly as it appears to. Three traps are handled
 * here explicitly:
 *
 * 1. Inside wp_insert_user(), WP_User::set_role() runs BEFORE the
 *    `user_register` action. A naive set_user_role handler therefore logs a
 *    phantom "role changed" for every single new user. Role events are
 *    buffered and flushed on shutdown, where they can be merged into the
 *    creation event instead.
 *
 * 2. `wp_set_password` does NOT fire when a user changes their own password on
 *    profile.php — wp_insert_user() writes the hash with a direct query. Three
 *    signals are needed, de-duplicated per request.
 *
 * 3. `delete_user` carries the WP_User; `deleted_user` does not usefully, since
 *    the row is already gone. Metadata is captured on the former.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class User_Monitor {

	private const ADMIN = 'administrator';

	/** @var array<int, array{old:string[], new:string[]}> Buffered role changes. */
	private array $role_buffer = [];

	/** @var int[] User IDs created in this request. */
	private array $created = [];

	/** @var int[] User IDs whose password change was already reported by the reset flow. */
	private array $password_reported = [];

	/** @var array<int, array{login:string, source:string}> Buffered password changes. */
	private array $password_buffer = [];

	/** @var array<int, \WP_User> Users captured before deletion. */
	private array $pending_delete = [];

	/** @var int[] User IDs whose reset flow is in progress. */
	private array $reset_flow = [];

	public function register(): void {
		add_action( 'user_register', [ $this, 'on_register' ], 10, 2 );

		add_action( 'set_user_role', [ $this, 'on_set_role' ], 10, 3 );
		add_action( 'add_user_role', [ $this, 'on_add_role' ], 10, 2 );
		add_action( 'remove_user_role', [ $this, 'on_remove_role' ], 10, 2 );

		add_action( 'profile_update', [ $this, 'on_profile_update' ], 10, 3 );

		add_action( 'delete_user', [ $this, 'capture_user' ], 10, 3 );
		add_action( 'deleted_user', [ $this, 'on_deleted' ], 10, 3 );

		add_action( 'wp_set_password', [ $this, 'on_set_password' ], 10, 2 );
		add_action( 'retrieve_password_key', [ $this, 'on_reset_requested' ], 10, 2 );
		add_action( 'after_password_reset', [ $this, 'on_reset_completed' ], 10, 2 );

		add_action( 'added_user_meta', [ $this, 'on_user_meta' ], 10, 4 );
		add_action( 'updated_user_meta', [ $this, 'on_user_meta' ], 10, 4 );

		// Priority 0 so the merge happens before anything else on shutdown.
		add_action( 'shutdown', [ $this, 'flush' ], 0 );
	}

	// -------------------------------------------------------------------------
	// Creation
	// -------------------------------------------------------------------------

	/**
	 * @param int                  $user_id  New user ID.
	 * @param array<string, mixed> $userdata Submitted data (since WP 5.8).
	 */
	public function on_register( $user_id, $userdata = [] ): void {
		$user_id = (int) $user_id;

		$this->created[] = $user_id;

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		$roles    = (array) $user->roles;
		$is_admin = in_array( self::ADMIN, $roles, true );

		Logger::log(
			$is_admin ? 'user.created_admin' : 'user.created',
			[
				'object_id'    => (string) $user_id,
				'object_label' => (string) $user->user_login,
				'target_user'  => $user_id,
				'message'      => sprintf(
					'A new user "%s" (%s) was created with the role %s.',
					$user->user_login,
					$user->user_email,
					implode( ', ', $roles ) ?: 'none'
				),
				'data'         => [
					'login' => $user->user_login,
					'email' => $user->user_email,
					'roles' => $roles,
				],
			]
		);
	}

	// -------------------------------------------------------------------------
	// Roles — buffered, see the class docblock
	// -------------------------------------------------------------------------

	/**
	 * @param int      $user_id   Affected user.
	 * @param string   $role      New role.
	 * @param string[] $old_roles Roles before the change.
	 */
	public function on_set_role( $user_id, $role, $old_roles ): void {
		// WP_User::set_role() fires remove_user_role and add_user_role BEFORE
		// this hook, and by then the in-memory roles are already partly
		// rewritten. Only set_user_role receives the true previous roles, so it
		// overwrites whatever those earlier hooks buffered.
		$this->role_buffer[ (int) $user_id ] = [
			'old' => array_values( (array) $old_roles ),
			'new' => [ (string) $role ],
		];
	}

	/**
	 * set_user_role does not fire for add_role()/remove_role(), so these are
	 * tracked separately.
	 *
	 * @param int    $user_id Affected user.
	 * @param string $role    Role added.
	 */
	public function on_add_role( $user_id, $role ): void {
		$user = get_userdata( (int) $user_id );
		$new  = $user ? (array) $user->roles : [];
		$old  = array_values( array_diff( $new, [ (string) $role ] ) );

		$this->buffer( (int) $user_id, $old, $new );
	}

	/**
	 * @param int    $user_id Affected user.
	 * @param string $role    Role removed.
	 */
	public function on_remove_role( $user_id, $role ): void {
		$user = get_userdata( (int) $user_id );
		$new  = $user ? (array) $user->roles : [];
		$old  = array_values( array_unique( array_merge( $new, [ (string) $role ] ) ) );

		$this->buffer( (int) $user_id, $old, $new );
	}

	/**
	 * @param string[] $old Roles before.
	 * @param string[] $new Roles after.
	 */
	private function buffer( int $user_id, array $old, array $new ): void {
		if ( isset( $this->role_buffer[ $user_id ] ) ) {
			// Keep the earliest "before" so a chain of changes in one request
			// still reports the true starting point.
			$this->role_buffer[ $user_id ]['new'] = $new;
			return;
		}

		$this->role_buffer[ $user_id ] = [
			'old' => array_values( $old ),
			'new' => array_values( $new ),
		];
	}

	/**
	 * Emit the buffered role changes, dropping any that belong to a user
	 * created in this same request.
	 */
	public function flush(): void {
		$this->flush_passwords();

		foreach ( $this->role_buffer as $user_id => $change ) {
			// The role was reported as part of user.created already.
			if ( in_array( $user_id, $this->created, true ) ) {
				continue;
			}

			$old = $change['old'];
			$new = $change['new'];

			sort( $old );
			sort( $new );

			if ( $old === $new ) {
				continue;
			}

			$user  = get_userdata( $user_id );
			$login = $user ? (string) $user->user_login : (string) $user_id;

			$was_admin = in_array( self::ADMIN, $old, true );
			$is_admin  = in_array( self::ADMIN, $new, true );

			if ( ! $was_admin && $is_admin ) {
				$type = 'user.promoted_admin';
			} elseif ( $was_admin && ! $is_admin ) {
				$type = 'user.demoted_admin';
			} else {
				$type = 'user.role_changed';
			}

			Logger::log(
				$type,
				[
					'object_id'    => (string) $user_id,
					'object_label' => $login,
					'target_user'  => $user_id,
					'message'      => sprintf(
						'The role of "%s" changed from [%s] to [%s].',
						$login,
						implode( ', ', $old ) ?: 'none',
						implode( ', ', $new ) ?: 'none'
					),
					'data'         => [
						'old_roles' => $old,
						'new_roles' => $new,
					],
				]
			);

			$this->maybe_self_admin( $user_id, $login, 'role' );
		}

		$this->role_buffer = [];
	}

	// -------------------------------------------------------------------------
	// Profile changes
	// -------------------------------------------------------------------------

	/**
	 * @param int                  $user_id       Affected user.
	 * @param \WP_User             $old_user_data User before the update.
	 * @param array<string, mixed> $userdata      Submitted data (since WP 5.9).
	 */
	public function on_profile_update( $user_id, $old_user_data = null, $userdata = [] ): void {
		$user_id = (int) $user_id;
		$user    = get_userdata( $user_id );

		if ( ! $user || ! $old_user_data instanceof \WP_User ) {
			return;
		}

		$login    = (string) $user->user_login;
		$is_admin = in_array( self::ADMIN, (array) $user->roles, true );

		// E-mail address.
		if ( $old_user_data->user_email !== $user->user_email ) {
			Logger::log(
				'user.email_changed',
				[
					'object_id'    => (string) $user_id,
					'object_label' => $login,
					'target_user'  => $user_id,
					'message'      => sprintf(
						'The e-mail address of "%s" changed from %s to %s.',
						$login,
						$old_user_data->user_email,
						$user->user_email
					),
					'data'         => [
						'old_email'        => $old_user_data->user_email,
						'new_email'        => $user->user_email,
						'is_administrator' => $is_admin,
					],
				]
			);

			$this->maybe_self_admin( $user_id, $login, 'email' );
		}

		// Password. The stored hash is compared, never logged.
		if ( $old_user_data->user_pass !== $user->user_pass ) {
			$this->report_password( $user_id, $login, 'profile' );
		}

		// Login name. Core refuses to change this, so a difference here means
		// something bypassed the normal API entirely.
		if ( $old_user_data->user_login !== $user->user_login ) {
			Logger::log(
				'user.login_changed',
				[
					'object_id'    => (string) $user_id,
					'object_label' => $login,
					'target_user'  => $user_id,
					'message'      => sprintf(
						'The login name changed from "%s" to "%s". WordPress does not allow this through its own API.',
						$old_user_data->user_login,
						$user->user_login
					),
					'data'         => [
						'old_login' => $old_user_data->user_login,
						'new_login' => $user->user_login,
					],
				]
			);
		}
	}

	/**
	 * A self-service e-mail change is deferred behind a confirmation link, so
	 * the request itself is worth recording — the confirmed change arrives
	 * later through profile_update.
	 *
	 * @param int    $meta_id    Meta row ID.
	 * @param int    $user_id    Affected user.
	 * @param string $meta_key   Meta key.
	 * @param mixed  $meta_value Meta value.
	 */
	public function on_user_meta( $meta_id, $user_id, $meta_key, $meta_value ): void {
		if ( '_new_email' !== $meta_key ) {
			return;
		}

		$user  = get_userdata( (int) $user_id );
		$login = $user ? (string) $user->user_login : (string) $user_id;
		$new   = is_array( $meta_value ) ? (string) ( $meta_value['newemail'] ?? '' ) : '';

		Logger::log(
			'user.email_change_requested',
			[
				'object_id'    => (string) (int) $user_id,
				'object_label' => $login,
				'target_user'  => (int) $user_id,
				'message'      => sprintf(
					'A change of e-mail address to %s was requested for "%s" and is awaiting confirmation.',
					$new,
					$login
				),
				'data'         => [ 'requested_email' => $new ],
			]
		);
	}

	// -------------------------------------------------------------------------
	// Passwords
	// -------------------------------------------------------------------------

	/**
	 * @param string $password Plain password. Never logged, never stored.
	 * @param int    $user_id  Affected user.
	 */
	public function on_set_password( $password, $user_id ): void {
		$user  = get_userdata( (int) $user_id );
		$login = $user ? (string) $user->user_login : (string) $user_id;

		$this->report_password( (int) $user_id, $login, 'api' );
	}

	/**
	 * @param string $user_login User login.
	 * @param string $key        Reset key. Not logged.
	 */
	public function on_reset_requested( $user_login, $key = '' ): void {
		$user = get_user_by( 'login', (string) $user_login );

		if ( ! $user ) {
			return;
		}

		$this->reset_flow[] = (int) $user->ID;

		Logger::log(
			'user.password_reset_requested',
			[
				'object_id'    => (string) $user->ID,
				'object_label' => (string) $user->user_login,
				'target_user'  => (int) $user->ID,
				'message'      => sprintf( 'A password reset was requested for "%s".', $user->user_login ),
				'data'         => [ 'login' => (string) $user->user_login ],
			]
		);
	}

	/**
	 * @param \WP_User $user     Affected user.
	 * @param string   $new_pass New password. Never logged.
	 */
	public function on_reset_completed( $user, $new_pass = '' ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}

		// Mark as handled so the profile_update / wp_set_password signals for
		// the same change do not produce a second event.
		$this->password_reported[] = (int) $user->ID;

		$is_admin = in_array( self::ADMIN, (array) $user->roles, true );

		Logger::log(
			'user.password_reset_completed',
			[
				'object_id'    => (string) $user->ID,
				'object_label' => (string) $user->user_login,
				'target_user'  => (int) $user->ID,
				'message'      => sprintf(
					'The password for "%s" was reset through the lost-password flow.%s',
					$user->user_login,
					$is_admin ? ' This user is an administrator.' : ''
				),
				'data'         => [ 'is_administrator' => $is_admin ],
			]
		);
	}

	/**
	 * Buffer a password change rather than emitting it immediately.
	 *
	 * On account creation the password is set BEFORE `user_register` fires, so
	 * an immediate event could not yet know it belongs to a brand-new account.
	 * Deferring to shutdown makes that distinction possible.
	 */
	private function report_password( int $user_id, string $login, string $source ): void {
		if ( isset( $this->password_buffer[ $user_id ] ) ) {
			return;
		}

		$this->password_buffer[ $user_id ] = [
			'login'  => $login,
			'source' => $source,
		];
	}

	/**
	 * Emit the buffered password changes.
	 */
	private function flush_passwords(): void {
		foreach ( $this->password_buffer as $user_id => $entry ) {
			// Setting the initial password while creating an account is not a
			// password change; user.created already reports the new account.
			if ( in_array( $user_id, $this->created, true ) ) {
				continue;
			}

			// The reset flow reports itself with a more specific event.
			if ( in_array( $user_id, $this->password_reported, true ) ) {
				continue;
			}

			$user     = get_userdata( $user_id );
			$login    = (string) $entry['login'];
			$is_admin = $user && in_array( self::ADMIN, (array) $user->roles, true );

			Logger::log(
				'user.password_changed',
				[
					'object_id'    => (string) $user_id,
					'object_label' => $login,
					'target_user'  => $user_id,
					'message'      => sprintf(
						'The password for "%s" was changed.%s',
						$login,
						$is_admin ? ' This user is an administrator.' : ''
					),
					'data'         => [
						'source'           => (string) $entry['source'],
						'is_administrator' => (bool) $is_admin,
					],
				]
			);

			$this->maybe_self_admin( $user_id, $login, 'password' );
		}

		$this->password_buffer = [];
	}

	// -------------------------------------------------------------------------
	// Deletion
	// -------------------------------------------------------------------------

	/**
	 * @param int      $user_id  User about to be deleted.
	 * @param int|null $reassign User content is reassigned to.
	 * @param \WP_User $user     The user object, still intact here.
	 */
	public function capture_user( $user_id, $reassign = null, $user = null ): void {
		if ( $user instanceof \WP_User ) {
			$this->pending_delete[ (int) $user_id ] = $user;
		}
	}

	/**
	 * @param int      $user_id  Deleted user ID.
	 * @param int|null $reassign User content reassigned to.
	 * @param \WP_User $user     The user object.
	 */
	public function on_deleted( $user_id, $reassign = null, $user = null ): void {
		$user_id = (int) $user_id;
		$user    = $this->pending_delete[ $user_id ] ?? ( $user instanceof \WP_User ? $user : null );

		if ( ! $user instanceof \WP_User ) {
			return;
		}

		$roles    = (array) $user->roles;
		$is_admin = in_array( self::ADMIN, $roles, true );

		Logger::log(
			$is_admin ? 'user.deleted_admin' : 'user.deleted',
			[
				'object_id'    => (string) $user_id,
				'object_label' => (string) $user->user_login,
				'target_user'  => $user_id,
				'target_login' => (string) $user->user_login,
				'message'      => sprintf(
					'The user "%s" (%s) with the role %s was deleted.',
					$user->user_login,
					$user->user_email,
					implode( ', ', $roles ) ?: 'none'
				),
				'data'         => [
					'login'    => (string) $user->user_login,
					'email'    => (string) $user->user_email,
					'roles'    => $roles,
					'reassign' => $reassign ? (int) $reassign : 0,
				],
			]
		);

		unset( $this->pending_delete[ $user_id ] );
	}

	// -------------------------------------------------------------------------

	/**
	 * An administrator changing their own account is a distinct signal: it is
	 * what an attacker does immediately after taking over a session.
	 */
	private function maybe_self_admin( int $user_id, string $login, string $what ): void {
		$ctx = Context::current();

		if ( (int) $ctx['actor_user_id'] !== $user_id || 0 === $user_id ) {
			return;
		}

		$user = get_userdata( $user_id );

		if ( ! $user || ! in_array( self::ADMIN, (array) $user->roles, true ) ) {
			return;
		}

		Logger::log(
			'user.self_admin_modified',
			[
				'object_id'    => (string) $user_id,
				'object_label' => $login,
				'target_user'  => $user_id,
				'message'      => sprintf(
					'Administrator "%s" changed their own %s.',
					$login,
					$what
				),
				'data'         => [ 'field' => $what ],
			]
		);
	}
}
