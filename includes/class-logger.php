<?php
/**
 * Writes events to the log table and hands them to the alerting layer.
 *
 * Every monitor and scanner funnels through Logger::log(). Two rules hold
 * everywhere: an unknown event type is refused (the registry is the single
 * source of truth), and a logging failure must never break the request that
 * triggered it — an audit tool that takes the site down is worse than one that
 * misses a line.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Logger {

	// alert_state column values.
	public const ALERT_NONE       = 0;
	public const ALERT_SENT       = 2;
	public const ALERT_FAILED     = 3;
	public const ALERT_SUPPRESSED = 4;

	/**
	 * Record an event.
	 *
	 * @param string               $type Event type from Event_Registry.
	 * @param array<string, mixed> $args {
	 *     Optional. Everything else is derived.
	 *
	 *     @type string $object_id     Identifier: plugin file, user ID, option name, path.
	 *     @type string $object_label  Human-readable name AT THE TIME of the event.
	 *     @type int    $target_user   User the event is about, if not the actor.
	 *     @type string $message       Pre-rendered English summary.
	 *     @type array  $data          Old/new values, diffs, decision traces.
	 *     @type string $country       ISO-3166-1 alpha-2, if known.
	 *     @type string $ip            Overrides the detected client IP.
	 *     @type int    $actor_user_id Overrides the detected actor.
	 * }
	 * @return int Inserted row ID, or 0 when nothing was written.
	 */
	public static function log( string $type, array $args = [] ): int {
		if ( ! Event_Registry::exists( $type ) ) {
			// A typo in an event name must be loud in development and harmless
			// in production, never a silent no-op that hides a real event.
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				trigger_error(
					esc_html( 'WP Security Center: unknown event type "' . $type . '"' ),
					E_USER_WARNING
				);
			}
			return 0;
		}

		$mode = Event_Registry::mode_of( $type );

		if ( Event_Registry::MODE_OFF === $mode ) {
			return 0;
		}

		/**
		 * Suppress logging entirely for the duration of an operation.
		 *
		 * Used when a scanner adopts the current state as its baseline: an
		 * established site would otherwise emit a wall of "new file" reports
		 * for things that have been in place for years.
		 *
		 * @param bool   $suppress Whether to skip this event.
		 * @param string $type     Event type.
		 */
		if ( apply_filters( 'wpsec_suppress_logging', false, $type ) ) {
			return 0;
		}

		global $wpdb;

		$ctx = Context::current();

		$ip = isset( $args['ip'] ) ? (string) $args['ip'] : (string) $ctx['ip'];
		$ip = '' !== $ip ? ( Ip_Matcher::normalise( $ip ) ?? '' ) : '';

		$target_id = (int) ( $args['target_user'] ?? 0 );

		$row = [
			'event_time'     => gmdate( 'Y-m-d H:i:s' ),
			'event_type'     => $type,
			'severity'       => Event_Registry::severity_of( $type ),
			'object_type'    => Event_Registry::object_of( $type ),
			'object_id'      => mb_substr( (string) ( $args['object_id'] ?? '' ), 0, 191 ),
			'object_label'   => mb_substr( (string) ( $args['object_label'] ?? '' ), 0, 191 ),
			'actor_user_id'  => (int) ( $args['actor_user_id'] ?? $ctx['actor_user_id'] ),
			'actor_login'    => mb_substr( (string) ( $args['actor_login'] ?? $ctx['actor_login'] ), 0, 60 ),
			'actor_roles'    => mb_substr( (string) $ctx['actor_roles'], 0, 191 ),
			'target_user_id' => $target_id,
			'target_login'   => mb_substr( (string) ( $args['target_login'] ?? self::login_of( $target_id ) ), 0, 60 ),
			'ip_bin'         => '' !== $ip ? inet_pton( $ip ) : null,
			'ip_text'        => $ip,
			'country'        => strtoupper( mb_substr( (string) ( $args['country'] ?? '' ), 0, 2 ) ),
			'context'        => $ctx['context'],
			'request_uri'    => $ctx['request_uri'],
			'user_agent'     => $ctx['user_agent'],
			'message'        => (string) ( $args['message'] ?? '' ),
			'data'           => (string) wp_json_encode( $args['data'] ?? [] ),
			'alert_state'    => self::ALERT_NONE,
		];

		$formats = [
			'%s',
			'%s',
			'%d',
			'%s',
			'%s',
			'%s',
			'%d',
			'%s',
			'%s',
			'%d',
			'%s',
			'%s',
			'%s',
			'%s',
			'%s',
			'%s',
			'%s',
			'%s',
			'%s',
			'%d',
		];

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- writing to our own table; there is no caching layer to invalidate.
		$ok = $wpdb->insert( Installer::table_log(), $row, $formats );

		if ( false === $ok ) {
			return 0;
		}

		$id = (int) $wpdb->insert_id;

		if ( Event_Registry::MODE_EMAIL === $mode ) {
			$row['id'] = $id;
			Alerts::dispatch( $id, $type, $row );
		}

		/**
		 * Fires after an event has been recorded.
		 *
		 * @param int                  $id   Log row ID.
		 * @param string               $type Event type.
		 * @param array<string, mixed> $row  The stored row.
		 */
		do_action( 'wpsec_event_logged', $id, $type, $row );

		return $id;
	}

	private static function login_of( int $user_id ): string {
		if ( $user_id <= 0 ) {
			return '';
		}

		$user = get_userdata( $user_id );

		return $user ? (string) $user->user_login : '';
	}

	/**
	 * Update the alert bookkeeping for a row.
	 */
	public static function set_alert_state( int $id, int $state ): void {
		if ( $id <= 0 ) {
			return;
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- our own table.
		$wpdb->update( Installer::table_log(), [ 'alert_state' => $state ], [ 'id' => $id ], [ '%d' ], [ '%d' ] );
	}

	/**
	 * Delete rows past the retention window.
	 *
	 * Batched, because the first prune on a site that has been running for
	 * months can otherwise be a multi-million-row DELETE that hits the query
	 * timeout and never completes.
	 *
	 * @return int Rows deleted.
	 */
	public static function prune(): int {
		global $wpdb;

		$settings = (array) get_option( Installer::OPTION_LOG, [] );
		$days     = (int) ( $settings['retention_days'] ?? 180 );

		if ( $days <= 0 ) {
			return 0;
		}

		$table   = Installer::table_log();
		$cutoff  = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );
		$deleted = 0;

		// Bounded so a pathological table cannot spin here forever; whatever is
		// left is picked up by tomorrow's run.
		for ( $i = 0; $i < 40; $i++ ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- table name from $wpdb->prefix; the value IS prepared.
			$rows = (int) $wpdb->query(
				$wpdb->prepare( "DELETE FROM `{$table}` WHERE event_time < %s LIMIT 5000", $cutoff )
			);

			$deleted += $rows;

			if ( $rows < 5000 ) {
				break;
			}
		}

		if ( $deleted > 0 ) {
			self::log(
				'log.pruned',
				[
					'message' => sprintf( 'Pruned %d log entries older than %d days.', $deleted, $days ),
					'data'    => [
						'deleted'        => $deleted,
						'retention_days' => $days,
					],
				]
			);
		}

		return $deleted;
	}

	/**
	 * Register the retention cron handler.
	 */
	public function register(): void {
		add_action( Installer::CRON_PRUNE, [ __CLASS__, 'prune' ] );
	}
}
