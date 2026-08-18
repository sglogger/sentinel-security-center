<?php
/**
 * Shared query builder for the log.
 *
 * The list table and the CSV export must always agree on what "the current
 * filter" means — exporting something other than what is on screen is a
 * genuinely misleading bug in an audit tool — so both go through here.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Log_Query {

	/** Columns that may be sorted on. Anything else is ignored. */
	private const SORTABLE = [ 'event_time', 'severity', 'event_type', 'actor_login', 'ip_text', 'country' ];

	/**
	 * Build the WHERE fragment and its bound values from a filter array.
	 *
	 * @param array<string, mixed> $filters Raw, already-sanitised filters.
	 * @return array{sql:string, values:array<int, mixed>}
	 */
	private static function where( array $filters ): array {
		$sql    = [ '1=1' ];
		$values = [];

		if ( ! empty( $filters['event_type'] ) ) {
			$sql[]    = 'event_type = %s';
			$values[] = (string) $filters['event_type'];
		}

		if ( ! empty( $filters['group'] ) ) {
			$types = [];
			foreach ( Event_Registry::all() as $type => $def ) {
				if ( $def['group'] === $filters['group'] ) {
					$types[] = $type;
				}
			}

			if ( empty( $types ) ) {
				// A group with no events must return nothing, not everything.
				$sql[] = '1=0';
			} else {
				$sql[]  = 'event_type IN (' . implode( ',', array_fill( 0, count( $types ), '%s' ) ) . ')';
				$values = array_merge( $values, $types );
			}
		}

		if ( ! empty( $filters['severity'] ) ) {
			$sql[]    = 'severity >= %d';
			$values[] = (int) $filters['severity'];
		}

		if ( ! empty( $filters['actor'] ) ) {
			$sql[]    = 'actor_user_id = %d';
			$values[] = (int) $filters['actor'];
		}

		if ( ! empty( $filters['ip'] ) ) {
			$sql[]    = 'ip_text LIKE %s';
			$values[] = '%' . $GLOBALS['wpdb']->esc_like( (string) $filters['ip'] ) . '%';
		}

		if ( ! empty( $filters['country'] ) ) {
			$sql[]    = 'country = %s';
			$values[] = strtoupper( (string) $filters['country'] );
		}

		if ( ! empty( $filters['since'] ) ) {
			$sql[]    = 'event_time >= %s';
			$values[] = (string) $filters['since'];
		}

		if ( ! empty( $filters['until'] ) ) {
			$sql[]    = 'event_time <= %s';
			$values[] = (string) $filters['until'];
		}

		if ( ! empty( $filters['search'] ) ) {
			$like   = '%' . $GLOBALS['wpdb']->esc_like( (string) $filters['search'] ) . '%';
			$sql[]  = '(message LIKE %s OR object_label LIKE %s OR object_id LIKE %s OR actor_login LIKE %s OR target_login LIKE %s)';
			$values = array_merge( $values, [ $like, $like, $like, $like, $like ] );
		}

		return [
			'sql'    => implode( ' AND ', $sql ),
			'values' => $values,
		];
	}

	/**
	 * Fetch a page of rows.
	 *
	 * @param array<string, mixed> $filters Filters.
	 * @param array<string, mixed> $args    orderby, order, per_page, offset.
	 * @return array<int, array<string, mixed>>
	 */
	public static function get_rows( array $filters, array $args = [] ): array {
		global $wpdb;

		$orderby = (string) ( $args['orderby'] ?? 'event_time' );
		if ( ! in_array( $orderby, self::SORTABLE, true ) ) {
			$orderby = 'event_time';
		}

		$order = strtoupper( (string) ( $args['order'] ?? 'DESC' ) );
		$order = 'ASC' === $order ? 'ASC' : 'DESC';

		$per_page = max( 1, min( 500, (int) ( $args['per_page'] ?? 50 ) ) );
		$offset   = max( 0, (int) ( $args['offset'] ?? 0 ) );

		$table = Installer::table_log();
		$where = self::where( $filters );

		// The id tiebreaker keeps pagination stable when many rows share a
		// timestamp, which happens constantly during a bulk action or a scan.
		$sql = "SELECT * FROM `{$table}` WHERE {$where['sql']} ORDER BY {$orderby} {$order}, id {$order} LIMIT %d OFFSET %d";

		$values = array_merge( $where['values'], [ $per_page, $offset ] );

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQLPlaceholders -- every value IS bound through prepare(); the interpolated parts are a $wpdb->prefix table name and a column/direction from a fixed whitelist, neither of which can be a placeholder.
		$rows = $wpdb->get_results( $wpdb->prepare( $sql, $values ), ARRAY_A );

		return is_array( $rows ) ? $rows : [];
	}

	/**
	 * Count rows matching the filters.
	 *
	 * A plain COUNT(*) rather than SQL_CALC_FOUND_ROWS, which is deprecated in
	 * MySQL 8 and slower than two indexed queries.
	 *
	 * @param array<string, mixed> $filters Filters.
	 */
	public static function count( array $filters ): int {
		global $wpdb;

		$table = Installer::table_log();
		$where = self::where( $filters );

		$sql = "SELECT COUNT(*) FROM `{$table}` WHERE {$where['sql']}";

		if ( empty( $where['values'] ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- no user input in this branch.
			return (int) $wpdb->get_var( $sql );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery -- placeholders bound here.
		return (int) $wpdb->get_var( $wpdb->prepare( $sql, $where['values'] ) );
	}

	/**
	 * Stream every matching row to a callback, in batches.
	 *
	 * Used by the exporter: a filter matching 400k rows must not be loaded into
	 * memory in one go.
	 *
	 * @param array<string, mixed> $filters  Filters.
	 * @param callable             $callback Receives one row array at a time.
	 * @param array<string, mixed> $args     orderby / order.
	 */
	public static function each( array $filters, callable $callback, array $args = [] ): void {
		$offset  = 0;
		$batch   = 500;
		$fetched = 0;

		do {
			$rows = self::get_rows(
				$filters,
				array_merge(
					$args,
					[
						'per_page' => $batch,
						'offset'   => $offset,
					]
				)
			);

			foreach ( $rows as $row ) {
				$callback( $row );
			}

			$offset += $batch;
			$fetched = count( $rows );
		} while ( $fetched === $batch );
	}

	/**
	 * Distinct event types actually present in the log, for the filter dropdown.
	 *
	 * @return string[]
	 */
	public static function used_event_types(): array {
		global $wpdb;

		$table = Installer::table_log();

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- table name from $wpdb->prefix, no user input.
		$types = $wpdb->get_col( "SELECT DISTINCT event_type FROM `{$table}` ORDER BY event_type ASC" );

		return is_array( $types ) ? array_map( 'strval', $types ) : [];
	}

	/**
	 * Read and sanitise the filters from the current request.
	 *
	 * @return array<string, mixed>
	 */
	public static function filters_from_request(): array {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only filtering of a list view; nothing is changed.
		$get = wp_unslash( $_GET );
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$filters = [];

		if ( ! empty( $get['event_type'] ) ) {
			$type = sanitize_text_field( (string) $get['event_type'] );
			if ( Event_Registry::exists( $type ) ) {
				$filters['event_type'] = $type;
			}
		}

		if ( ! empty( $get['group'] ) ) {
			$group = sanitize_key( (string) $get['group'] );
			if ( isset( Event_Registry::groups()[ $group ] ) ) {
				$filters['group'] = $group;
			}
		}

		if ( ! empty( $get['severity'] ) ) {
			$filters['severity'] = max( 0, min( 50, (int) $get['severity'] ) );
		}

		if ( ! empty( $get['actor'] ) ) {
			$filters['actor'] = (int) $get['actor'];
		}

		if ( ! empty( $get['ip'] ) ) {
			$filters['ip'] = sanitize_text_field( (string) $get['ip'] );
		}

		if ( ! empty( $get['country'] ) ) {
			$filters['country'] = substr( sanitize_text_field( (string) $get['country'] ), 0, 2 );
		}

		if ( ! empty( $get['s'] ) ) {
			$filters['search'] = sanitize_text_field( (string) $get['s'] );
		}

		// Relative timeframe, in days.
		if ( ! empty( $get['days'] ) ) {
			$days = max( 1, min( 3650, (int) $get['days'] ) );

			$filters['days']  = $days;
			$filters['since'] = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );
		}

		return $filters;
	}
}
