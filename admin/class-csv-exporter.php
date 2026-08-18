<?php
/**
 * CSV export of the currently filtered log.
 *
 * Streamed row by row: a filter matching several hundred thousand entries must
 * not be assembled in memory first.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Csv_Exporter {

	public const ACTION = 'wpsec_export_csv';

	/**
	 * Neutralise spreadsheet formula injection in one cell.
	 *
	 * This log exists to record hostile input — a user name typed into the
	 * login form, a request path, a user agent — which makes its export the
	 * textbook carrier for CSV injection: Excel and LibreOffice execute cells
	 * beginning with =, +, - or @ as formulas, and DDE payloads have been
	 * delivered exactly this way. Such cells are prefixed with a single quote,
	 * which spreadsheets treat as "display as text" and drop on render.
	 */
	public static function guard_cell( string $value ): string {
		if ( '' === $value ) {
			return $value;
		}

		// Also guard after a leading tab/CR/LF, which Excel strips before
		// deciding whether the cell is a formula.
		$first = substr( ltrim( $value, "\t\r\n " ), 0, 1 );

		if ( in_array( $first, [ '=', '+', '-', '@' ], true ) ) {
			return "'" . $value;
		}

		return $value;
	}

	public function register(): void {
		add_action( 'admin_post_' . self::ACTION, [ $this, 'handle' ] );
	}

	public function handle(): void {
		if ( ! current_user_can( Admin::CAP ) ) {
			wp_die( esc_html__( 'You do not have permission to export the security log.', 'sentinel-security-center' ), '', [ 'response' => 403 ] );
		}

		check_admin_referer( self::ACTION );

		$filters = Log_Query::filters_from_request();

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header(
			'Content-Disposition: attachment; filename=' . sprintf(
				'security-log-%s.csv',
				gmdate( 'Y-m-d-His' )
			)
		);

		$out = fopen( 'php://output', 'w' );

		if ( false === $out ) {
			wp_die( esc_html__( 'The export could not be started.', 'sentinel-security-center' ) );
		}

		// UTF-8 BOM so Excel opens the file with the right encoding instead of
		// mangling every non-ASCII character.
		fwrite( $out, "\xEF\xBB\xBF" );

		fputcsv(
			$out,
			[
				'id',
				'time_utc',
				'event_type',
				'severity',
				'severity_label',
				'description',
				'object_type',
				'object_id',
				'object_label',
				'actor_user_id',
				'actor_login',
				'actor_roles',
				'target_user_id',
				'target_login',
				'ip',
				'country',
				'context',
				'request_uri',
				'user_agent',
				'alert_state',
				'data_json',
			]
		);

		Log_Query::each(
			$filters,
			static function ( array $row ) use ( $out ): void {
				fputcsv(
					$out,
					[
						(int) $row['id'],
						(string) $row['event_time'],
						(string) $row['event_type'],
						(int) $row['severity'],
						Event_Registry::severity_label( (int) $row['severity'] ),
						self::guard_cell( (string) $row['message'] ),
						(string) $row['object_type'],
						self::guard_cell( (string) $row['object_id'] ),
						self::guard_cell( (string) $row['object_label'] ),
						(int) $row['actor_user_id'],
						self::guard_cell( (string) $row['actor_login'] ),
						self::guard_cell( (string) $row['actor_roles'] ),
						(int) $row['target_user_id'],
						self::guard_cell( (string) $row['target_login'] ),
						(string) $row['ip_text'],
						(string) $row['country'],
						(string) $row['context'],
						self::guard_cell( (string) $row['request_uri'] ),
						self::guard_cell( (string) $row['user_agent'] ),
						(int) $row['alert_state'],
						self::guard_cell( (string) $row['data'] ),
					]
				);
			}
		);

		fclose( $out );
		exit;
	}
}
