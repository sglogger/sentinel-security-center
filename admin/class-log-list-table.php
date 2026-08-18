<?php
/**
 * The event log viewer.
 *
 * A log nobody can read is not an audit trail, so this is a real WP_List_Table
 * with sorting, paging, search and filters rather than a dump of rows.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( '\WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

final class Log_List_Table extends \WP_List_Table {

	/** @var array<string, mixed> */
	private array $filters = [];

	private int $total = 0;

	public function __construct() {
		parent::__construct(
			[
				'singular' => 'wpsec_event',
				'plural'   => 'wpsec_events',
				'ajax'     => false,
			]
		);
	}

	/**
	 * @return array<string, string>
	 */
	public function get_columns(): array {
		return [
			'event_time'  => __( 'Time (UTC)', 'wp-security-center' ),
			'severity'    => __( 'Severity', 'wp-security-center' ),
			'event_type'  => __( 'Event', 'wp-security-center' ),
			'description' => __( 'Description', 'wp-security-center' ),
			'actor_login' => __( 'Performed by', 'wp-security-center' ),
			'ip_text'     => __( 'IP address', 'wp-security-center' ),
		];
	}

	/**
	 * @return array<string, array<int, mixed>>
	 */
	protected function get_sortable_columns(): array {
		return [
			'event_time'  => [ 'event_time', true ],
			'severity'    => [ 'severity', false ],
			'event_type'  => [ 'event_type', false ],
			'actor_login' => [ 'actor_login', false ],
			'ip_text'     => [ 'ip_text', false ],
		];
	}

	public function prepare_items(): void {
		$this->filters = Log_Query::filters_from_request();

		$settings = (array) get_option( Installer::OPTION_LOG, [] );
		$per_page = (int) ( $settings['per_page'] ?? 50 );
		$per_page = max( 10, min( 200, $per_page ) );

		$paged = max( 1, (int) $this->get_pagenum() );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only list view.
		$orderby = isset( $_GET['orderby'] ) ? sanitize_key( wp_unslash( (string) $_GET['orderby'] ) ) : 'event_time';
		$order   = isset( $_GET['order'] ) ? sanitize_key( wp_unslash( (string) $_GET['order'] ) ) : 'desc';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$this->total = Log_Query::count( $this->filters );

		$this->items = Log_Query::get_rows(
			$this->filters,
			[
				'orderby'  => $orderby,
				'order'    => $order,
				'per_page' => $per_page,
				'offset'   => ( $paged - 1 ) * $per_page,
			]
		);

		$this->set_pagination_args(
			[
				'total_items' => $this->total,
				'per_page'    => $per_page,
				'total_pages' => (int) ceil( $this->total / $per_page ),
			]
		);

		$this->_column_headers = [ $this->get_columns(), [], $this->get_sortable_columns(), 'description' ];
	}

	public function no_items(): void {
		esc_html_e( 'No events recorded yet.', 'wp-security-center' );
	}

	/**
	 * @param array<string, mixed> $item   Row data.
	 * @param string               $column Column name.
	 */
	public function column_default( $item, $column_name ): string {
		return esc_html( (string) ( $item[ $column_name ] ?? '' ) );
	}

	/**
	 * @param array<string, mixed> $item Row data.
	 */
	public function column_event_time( $item ): string {
		$time = (string) ( $item['event_time'] ?? '' );

		if ( '' === $time ) {
			return '&mdash;';
		}

		$stamp = strtotime( $time . ' UTC' );

		return sprintf(
			'<span title="%s">%s</span><br><small>%s</small>',
			esc_attr( $time . ' UTC' ),
			esc_html( gmdate( 'Y-m-d H:i:s', (int) $stamp ) ),
			esc_html(
				sprintf(
					/* translators: %s: human-readable time difference */
					__( '%s ago', 'wp-security-center' ),
					human_time_diff( (int) $stamp, time() )
				)
			)
		);
	}

	/**
	 * @param array<string, mixed> $item Row data.
	 */
	public function column_severity( $item ): string {
		$severity = (int) ( $item['severity'] ?? 0 );

		$colours = [
			Event_Registry::CRITICAL => '#b32d2e',
			Event_Registry::HIGH     => '#d63638',
			Event_Registry::WARNING  => '#dba617',
			Event_Registry::NOTICE   => '#2271b1',
			Event_Registry::INFO     => '#646970',
		];

		$colour = '#646970';
		foreach ( $colours as $level => $hex ) {
			if ( $severity >= $level ) {
				$colour = $hex;
				break;
			}
		}

		return sprintf(
			'<span style="display:inline-block;padding:2px 8px;border-radius:3px;background:%s;color:#fff;font-size:11px;font-weight:600;">%s</span>',
			esc_attr( $colour ),
			esc_html( Event_Registry::severity_label( $severity ) )
		);
	}

	/**
	 * @param array<string, mixed> $item Row data.
	 */
	public function column_event_type( $item ): string {
		$type = (string) ( $item['event_type'] ?? '' );

		$url = add_query_arg(
			[
				'page'       => Admin::MENU_LOG,
				'event_type' => $type,
			],
			admin_url( 'admin.php' )
		);

		return sprintf( '<a href="%s"><code>%s</code></a>', esc_url( $url ), esc_html( $type ) );
	}

	/**
	 * @param array<string, mixed> $item Row data.
	 */
	public function column_description( $item ): string {
		$message = trim( (string) ( $item['message'] ?? '' ) );

		if ( '' === $message ) {
			$message = Mailer::describe( (string) $item['event_type'], $item );
		}

		$out = '<strong>' . esc_html( $message ) . '</strong>';

		$data = json_decode( (string) ( $item['data'] ?? '' ), true );

		if ( is_array( $data ) && ! empty( $data ) ) {
			$out .= sprintf(
				'<details style="margin-top:4px;"><summary style="cursor:pointer;color:#2271b1;">%s</summary><pre style="white-space:pre-wrap;word-break:break-word;background:#f6f7f7;padding:8px;margin-top:4px;font-size:11px;">%s</pre></details>',
				esc_html__( 'Details', 'wp-security-center' ),
				esc_html( (string) wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) )
			);
		}

		$alert = (int) ( $item['alert_state'] ?? 0 );

		if ( Logger::ALERT_SENT === $alert ) {
			$out .= '<br><small style="color:#646970;">' . esc_html__( 'Alert e-mail sent', 'wp-security-center' ) . '</small>';
		} elseif ( Logger::ALERT_FAILED === $alert ) {
			$out .= '<br><small style="color:#d63638;">' . esc_html__( 'Alert e-mail FAILED to send', 'wp-security-center' ) . '</small>';
		} elseif ( Logger::ALERT_SUPPRESSED === $alert ) {
			$out .= '<br><small style="color:#dba617;">' . esc_html__( 'Alert e-mail suppressed (hourly budget)', 'wp-security-center' ) . '</small>';
		}

		return $out;
	}

	/**
	 * @param array<string, mixed> $item Row data.
	 */
	public function column_actor_login( $item ): string {
		$login = (string) ( $item['actor_login'] ?? '' );
		$id    = (int) ( $item['actor_user_id'] ?? 0 );
		$roles = (string) ( $item['actor_roles'] ?? '' );

		if ( '' === $login ) {
			return '<em>' . esc_html__( 'anonymous', 'wp-security-center' ) . '</em>';
		}

		$out = $id > 0
			? sprintf(
				'<a href="%s">%s</a>',
				esc_url(
					add_query_arg(
						[
							'page'  => Admin::MENU_LOG,
							'actor' => $id,
						],
						admin_url( 'admin.php' )
					)
				),
				esc_html( $login )
			)
			: '<em>' . esc_html( $login ) . '</em>';

		if ( '' !== $roles ) {
			$out .= '<br><small>' . esc_html( $roles ) . '</small>';
		}

		$target = (string) ( $item['target_login'] ?? '' );

		if ( '' !== $target && $target !== $login ) {
			$out .= '<br><small style="color:#2271b1;">' . esc_html(
				sprintf(
					/* translators: %s: affected user login */
					__( 'affected: %s', 'wp-security-center' ),
					$target
				)
			) . '</small>';
		}

		return $out;
	}

	/**
	 * @param array<string, mixed> $item Row data.
	 */
	public function column_ip_text( $item ): string {
		$ip = (string) ( $item['ip_text'] ?? '' );

		if ( '' === $ip ) {
			return '<span style="color:#646970;">&mdash;</span>';
		}

		$out = sprintf(
			'<a href="%s"><code>%s</code></a>',
			esc_url(
				add_query_arg(
					[
						'page' => Admin::MENU_LOG,
						'ip'   => $ip,
					],
					admin_url( 'admin.php' )
				)
			),
			esc_html( $ip )
		);

		$country = (string) ( $item['country'] ?? '' );

		if ( '' !== $country ) {
			$out .= '<br><small>' . esc_html( Country_Resolver::country_name( $country ) ) . '</small>';
		}

		$context = (string) ( $item['context'] ?? '' );

		if ( '' !== $context ) {
			$out .= '<br><small style="color:#646970;">' . esc_html( $context ) . '</small>';
		}

		return $out;
	}

	/**
	 * The filter bar above the table.
	 *
	 * @param string $which Top or bottom.
	 */
	protected function extra_tablenav( $which ): void {
		if ( 'top' !== $which ) {
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only list view.
		$get      = wp_unslash( $_GET );
		$group    = isset( $get['group'] ) ? sanitize_key( (string) $get['group'] ) : '';
		$severity = isset( $get['severity'] ) ? (int) $get['severity'] : 0;
		$days     = isset( $get['days'] ) ? (int) $get['days'] : 0;
		$ip       = isset( $get['ip'] ) ? sanitize_text_field( (string) $get['ip'] ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		echo '<div class="alignleft actions">';

		echo '<select name="group">';
		printf( '<option value="">%s</option>', esc_html__( 'All categories', 'wp-security-center' ) );
		foreach ( Event_Registry::groups() as $key => $label ) {
			printf(
				'<option value="%s"%s>%s</option>',
				esc_attr( $key ),
				selected( $group, $key, false ),
				esc_html( $label )
			);
		}
		echo '</select>';

		echo '<select name="severity">';
		printf( '<option value="">%s</option>', esc_html__( 'Any severity', 'wp-security-center' ) );
		foreach ( [ Event_Registry::CRITICAL, Event_Registry::HIGH, Event_Registry::WARNING, Event_Registry::NOTICE ] as $level ) {
			printf(
				'<option value="%d"%s>%s</option>',
				(int) $level,
				selected( $severity, $level, false ),
				esc_html(
					sprintf(
						/* translators: %s: severity name */
						__( '%s and above', 'wp-security-center' ),
						Event_Registry::severity_label( $level )
					)
				)
			);
		}
		echo '</select>';

		echo '<select name="days">';
		printf( '<option value="">%s</option>', esc_html__( 'All time', 'wp-security-center' ) );
		foreach ( [
			1  => __( 'Last 24 hours', 'wp-security-center' ),
			7  => __( 'Last 7 days', 'wp-security-center' ),
			30 => __( 'Last 30 days', 'wp-security-center' ),
			90 => __( 'Last 90 days', 'wp-security-center' ),
		] as $value => $label ) {
			printf( '<option value="%d"%s>%s</option>', (int) $value, selected( $days, $value, false ), esc_html( $label ) );
		}
		echo '</select>';

		printf(
			'<input type="search" name="ip" value="%s" placeholder="%s" style="width:150px;">',
			esc_attr( $ip ),
			esc_attr__( 'IP address', 'wp-security-center' )
		);

		submit_button( __( 'Filter', 'wp-security-center' ), '', 'filter_action', false );

		echo ' <a href="' . esc_url( $this->export_url() ) . '" class="button">'
			. esc_html__( 'Export CSV', 'wp-security-center' ) . '</a>';

		echo '</div>';
	}

	/**
	 * Export link carrying exactly the filters currently on screen — exporting
	 * something other than what is displayed would be actively misleading.
	 */
	private function export_url(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only list view.
		$get = wp_unslash( $_GET );

		$args = [ 'action' => Csv_Exporter::ACTION ];

		foreach ( [ 'group', 'event_type', 'severity', 'days', 'ip', 'actor', 'country', 's' ] as $key ) {
			if ( ! empty( $get[ $key ] ) ) {
				$args[ $key ] = sanitize_text_field( (string) $get[ $key ] );
			}
		}

		return wp_nonce_url( add_query_arg( $args, admin_url( 'admin-post.php' ) ), Csv_Exporter::ACTION );
	}

	public function get_total(): int {
		return $this->total;
	}
}
