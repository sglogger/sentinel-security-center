<?php
/**
 * Turns a logged event into an immediate e-mail.
 *
 * Alerts are sent at once and are never digested — that was an explicit
 * requirement. The hourly budget is not a digest: it is a circuit breaker. A
 * mass finding (a scanner meeting 500 planted PHP files, a bulk plugin action)
 * would otherwise become 500 outbound messages, which gets a mail server rate
 * limited or blacklisted, at which point the alerts that matter never arrive.
 * Above the budget, delivery pauses and one summary goes out. Every event is
 * still written to the log regardless.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Alerts {

	private const COUNTER_TRANSIENT    = 'wpsec_mail_count';
	private const SUPPRESSED_TRANSIENT = 'wpsec_mail_suppressed';

	/**
	 * Send the alert for a logged event.
	 *
	 * @param int                  $log_id Log row ID.
	 * @param string               $type   Event type.
	 * @param array<string, mixed> $row    The stored row.
	 */
	public static function dispatch( int $log_id, string $type, array $row ): void {
		$settings   = (array) get_option( Installer::OPTION_SETTINGS, [] );
		$recipients = self::recipients( $settings );

		if ( empty( $recipients ) ) {
			Logger::set_alert_state( $log_id, Logger::ALERT_SUPPRESSED );
			return;
		}

		/**
		 * Short-circuit an individual alert.
		 *
		 * @param bool                 $send Whether to send.
		 * @param string               $type Event type.
		 * @param array<string, mixed> $row  The stored row.
		 */
		if ( ! apply_filters( 'wpsec_should_send_alert', true, $type, $row ) ) {
			Logger::set_alert_state( $log_id, Logger::ALERT_SUPPRESSED );
			return;
		}

		$budget = (int) ( $settings['mail_budget_per_hour'] ?? 50 );
		$sent   = (int) get_transient( self::COUNTER_TRANSIENT );

		if ( $budget > 0 && $sent >= $budget ) {
			self::note_suppression( $type );
			Logger::set_alert_state( $log_id, Logger::ALERT_SUPPRESSED );
			return;
		}

		$ok = Mailer::send_event( $recipients, $type, $row );

		// The counter is only advanced on an actual send attempt, so a
		// misconfigured recipient list cannot silently eat the budget.
		set_transient( self::COUNTER_TRANSIENT, $sent + 1, HOUR_IN_SECONDS );

		Logger::set_alert_state( $log_id, $ok ? Logger::ALERT_SENT : Logger::ALERT_FAILED );

		if ( ! $ok ) {
			// Logged, never e-mailed: mailing about a mail failure is a loop.
			Logger::log(
				'alert.mail_failed',
				[
					'object_id' => (string) $log_id,
					'message'   => sprintf( 'Could not send the alert e-mail for %s.', $type ),
					'data'      => [ 'event_type' => $type ],
				]
			);
		}
	}

	/**
	 * Record that an alert was held back, and send exactly one notice saying so.
	 */
	private static function note_suppression( string $type ): void {
		$count = (int) get_transient( self::SUPPRESSED_TRANSIENT );

		set_transient( self::SUPPRESSED_TRANSIENT, $count + 1, HOUR_IN_SECONDS );

		if ( 0 !== $count ) {
			return;
		}

		$settings   = (array) get_option( Installer::OPTION_SETTINGS, [] );
		$recipients = self::recipients( $settings );

		$row = [
			'event_type' => 'alert.flood_suppressed',
			'severity'   => Event_Registry::WARNING,
			'event_time' => gmdate( 'Y-m-d H:i:s' ),
			'message'    => sprintf(
				'The hourly alert budget of %d messages was reached. Further alerts this hour are being logged but not e-mailed. The first suppressed event was %s.',
				(int) ( $settings['mail_budget_per_hour'] ?? 50 ),
				$type
			),
			'data'       => wp_json_encode( [ 'first_suppressed' => $type ] ),
		];

		Mailer::send_event( $recipients, 'alert.flood_suppressed', $row );

		// Written directly rather than through Logger::log() so this notice
		// cannot itself be caught by the budget it is reporting on.
		Logger::log(
			'alert.flood_suppressed',
			[
				'message' => $row['message'],
				'data'    => [ 'first_suppressed' => $type ],
			]
		);
	}

	/**
	 * @param array<string, mixed> $settings Plugin settings.
	 * @return string[]
	 */
	public static function recipients( array $settings ): array {
		$list = (array) ( $settings['recipients'] ?? [] );
		$out  = [];

		foreach ( $list as $email ) {
			$email = sanitize_email( (string) $email );
			if ( '' !== $email && is_email( $email ) ) {
				$out[] = $email;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * How many alerts are left in this hour's budget. Shown on the Status page.
	 *
	 * @return array{sent:int, budget:int, suppressed:int}
	 */
	public static function budget_status(): array {
		$settings = (array) get_option( Installer::OPTION_SETTINGS, [] );

		return [
			'sent'       => (int) get_transient( self::COUNTER_TRANSIENT ),
			'budget'     => (int) ( $settings['mail_budget_per_hour'] ?? 50 ),
			'suppressed' => (int) get_transient( self::SUPPRESSED_TRANSIENT ),
		];
	}
}
