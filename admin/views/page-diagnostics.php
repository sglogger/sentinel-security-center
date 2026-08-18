<?php
/**
 * Diagnostics screen.
 *
 * Answers the one question that decides whether any of the location rules work
 * correctly: which address does this site think you are coming from, and why?
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$wpsec_geo    = (array) get_option( Installer::OPTION_GEO, [] );
$wpsec_detail = Context::ip_detail();
$wpsec_ip     = $wpsec_detail['ip'];
$wpsec_here   = Country_Resolver::resolve( $wpsec_ip );

$wpsec_decision = Access_Policy::decide(
	[
		'ip'                => $wpsec_ip,
		'country'           => $wpsec_here['country'],
		'enabled'           => ! empty( $wpsec_geo['enabled'] ),
		'mode'              => (string) ( $wpsec_geo['mode'] ?? 'monitor' ),
		'countries'         => (array) ( $wpsec_geo['countries'] ?? [] ),
		'allow_ips'         => Allowlist::stat(),
		'temp_allow_ips'    => Allowlist::temporary(),
		'kill_switch'       => Login_Guard::kill_switch_active(),
		'geoip_healthy'     => Country_Resolver::is_healthy(),
		'is_api_auth'       => false,
		'apply_to_api_auth' => ! empty( $wpsec_geo['apply_to_api_auth'] ),
	]
);

// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only what-if calculation.
$wpsec_test_ip = isset( $_GET['test_ip'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['test_ip'] ) ) : '';
?>
<div class="wrap">
	<h1><?php esc_html_e( 'Diagnostics', 'wp-security-center' ); ?></h1>

	<h2><?php esc_html_e( 'How this request was seen', 'wp-security-center' ); ?></h2>
	<table class="widefat striped" style="max-width:900px;">
		<tbody>
			<tr>
				<th style="width:280px;"><?php esc_html_e( 'Connecting address (REMOTE_ADDR)', 'wp-security-center' ); ?></th>
				<td><code><?php echo esc_html( (string) ( $wpsec_detail['remote'] ?? '—' ) ); ?></code></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Is it a trusted proxy?', 'wp-security-center' ); ?></th>
				<td>
					<?php if ( $wpsec_detail['remote_trusted'] ) : ?>
						<strong style="color:#00a32a;"><?php esc_html_e( 'Yes — forwarding headers are being honoured', 'wp-security-center' ); ?></strong>
					<?php else : ?>
						<strong><?php esc_html_e( 'No — forwarding headers are ignored entirely', 'wp-security-center' ); ?></strong>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Resolved client address', 'wp-security-center' ); ?></th>
				<td>
					<code><?php echo esc_html( (string) ( $wpsec_ip ?? '—' ) ); ?></code>
					<?php if ( '' !== (string) $wpsec_detail['source'] ) : ?>
						<small>(<?php echo esc_html( (string) $wpsec_detail['source'] ); ?>)</small>
					<?php endif; ?>
				</td>
			</tr>
			<?php if ( ! empty( $wpsec_detail['chain'] ) ) : ?>
			<tr>
				<th><?php esc_html_e( 'Forwarded-for chain', 'wp-security-center' ); ?></th>
				<td>
					<?php foreach ( $wpsec_detail['chain'] as $wpsec_hop ) : ?>
						<?php $wpsec_hop_trusted = Ip_Matcher::in_any( $wpsec_hop, (array) ( $wpsec_geo['trusted_proxies'] ?? [] ) ); ?>
						<code><?php echo esc_html( $wpsec_hop ); ?></code>
						<small><?php echo $wpsec_hop_trusted ? esc_html__( '(trusted proxy)', 'wp-security-center' ) : esc_html__( '(not trusted)', 'wp-security-center' ); ?></small><br>
					<?php endforeach; ?>
				</td>
			</tr>
			<?php endif; ?>
			<tr>
				<th><?php esc_html_e( 'Country', 'wp-security-center' ); ?></th>
				<td>
					<strong><?php echo esc_html( Country_Resolver::country_name( $wpsec_here['country'] ) ); ?></strong>
					<code><?php echo esc_html( $wpsec_here['country'] ); ?></code>
					<small>(
					<?php
						echo esc_html(
							'header' === $wpsec_here['source']
								? __( 'from the CDN country header', 'wp-security-center' )
								: ( 'database' === $wpsec_here['source']
									? __( 'from the local GeoIP database', 'wp-security-center' )
									: __( 'no source available', 'wp-security-center' ) )
						);
						?>
					)</small>
				</td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'What would happen on login', 'wp-security-center' ); ?></th>
				<td>
					<?php
					$wpsec_labels = [
						Access_Policy::ALLOW   => [ '#00a32a', __( 'Allowed', 'wp-security-center' ) ],
						Access_Policy::MONITOR => [ '#dba617', __( 'Allowed, but reported', 'wp-security-center' ) ],
						Access_Policy::BLOCK   => [ '#d63638', __( 'BLOCKED', 'wp-security-center' ) ],
					];
					$wpsec_label  = $wpsec_labels[ $wpsec_decision['action'] ] ?? [ '#646970', $wpsec_decision['action'] ];
					?>
					<strong style="color:<?php echo esc_attr( $wpsec_label[0] ); ?>;"><?php echo esc_html( $wpsec_label[1] ); ?></strong>
					<br><small>
					<?php
						/* translators: %s: internal name of the rule that decided */
						printf( esc_html__( 'Decided by: %s', 'wp-security-center' ), '<code>' . esc_html( $wpsec_decision['rail'] ) . '</code>' );
					?>
					</small>
				</td>
			</tr>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'What would happen for another address?', 'wp-security-center' ); ?></h2>
	<form method="get">
		<input type="hidden" name="page" value="<?php echo esc_attr( Admin::MENU_DIAGNOSTICS ); ?>">
		<input type="text" name="test_ip" class="regular-text code" value="<?php echo esc_attr( $wpsec_test_ip ); ?>" placeholder="89.160.20.112">
		<?php submit_button( __( 'Test', 'wp-security-center' ), 'secondary', 'submit', false ); ?>
	</form>

	<?php if ( '' !== $wpsec_test_ip ) : ?>
		<?php
		$wpsec_norm = Ip_Matcher::normalise( $wpsec_test_ip );

		if ( null === $wpsec_norm ) :
			?>
			<p style="color:#d63638;"><?php esc_html_e( 'That is not a valid IP address.', 'wp-security-center' ); ?></p>
		<?php else : ?>
			<?php
			$wpsec_test_country = Country_Resolver::lookup( $wpsec_norm );

			$wpsec_test_decision = Access_Policy::decide(
				[
					'ip'                => $wpsec_norm,
					'country'           => $wpsec_test_country,
					'enabled'           => ! empty( $wpsec_geo['enabled'] ),
					'mode'              => (string) ( $wpsec_geo['mode'] ?? 'monitor' ),
					'countries'         => (array) ( $wpsec_geo['countries'] ?? [] ),
					'allow_ips'         => Allowlist::stat(),
					'temp_allow_ips'    => Allowlist::temporary(),
					'kill_switch'       => Login_Guard::kill_switch_active(),
					'geoip_healthy'     => Country_Resolver::is_healthy(),
					'is_api_auth'       => false,
					'apply_to_api_auth' => ! empty( $wpsec_geo['apply_to_api_auth'] ),
				]
			);
			?>
			<table class="widefat striped" style="max-width:900px;">
				<tbody>
					<tr><th style="width:280px;"><?php esc_html_e( 'Address', 'wp-security-center' ); ?></th><td><code><?php echo esc_html( $wpsec_norm ); ?></code></td></tr>
					<tr><th><?php esc_html_e( 'Country', 'wp-security-center' ); ?></th><td><?php echo esc_html( Country_Resolver::country_name( $wpsec_test_country ) ); ?> <code><?php echo esc_html( $wpsec_test_country ); ?></code></td></tr>
					<tr><th><?php esc_html_e( 'Verdict', 'wp-security-center' ); ?></th><td><strong><?php echo esc_html( $wpsec_test_decision['action'] ); ?></strong> — <code><?php echo esc_html( $wpsec_test_decision['rail'] ); ?></code></td></tr>
					<tr><th><?php esc_html_e( 'Rules consulted', 'wp-security-center' ); ?></th><td><code><?php echo esc_html( implode( ' → ', $wpsec_test_decision['trace'] ) ); ?></code></td></tr>
				</tbody>
			</table>
		<?php endif; ?>
	<?php endif; ?>

	<h2><?php esc_html_e( 'Incoming headers', 'wp-security-center' ); ?></h2>
	<p class="description"><?php esc_html_e( 'Everything the web server passed to PHP for this request. Use it to work out which header your proxy actually sets.', 'wp-security-center' ); ?></p>
	<table class="widefat striped" style="max-width:900px;">
		<tbody>
		<?php
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- displayed escaped, never used for logic.
		$wpsec_server = (array) $_SERVER;
		ksort( $wpsec_server );

		foreach ( $wpsec_server as $wpsec_key => $wpsec_value ) :
			if ( ! is_string( $wpsec_value ) ) {
				continue;
			}
			if ( ! str_starts_with( (string) $wpsec_key, 'HTTP_' ) && ! in_array( $wpsec_key, [ 'REMOTE_ADDR', 'SERVER_ADDR', 'REQUEST_SCHEME' ], true ) ) {
				continue;
			}
			// Never render the session cookie back to the screen.
			if ( 'HTTP_COOKIE' === $wpsec_key ) {
				continue;
			}
			?>
			<tr>
				<th style="width:280px;"><code><?php echo esc_html( (string) $wpsec_key ); ?></code></th>
				<td><code><?php echo esc_html( mb_substr( $wpsec_value, 0, 300 ) ); ?></code></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
</div>
