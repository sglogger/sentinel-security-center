<?php
/**
 * Hardening screen — the current posture, and what would improve it.
 *
 * Read-only. Nothing on this page changes anything; every recommendation says
 * where the change is made and links to the section of the official WordPress
 * hardening guide it comes from.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$wpsec_checks  = Hardening::checks();
$wpsec_summary = Hardening::summary();

$wpsec_badges = [
	Hardening::OK   => [ '#00a32a', __( 'Good', 'sentinel-security-center' ) ],
	Hardening::WARN => [ '#dba617', __( 'Worth fixing', 'sentinel-security-center' ) ],
	Hardening::FAIL => [ '#d63638', __( 'Fix this', 'sentinel-security-center' ) ],
	Hardening::INFO => [ '#2271b1', __( 'Your call', 'sentinel-security-center' ) ],
];

$wpsec_by_group = [];

foreach ( $wpsec_checks as $wpsec_check ) {
	$wpsec_by_group[ $wpsec_check['group'] ][] = $wpsec_check;
}
?>
<div class="wrap">
	<h1><?php esc_html_e( 'Hardening', 'sentinel-security-center' ); ?></h1>

	<p>
		<?php esc_html_e( 'What this installation currently looks like to someone trying to get into it. Nothing on this page changes anything — each item says where the change is made and links to the section of the official WordPress hardening guide it comes from, so you can check the advice against the source.', 'sentinel-security-center' ); ?>
	</p>

	<p>
		<a href="<?php echo esc_url( Hardening::doc_url() ); ?>" target="_blank" rel="noopener noreferrer">
			<?php esc_html_e( 'Hardening WordPress — developer.wordpress.org', 'sentinel-security-center' ); ?>
		</a>
	</p>

	<table class="widefat" style="max-width:900px;margin-bottom:24px;">
		<tbody>
			<tr>
				<td style="font-size:15px;">
					<strong style="color:#00a32a;"><?php echo esc_html( (string) $wpsec_summary['ok'] ); ?></strong>
					<?php esc_html_e( 'good', 'sentinel-security-center' ); ?>
					&nbsp;·&nbsp;
					<strong style="color:#d63638;"><?php echo esc_html( (string) $wpsec_summary['fail'] ); ?></strong>
					<?php esc_html_e( 'to fix', 'sentinel-security-center' ); ?>
					&nbsp;·&nbsp;
					<strong style="color:#dba617;"><?php echo esc_html( (string) $wpsec_summary['warn'] ); ?></strong>
					<?php esc_html_e( 'worth fixing', 'sentinel-security-center' ); ?>
					&nbsp;·&nbsp;
					<strong style="color:#2271b1;"><?php echo esc_html( (string) $wpsec_summary['info'] ); ?></strong>
					<?php esc_html_e( 'your call', 'sentinel-security-center' ); ?>
				</td>
			</tr>
		</tbody>
	</table>

	<p class="description" style="max-width:900px;">
		<?php esc_html_e( '"Your call" is not a failing grade. Those are the decisions that depend on how the site is run — a badge either way would be dishonest, so the trade-off is spelled out instead.', 'sentinel-security-center' ); ?>
	</p>

	<?php foreach ( Hardening::groups() as $wpsec_group => $wpsec_group_label ) : ?>
		<?php if ( empty( $wpsec_by_group[ $wpsec_group ] ) ) : ?>
			<?php continue; ?>
		<?php endif; ?>

		<h2><?php echo esc_html( $wpsec_group_label ); ?></h2>
		<table class="widefat striped" style="margin-bottom:24px;">
			<thead>
				<tr>
					<th style="width:110px;"><?php esc_html_e( 'Status', 'sentinel-security-center' ); ?></th>
					<th style="width:260px;"><?php esc_html_e( 'Check', 'sentinel-security-center' ); ?></th>
					<th><?php esc_html_e( 'What is true now, and what to do', 'sentinel-security-center' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $wpsec_by_group[ $wpsec_group ] as $wpsec_check ) : ?>
				<?php $wpsec_badge = $wpsec_badges[ $wpsec_check['status'] ]; ?>
				<tr>
					<td>
						<strong style="color:<?php echo esc_attr( $wpsec_badge[0] ); ?>;">
							<?php echo esc_html( $wpsec_badge[1] ); ?>
						</strong>
					</td>
					<td><strong><?php echo esc_html( $wpsec_check['label'] ); ?></strong></td>
					<td>
						<p style="margin:0 0 6px;"><?php echo esc_html( $wpsec_check['value'] ); ?></p>
						<?php if ( '' !== $wpsec_check['advice'] ) : ?>
							<p class="description" style="margin:0 0 6px;"><?php echo esc_html( $wpsec_check['advice'] ); ?></p>
						<?php endif; ?>
						<p style="margin:0;"><small>
							<a href="<?php echo esc_url( Hardening::doc_url( $wpsec_check['doc'] ) ); ?>" target="_blank" rel="noopener noreferrer">
								<?php esc_html_e( 'Reference: Hardening WordPress', 'sentinel-security-center' ); ?>
							</a>
						</small></p>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endforeach; ?>

	<h2><?php esc_html_e( 'What is deliberately not checked here', 'sentinel-security-center' ); ?></h2>
	<p style="max-width:900px;">
		<?php esc_html_e( 'The guide also covers things no plugin can see from inside PHP: whether your host keeps its software current, whether the machine you administer the site from is clean, whether you connect over SFTP rather than FTP, and what privileges the database user actually holds. Those are worth reading through even though nothing on this page can grade them.', 'sentinel-security-center' ); ?>
	</p>
	<ul style="max-width:900px;list-style:disc;margin-left:20px;">
		<li><a href="<?php echo esc_url( Hardening::doc_url( 'web-server-vulnerabilities' ) ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Web server and shared hosting', 'sentinel-security-center' ); ?></a></li>
		<li><a href="<?php echo esc_url( Hardening::doc_url( 'ftp' ) ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'FTP versus SFTP', 'sentinel-security-center' ); ?></a></li>
		<li><a href="<?php echo esc_url( Hardening::doc_url( 'restricting-database-user-privileges' ) ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Restricting database user privileges', 'sentinel-security-center' ); ?></a></li>
		<li><a href="<?php echo esc_url( Hardening::doc_url( 'securing-wp-includes' ) ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Blocking direct requests to wp-includes', 'sentinel-security-center' ); ?></a></li>
		<li><a href="<?php echo esc_url( Hardening::doc_url( 'firewall' ) ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Putting a firewall in front of the site', 'sentinel-security-center' ); ?></a></li>
	</ul>
</div>
