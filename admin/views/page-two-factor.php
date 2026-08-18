<?php
/**
 * Two-factor setup screen, for the signed-in user's own account.
 *
 * Variables are provided by Two_Factor_Admin::render().
 *
 * @package WPSecurityCenter
 *
 * @var \WP_User $wpsec_user       The current user.
 * @var bool     $wpsec_available  Whether the feature can be used at all.
 * @var bool     $wpsec_active     Whether this account already has a factor.
 * @var int      $wpsec_left       Unused recovery codes.
 * @var bool     $wpsec_required   Whether policy requires it for this user.
 * @var bool     $wpsec_setting_up Whether the enrolment step is showing.
 * @var string   $wpsec_secret     The pending secret, base32.
 * @var string   $wpsec_uri        The otpauth:// provisioning URI.
 * @var string   $wpsec_svg        The QR code as inline SVG, or ''.
 * @var string[] $wpsec_new_codes  Recovery codes to display exactly once.
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap">
	<h1><?php esc_html_e( 'Two-factor authentication', 'sentinel-security-center' ); ?></h1>

	<?php Two_Factor_Admin::render_notice(); ?>

	<?php if ( ! $wpsec_available ) : ?>

		<div class="notice notice-error"><p>
			<?php esc_html_e( 'Two-factor authentication is unavailable on this installation. Either it is switched off in the Security Center settings, or PHP has no OpenSSL support — without it there is nowhere safe to keep the shared secret, so the feature refuses to run rather than store it in the clear.', 'sentinel-security-center' ); ?>
		</p></div>

	<?php else : ?>

		<?php if ( ! empty( $wpsec_new_codes ) ) : ?>
			<div class="notice notice-warning">
				<h2 style="margin-bottom:4px;"><?php esc_html_e( 'Your recovery codes', 'sentinel-security-center' ); ?></h2>
				<p><?php esc_html_e( 'Each code works once. Keep them somewhere you can reach without this site and without your phone — a password manager, or printed and filed. This is the only time they are shown.', 'sentinel-security-center' ); ?></p>
				<p><code style="display:inline-block;padding:10px 16px;line-height:1.9;font-size:14px;">
					<?php foreach ( $wpsec_new_codes as $wpsec_code ) : ?>
						<?php echo esc_html( $wpsec_code ); ?><br>
					<?php endforeach; ?>
				</code></p>
			</div>
		<?php endif; ?>

		<?php if ( $wpsec_active ) : ?>

			<h2><?php esc_html_e( 'Status', 'sentinel-security-center' ); ?></h2>
			<p>
				<strong><?php esc_html_e( 'On.', 'sentinel-security-center' ); ?></strong>
				<?php
				echo esc_html(
					sprintf(
						/* translators: %d: number of unused recovery codes */
						_n( '%d unused recovery code remains.', '%d unused recovery codes remain.', $wpsec_left, 'sentinel-security-center' ),
						$wpsec_left
					)
				);
				?>
			</p>

			<?php if ( $wpsec_left <= 2 ) : ?>
				<div class="notice notice-warning inline"><p>
					<?php esc_html_e( 'You are nearly out of recovery codes. Generate a new set now, while you can still sign in.', 'sentinel-security-center' ); ?>
				</p></div>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Recovery codes', 'sentinel-security-center' ); ?></h2>
			<p><?php esc_html_e( 'Generating a new set immediately invalidates the old one.', 'sentinel-security-center' ); ?></p>
			<?php Two_Factor_Admin::form_open( 'regenerate' ); ?>
				<?php submit_button( __( 'Generate new recovery codes', 'sentinel-security-center' ), 'secondary', 'submit', false ); ?>
			</form>

			<h2><?php esc_html_e( 'Turn it off', 'sentinel-security-center' ); ?></h2>
			<p>
				<?php esc_html_e( 'Your account goes back to being protected by the password alone.', 'sentinel-security-center' ); ?>
				<?php if ( $wpsec_required ) : ?>
					<strong><?php esc_html_e( 'This site requires administrators to use two-factor authentication, so you will be asked to set it up again at your next sign-in.', 'sentinel-security-center' ); ?></strong>
				<?php endif; ?>
			</p>
			<?php Two_Factor_Admin::form_open( 'disable' ); ?>
				<?php submit_button( __( 'Turn off two-factor authentication', 'sentinel-security-center' ), 'delete', 'submit', false ); ?>
			</form>

		<?php elseif ( $wpsec_setting_up ) : ?>

			<h2><?php esc_html_e( 'Step 1 — add the account to your authenticator', 'sentinel-security-center' ); ?></h2>
			<p><?php esc_html_e( 'Scan this with any authenticator app: 1Password, Bitwarden, Aegis, Google Authenticator, Microsoft Authenticator — they all speak the same standard.', 'sentinel-security-center' ); ?></p>

			<?php if ( '' !== $wpsec_svg ) : ?>
				<p>
				<?php
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- SVG rendered locally by the bundled QR encoder from a URI built above.
				echo $wpsec_svg;
				?>
				</p>
			<?php endif; ?>

			<p><?php esc_html_e( 'Or type this key in by hand:', 'sentinel-security-center' ); ?></p>
			<p><code style="display:inline-block;padding:8px 12px;font-size:14px;letter-spacing:1px;">
				<?php echo esc_html( Totp::format_secret( $wpsec_secret ) ); ?>
			</code></p>

			<?php if ( '' !== $wpsec_uri ) : ?>
				<p><a href="<?php echo esc_url( $wpsec_uri, [ 'otpauth' ] ); ?>"><?php esc_html_e( 'Open in an authenticator app on this device', 'sentinel-security-center' ); ?></a></p>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Step 2 — prove it worked', 'sentinel-security-center' ); ?></h2>
			<p><?php esc_html_e( 'Nothing is switched on until a code from the app is accepted, so a mistyped key cannot lock you out.', 'sentinel-security-center' ); ?></p>
			<?php Two_Factor_Admin::form_open( 'confirm' ); ?>
				<p>
					<label for="wpsec_code"><?php esc_html_e( 'Six-digit code', 'sentinel-security-center' ); ?></label><br>
					<input type="text" id="wpsec_code" name="wpsec_code" class="regular-text" inputmode="numeric"
						autocomplete="one-time-code" autocapitalize="off" autocorrect="off" spellcheck="false" required>
				</p>
				<?php submit_button( __( 'Switch on two-factor authentication', 'sentinel-security-center' ), 'primary', 'submit', false ); ?>
			</form>

		<?php else : ?>

			<h2><?php esc_html_e( 'Status', 'sentinel-security-center' ); ?></h2>
			<p>
				<strong><?php esc_html_e( 'Off.', 'sentinel-security-center' ); ?></strong>
				<?php esc_html_e( 'Anyone who learns your password can sign in as you. An authenticator app closes that off.', 'sentinel-security-center' ); ?>
			</p>

			<?php if ( $wpsec_required ) : ?>
				<div class="notice notice-warning inline"><p>
					<?php
					$wpsec_deadline = Two_Factor::grace_ends();
					echo esc_html(
						$wpsec_deadline > time()
							? sprintf(
								/* translators: %s: formatted date */
								__( 'This site requires administrators to use two-factor authentication from %s.', 'sentinel-security-center' ),
								wp_date( (string) get_option( 'date_format' ), $wpsec_deadline )
							)
							: __( 'This site requires administrators to use two-factor authentication.', 'sentinel-security-center' )
					);
					?>
				</p></div>
			<?php endif; ?>

			<?php Two_Factor_Admin::form_open( 'start' ); ?>
				<?php submit_button( __( 'Set up two-factor authentication', 'sentinel-security-center' ), 'primary', 'submit', false ); ?>
			</form>

		<?php endif; ?>

		<?php if ( Two_Factor::email_fallback_enabled() ) : ?>
			<h2><?php esc_html_e( 'If you lose your authenticator', 'sentinel-security-center' ); ?></h2>
			<p><?php esc_html_e( 'Use a recovery code. If those are gone too, the sign-in screen can e-mail a one-time code to the address on this account — which means whoever reads that mailbox can sign in as you, so treat it as the last resort it is. If everything is lost, another administrator can reset the second factor for your account.', 'sentinel-security-center' ); ?></p>
		<?php else : ?>
			<h2><?php esc_html_e( 'If you lose your authenticator', 'sentinel-security-center' ); ?></h2>
			<p><?php esc_html_e( 'Use a recovery code. The e-mail fallback is switched off on this site, so if the recovery codes are gone as well, another administrator has to reset the second factor for your account.', 'sentinel-security-center' ); ?></p>
		<?php endif; ?>

	<?php endif; ?>
</div>
