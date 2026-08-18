<?php
/**
 * Authenticated encryption for the TOTP shared secrets.
 *
 * A TOTP secret is a bearer credential: anyone holding it can generate valid
 * codes forever. Stored in plain text it turns any SQL injection, stray backup
 * or shared staging database into a permanent second-factor bypass, so it is
 * sealed with AES-256-GCM under a key derived from the site's salts — which
 * live in wp-config.php, not in the database.
 *
 * Two consequences worth knowing about:
 *
 *   - Rotating SECURE_AUTH_SALT makes every stored secret undecryptable. That
 *     is by design; recovery codes are hashed rather than encrypted precisely
 *     so they still work afterwards and users can re-enrol.
 *   - The database alone is not enough to forge a login. A dump without
 *     wp-config.php yields nothing usable.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Secret_Cipher {

	private const CIPHER = 'aes-256-gcm';

	/** Marks the format, so a future scheme can be told apart from this one. */
	private const PREFIX = 'wpsec1:';

	private const IV_BYTES  = 12;
	private const TAG_BYTES = 16;

	/**
	 * Can secrets be stored safely on this installation?
	 *
	 * Without OpenSSL there is no safe place to put a TOTP secret, so the
	 * feature refuses to switch on rather than storing one in the clear.
	 */
	public static function is_available(): bool {
		return function_exists( 'openssl_encrypt' )
			&& in_array( self::CIPHER, (array) openssl_get_cipher_methods(), true );
	}

	/**
	 * @return string The sealed value, or '' when it could not be sealed.
	 */
	public static function encrypt( string $plaintext ): string {
		if ( '' === $plaintext || ! self::is_available() ) {
			return '';
		}

		$iv  = random_bytes( self::IV_BYTES );
		$tag = '';

		$ciphertext = openssl_encrypt(
			$plaintext,
			self::CIPHER,
			self::key(),
			OPENSSL_RAW_DATA,
			$iv,
			$tag,
			'',
			self::TAG_BYTES
		);

		if ( ! is_string( $ciphertext ) || '' === $ciphertext ) {
			return '';
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- transport encoding for binary ciphertext going into a text column, not obfuscation.
		return self::PREFIX . base64_encode( $iv . $tag . $ciphertext );
	}

	/**
	 * @return string The plaintext, or '' when the value is missing, tampered
	 *                with, or was sealed under different salts.
	 */
	public static function decrypt( string $blob ): string {
		if ( ! str_starts_with( $blob, self::PREFIX ) || ! self::is_available() ) {
			return '';
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- reverses our own storage encoding above; strict mode rejects anything malformed.
		$raw = base64_decode( substr( $blob, strlen( self::PREFIX ) ), true );

		if ( ! is_string( $raw ) || strlen( $raw ) <= self::IV_BYTES + self::TAG_BYTES ) {
			return '';
		}

		$iv         = substr( $raw, 0, self::IV_BYTES );
		$tag        = substr( $raw, self::IV_BYTES, self::TAG_BYTES );
		$ciphertext = substr( $raw, self::IV_BYTES + self::TAG_BYTES );

		$plaintext = openssl_decrypt( $ciphertext, self::CIPHER, self::key(), OPENSSL_RAW_DATA, $iv, $tag );

		// GCM authenticates as well as encrypts: a false here means the stored
		// value was altered, not merely that the key is wrong.
		return is_string( $plaintext ) ? $plaintext : '';
	}

	private static function key(): string {
		return hash_hkdf( 'sha256', wp_salt( 'secure_auth' ), 32, 'wpsec-2fa-secret' );
	}
}
