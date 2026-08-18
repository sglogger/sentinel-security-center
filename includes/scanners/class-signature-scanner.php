<?php
/**
 * Heuristic detection of common PHP backdoor patterns.
 *
 * Weighted rather than binary, because every individual pattern here has
 * legitimate uses. A single `base64_decode` is unremarkable; `eval` wrapped
 * around one, in a file that also reads straight from $_POST, is not. The
 * threshold is configurable so a site with unusual-but-legitimate code can be
 * calmed down without switching the scanner off.
 *
 * WordPress-free so the rules can be unit-tested against real true and false
 * positives.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Signature_Scanner {

	/**
	 * id => [ pattern, weight, description ]
	 *
	 * @return array<string, array{0:string, 1:int, 2:string}>
	 */
	public static function rules(): array {
		return [
			'eval_encoded'             => [
				'/\beval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|pack)\s*\(/i',
				70,
				'eval() of decoded data',
			],
			'eval_request'             => [
				'/\beval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)\b/i',
				90,
				'eval() of request input',
			],
			'assert_request'           => [
				'/\bassert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b/i',
				90,
				'assert() of request input',
			],
			'preg_replace_e'           => [
				// The /e modifier lives INSIDE the pattern string, in the
				// trailing modifier block after the closing delimiter — not
				// after the PHP string's own closing quote.
				'/preg_replace\s*\(\s*([\'"]).+?[\/#~%|][a-zA-Z]*e[a-zA-Z]*\1/',
				80,
				'preg_replace with the removed /e modifier',
			],
			'create_function'          => [
				'/\bcreate_function\s*\(/i',
				40,
				'create_function(), removed in PHP 8',
			],
			'shell_exec'               => [
				'/\b(shell_exec|passthru|proc_open|popen|system)\s*\(/i',
				40,
				'shell command execution',
			],
			'exec_request'             => [
				'/\b(shell_exec|passthru|system|exec)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b/i',
				90,
				'shell command built from request input',
			],
			'variable_function'        => [
				'/\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(/',
				80,
				'calling a function named by request input',
			],
			'file_write_request'       => [
				'/\bfile_put_contents\s*\(\s*[^,]+,\s*\$_(POST|GET|REQUEST)\b/i',
				70,
				'writing request input to a file',
			],
			'obfuscated_chr'           => [
				'/(chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}/i',
				50,
				'string assembled from chr() calls',
			],
			'long_base64'              => [
				'/[\'"][A-Za-z0-9+\/]{400,}={0,2}[\'"]/',
				40,
				'very long base64 blob',
			],
			'known_shell'              => [
				'/(WSO\s*\d|FilesMan|b374k|c99shell|r57shell|IndoXploit|AnonymousFox|WebShell by)/i',
				95,
				'known web shell banner',
			],
			'hidden_upload'            => [
				'/move_uploaded_file\s*\(\s*\$_FILES/i',
				30,
				'file upload handler',
			],
			'error_suppressed_include' => [
				'/@\s*(include|require)(_once)?\s*\(\s*\$/i',
				40,
				'error-suppressed dynamic include',
			],
		];
	}

	/**
	 * Score a chunk of PHP source.
	 *
	 * @return array{score:int, matches:string[]}
	 */
	public static function scan( string $code ): array {
		$score   = 0;
		$matches = [];

		foreach ( self::rules() as $id => $rule ) {
			[ $pattern, $weight ] = $rule;

			if ( preg_match( $pattern, $code ) ) {
				$score    += $weight;
				$matches[] = $id;
			}
		}

		return [
			'score'   => min( 100, $score ),
			'matches' => $matches,
		];
	}

	/**
	 * Human-readable reasons for a set of matched rule ids.
	 *
	 * @param string[] $ids Matched rule identifiers.
	 * @return string[]
	 */
	public static function describe( array $ids ): array {
		$rules = self::rules();
		$out   = [];

		foreach ( $ids as $id ) {
			if ( isset( $rules[ $id ] ) ) {
				$out[] = $rules[ $id ][2];
			}
		}

		return $out;
	}
}
