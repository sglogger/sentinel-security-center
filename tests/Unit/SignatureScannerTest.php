<?php
/**
 * Backdoor heuristics.
 *
 * The false-negative tests matter as much as the true positives: a scanner that
 * flags ordinary plugin code trains its owner to ignore it, which is worse than
 * no scanner at all.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPSecurityCenter\Signature_Scanner;

final class SignatureScannerTest extends TestCase {

	private const THRESHOLD = 60;

	/**
	 * @dataProvider malicious_provider
	 */
	public function test_known_backdoor_patterns_score_above_the_threshold( string $label, string $code ): void {
		$result = Signature_Scanner::scan( $code );

		$this->assertGreaterThanOrEqual(
			self::THRESHOLD,
			$result['score'],
			"{$label} should be reported (scored {$result['score']})"
		);
		$this->assertNotEmpty( $result['matches'] );
	}

	/**
	 * @return array<string, array{0:string, 1:string}>
	 */
	public static function malicious_provider(): array {
		return [
			'eval of base64'     => [ 'eval of base64', '<?php eval(base64_decode($_POST["c"]));' ],
			'eval of gzinflate'  => [ 'eval of gzinflate', '<?php eval(gzinflate(base64_decode("abc")));' ],
			'eval of request'    => [ 'eval of request', '<?php eval($_REQUEST["x"]);' ],
			'assert of request'  => [ 'assert of request', '<?php assert($_POST["a"]);' ],
			'preg_replace /e'    => [ 'preg_replace /e', '<?php preg_replace("/.*/e", $_GET["c"], "");' ],
			'variable function'  => [ 'variable function', '<?php $_GET["f"]("whoami");' ],
			'shell from request' => [ 'shell from request', '<?php system($_GET["cmd"]);' ],
			'known shell banner' => [ 'known shell banner', '<?php /* WSO 2.5 FilesMan */ ?>' ],
			'chr obfuscation'    => [
				'chr obfuscation',
				'<?php $x = chr(101).chr(118).chr(97).chr(108).chr(40).chr(36).chr(97); eval(base64_decode($x));',
			],
		];
	}

	/**
	 * @dataProvider benign_provider
	 */
	public function test_ordinary_code_stays_below_the_threshold( string $label, string $code ): void {
		$result = Signature_Scanner::scan( $code );

		$this->assertLessThan(
			self::THRESHOLD,
			$result['score'],
			"{$label} must not be reported (scored {$result['score']}: " . implode( ', ', $result['matches'] ) . ')'
		);
	}

	/**
	 * @return array<string, array{0:string, 1:string}>
	 */
	public static function benign_provider(): array {
		return [
			'plugin header'            => [
				'a normal plugin header',
				"<?php\n/**\n * Plugin Name: Example\n */\nadd_action('init', function () { return true; });",
			],
			'the word system in prose' => [
				'the word system in a comment',
				"<?php\n// This talks to the payment system and the booking system.\n\$x = 1;",
			],
			'ordinary base64 use'      => [
				'a short base64 decode',
				'<?php $token = base64_decode($stored_token); return $token;',
			],
			'file upload handling'     => [
				'a legitimate upload handler',
				'<?php if (!empty($_FILES["f"])) { move_uploaded_file($_FILES["f"]["tmp_name"], $dest); }',
			],
			'wordpress api use'        => [
				'plain WordPress code',
				'<?php $u = wp_get_current_user(); if (user_can($u, "edit_posts")) { wp_send_json_success(); }',
			],
		];
	}

	public function test_score_is_capped_at_one_hundred(): void {
		$code = '<?php eval(base64_decode($_POST["a"])); assert($_POST["b"]); system($_GET["c"]); /* WSO FilesMan */';

		$this->assertSame( 100, Signature_Scanner::scan( $code )['score'] );
	}

	public function test_clean_code_scores_zero(): void {
		$result = Signature_Scanner::scan( '<?php return 42;' );

		$this->assertSame( 0, $result['score'] );
		$this->assertSame( [], $result['matches'] );
	}

	public function test_matches_are_described_in_words(): void {
		$result = Signature_Scanner::scan( '<?php eval(base64_decode("x"));' );

		$described = Signature_Scanner::describe( $result['matches'] );

		$this->assertNotEmpty( $described );
		$this->assertStringContainsString( 'eval', strtolower( implode( ' ', $described ) ) );
	}

	public function test_unknown_rule_ids_are_ignored_when_describing(): void {
		$this->assertSame( [], Signature_Scanner::describe( [ 'no_such_rule' ] ) );
	}
}
