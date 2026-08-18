<?php
/**
 * Spreadsheet formula injection guard on the CSV export.
 *
 * The log records hostile input by design — a user name typed into the login
 * form ends up in the export — so the guard is what stands between a security
 * feature and a code-execution vector in the analyst's spreadsheet.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPSecurityCenter\Csv_Exporter;

final class CsvGuardTest extends TestCase {

	/**
	 * @dataProvider cell_provider
	 */
	public function test_guard_cell( string $in, string $expected ): void {
		$this->assertSame( $expected, Csv_Exporter::guard_cell( $in ) );
	}

	/**
	 * @return array<string, array{0:string, 1:string}>
	 */
	public static function cell_provider(): array {
		return [
			'plain text untouched'      => [ 'Login by "admin"', 'Login by "admin"' ],
			'empty untouched'           => [ '', '' ],
			'whitespace only untouched' => [ "  \t ", "  \t " ],
			'ip untouched'              => [ '203.0.113.9', '203.0.113.9' ],
			'formula ='                 => [ '=HYPERLINK("http://evil")', "'=HYPERLINK(\"http://evil\")" ],
			'formula +'                 => [ '+cmd|/C calc', "'+cmd|/C calc" ],
			'formula -'                 => [ '-2+3+cmd', "'-2+3+cmd" ],
			'formula @'                 => [ '@SUM(1)', "'@SUM(1)" ],
			'tab-prefixed formula'      => [ "\t=1+1", "'\t=1+1" ],
			'newline-prefixed formula'  => [ "\n=1+1", "'\n=1+1" ],
			'equals mid-string is fine' => [ 'a=b', 'a=b' ],
		];
	}
}
