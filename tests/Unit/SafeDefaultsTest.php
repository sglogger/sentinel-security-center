<?php
/**
 * Locks in the "safe by default" contract of a fresh install.
 *
 * These assertions are not decoration. A regression in any one of them would
 * silently arm login blocking, or arm it against an unconfigured allow list,
 * on every site that installs or updates the plugin.
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPSecurityCenter\Installer;

final class SafeDefaultsTest extends TestCase {

	public function test_blocking_is_off_after_install(): void {
		$geo = Installer::default_geo();

		$this->assertSame(
			'monitor',
			$geo['mode'],
			'A fresh install must never block logins. Monitor mode gives the admin data before they arm it.'
		);
	}

	public function test_country_allow_list_starts_empty(): void {
		$geo = Installer::default_geo();

		$this->assertSame(
			[],
			$geo['countries'],
			'Shipping a guessed country would be wrong for most sites. An empty list never blocks (rail D).'
		);
	}

	public function test_geo_evaluation_is_on_so_the_admin_sees_data(): void {
		$geo = Installer::default_geo();

		$this->assertTrue(
			$geo['enabled'],
			'Evaluation and logging are on by default; only the blocking action is opt-in.'
		);
	}

	public function test_api_authentication_is_exempt_by_default(): void {
		$geo = Installer::default_geo();

		$this->assertFalse(
			$geo['apply_to_api_auth'],
			'Application passwords and XML-RPC share the authenticate hook. Blocking them by default would silently break REST integrations hosted abroad.'
		);
	}

	public function test_no_trusted_proxies_are_configured_by_default(): void {
		$geo = Installer::default_geo();

		$this->assertSame(
			[],
			$geo['trusted_proxies'],
			'With no trusted proxies the resolver must ignore X-Forwarded-For entirely. Trusting a header out of the box would make the client IP spoofable.'
		);
	}

	public function test_uninstall_preserves_data_by_default(): void {
		$settings = Installer::default_settings();

		$this->assertFalse(
			$settings['delete_data_on_uninstall'],
			'Discarding an audit trail must be an explicit choice, never a default.'
		);
	}

	public function test_a_mail_budget_exists(): void {
		$settings = Installer::default_settings();

		$this->assertGreaterThan(
			0,
			$settings['mail_budget_per_hour'],
			'Alerts are immediate and never digested, so the hourly budget is the only thing standing between a mass finding and a blacklisted mail server.'
		);
	}
}
