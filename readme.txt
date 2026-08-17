=== WP Security Center ===
Contributors: glogger
Tags: security, activity log, audit log, geoblocking, file integrity
Requires at least: 6.5
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security monitoring and alerting for WordPress: plugin and theme changes, administrator and role changes, configuration changes, filesystem integrity, and geo-aware login control.

== Description ==

WP Security Center watches the things an attacker actually has to touch in order to keep a foothold in a WordPress site, records them in a searchable log, and e-mails you immediately when something matters.

It is built around two goals that pull against each other: miss as little as possible, and produce as few false alarms as possible. Every event type can be set individually to immediate e-mail, log only, or off. Login blocking always starts in monitor mode so you can see what a rule would have done before you arm it.

**What is monitored**

* Plugins: installed, activated, deactivated, updated, deleted, and plugins that appear without a matching install (an SFTP drop).
* Themes: installed, activated, updated, deleted.
* Users and administrators: created, deleted, role changed, promoted to administrator, demoted, e-mail changed, password changed or reset — including changes an administrator makes to their own account.
* User records altered directly in the database, outside WordPress, detected by a periodic reconciliation scan.
* Configuration: critical options such as siteurl, home, admin_email, users_can_register and default_role; wp-config.php and .htaccess changes; WordPress core files verified against the official checksums; cron jobs; newly appearing must-use plugins; XML-RPC and file-editor state; application passwords.
* Filesystem: new or changed files in wp-content/mu-plugins/, and any PHP file under wp-content/uploads/ — where one never belongs. New PHP files are additionally checked against common backdoor signatures.
* Logins: a successful login from a country outside your allow list, with optional blocking.

**The plugin never modifies, quarantines or deletes a scanned file.** It reports, and leaves recovery to you.

**Geo-aware login control**

Country is resolved from your CDN or reverse proxy's country header when the request demonstrably came through it, otherwise from a local MaxMind GeoLite2 database. No external API is called during login. X-Forwarded-For is only trusted when the connecting address is in your configured trusted-proxy list, so the client IP cannot be spoofed.

Because locking yourself out is the real risk, there are four independent ways back in: monitor mode is the default, an IP/CIDR allow list is exempt from blocking, a wp-config.php constant disables blocking outright, and every blocked login e-mails you a single-use, time-limited link that unblocks your current IP.

**Administrator-only**

The plugin adds no front-end output, no REST routes and no shortcodes. Its menu, notices, assets and actions all require the manage_options capability, and a blocked login is indistinguishable from an ordinary wrong password.

== Installation ==

1. Upload the plugin to `/wp-content/plugins/wp-security-center` or install the ZIP from the Plugins screen.
2. Activate it. WordPress Multisite is not supported and activation will stop with an explanation.
3. Open Security Center → Settings and set your alert recipients.
4. For country-based rules, add a MaxMind GeoLite2 licence key (free) and download the database, or configure your CDN's country header.
5. Leave blocking in monitor mode for a few days, review the log, then arm it.

== Frequently Asked Questions ==

= Does it block brute-force login attempts? =

No, by design. Failed logins are not processed at all — no counters, no thresholds, no lockouts. Rate limiting belongs in your firewall, CDN or fail2ban, where it can act before the request reaches PHP. This plugin only reacts to logins that actually succeeded.

= Will country blocking stop a determined attacker? =

No. An attacker using a VPN endpoint inside an allowed country resolves to that country and passes. There is no VPN or Tor detection. Treat this control as something that removes opportunistic foreign traffic, not as a boundary.

= What happens if the GeoIP database is missing or broken? =

An individual IP that cannot be resolved is treated as not allowed and is blocked. But if the lookup subsystem as a whole is unavailable, blocking automatically falls back to monitor mode and raises a critical alert, so a deleted database file can never lock you out.

= Can I get locked out? =

Blocking is off until you arm it, and the settings screen refuses to arm it without a working database. If it does happen: the `WPSEC_DISABLE_BLOCKING` constant in wp-config.php disables blocking immediately, and the alert e-mail for every blocked login contains a single-use bypass link.

= Are logins over the REST API or XML-RPC blocked too? =

Not by default. Application passwords and XML-RPC authenticate through the same WordPress hook as an interactive login, so blocking them would silently break integrations hosted abroad. There is a setting to include them.

= Does it support Multisite? =

No. Activation on a network stops with a message rather than misbehaving quietly.

== Changelog ==

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.0.0 =
Initial release.
