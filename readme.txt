=== WP Security Center ===
Contributors: glogger
Tags: security, activity log, audit log, geoblocking, file integrity
Requires at least: 6.5
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 1.1.1
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
* Logins: failed attempts, successful logins, and a login from a country outside your allow list — with optional blocking.
* Two-factor authentication: who switched it on or off, wrong codes submitted after a correct password, and every use of a recovery code or the e-mail fallback.

**The plugin never modifies, quarantines or deletes a scanned file.** It reports, and leaves recovery to you.

**Two-factor authentication**

A one-time code from any authenticator app, asked for after the password is accepted — and the session is only issued once that code is right. Enrolment is per account and voluntary by default; a site setting can require it for administrators, with a grace period whose clock starts when you switch the requirement on.

Shared secrets are encrypted with AES-256-GCM under a key derived from the site salts, so a database dump without wp-config.php is useless. Each code is accepted once, so a code read over your shoulder cannot be replayed. The QR code is drawn on your own server — the secret is never sent to an external QR service.

Recovery, in order: ten single-use recovery codes issued at enrolment; optionally a one-time code mailed to the account address; and failing everything, a reset by another administrator.

**Geo-aware login control**

Country is resolved from your CDN or reverse proxy's country header when the request demonstrably came through it, otherwise from a local MaxMind GeoLite2 database. No external API is called during login. X-Forwarded-For is only trusted when the connecting address is in your configured trusted-proxy list, so the client IP cannot be spoofed.

Because locking yourself out is the real risk, there are four independent ways back in: monitor mode is the default, an IP/CIDR allow list is exempt from blocking, a wp-config.php constant disables blocking outright, and every blocked login e-mails you a single-use, time-limited link that unblocks your current IP.

**Administrator-only**

The plugin adds no front-end output, no REST routes and no shortcodes. Its menu, notices, assets and actions all require the manage_options capability, and a blocked login is indistinguishable from an ordinary wrong password. The one exception is two-factor enrolment: that belongs to the account holder, so the setup screen is reachable by any signed-in user from their own profile — without appearing in the menu for anyone who cannot otherwise see the plugin.

== Installation ==

1. Upload the plugin to `/wp-content/plugins/wp-security-center` or install the ZIP from the Plugins screen.
2. Activate it. WordPress Multisite is not supported and activation will stop with an explanation.
3. Open Security Center → Settings and set your alert recipients.
4. For country-based rules, add a MaxMind GeoLite2 licence key (free) and download the database, or configure your CDN's country header.
5. Leave blocking in monitor mode for a few days, review the log, then arm it.

== Frequently Asked Questions ==

= What happens if I lose my authenticator app? =

Use one of the ten recovery codes issued when you switched two-factor on. If those are gone too and the site has the e-mail fallback enabled, the sign-in screen can mail a one-time code to the address on your account. If everything is lost, any other administrator can reset your second factor from your profile screen — you then set it up again.

The e-mail fallback is off by default on purpose. It means whoever can read that mailbox can finish the sign-in, which on many sites is the same person who controls the hosting account. Turn it on when losing a phone would otherwise mean losing the site; leave it off otherwise. Every code sent and every code used is written to the log.

= Does two-factor cover the REST API and application passwords? =

No. They are non-interactive — there is nobody there to type a code — and an application password is already a separate credential you can revoke on its own. If an account has to be locked down completely, revoke its application passwords as well.

= Does it block brute-force login attempts? =

No, by design. Failed attempts are logged — `login.failed`, at Info and log-only, so a burst of them is visible in the log and searchable by user name and IP — but nothing is enforced: no counters, no thresholds, no lockouts. Rate limiting belongs in your firewall, CDN or fail2ban, where it can act before the request reaches PHP. Every rule this plugin enforces reacts only to logins that actually succeeded.

Set the event to "E-mail" only if you know the site is quiet. On a public site bots guess passwords around the clock, and an inbox that learns to ignore this plugin is worse than no alert at all.

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

= 1.1.1 =
* Fixed: updating from a private GitHub repository failed after the update had already been offered. The release asset was fetched from its browser URL, which cannot carry a token; it is now fetched from the API asset URL with the token and the correct Accept header. Public repositories were unaffected.

= 1.1.0 =
* First functional release. Everything below is new.
* Event log with a filterable admin viewer, search, sorting, per-page control and CSV export of exactly the filtered view.
* Monitoring of plugins and themes: install, activate, deactivate, update, delete, auto-update, and plugins that appear on disk without an install.
* Monitoring of users and administrators: creation, deletion, role change, promotion and demotion, e-mail and password changes, application passwords, and changes an administrator makes to their own account.
* Detection of user records altered directly in the database, by hourly reconciliation against a stored baseline. This is the only way to see a changed login name, which WordPress itself provides no path for.
* Configuration monitoring: critical options, wp-config.php and .htaccess hashes, WordPress core files against the official checksums, cron jobs, new must-use plugins, XML-RPC and file-editor state.
* File integrity for wp-content/mu-plugins and any PHP file under uploads, with weighted backdoor-signature heuristics. Files are only ever read, never modified, quarantined or deleted.
* Geo-aware login control: country from a trusted CDN header or a local MaxMind GeoLite2 database, monitor mode by default, optional blocking, and four independent ways back in if you lock yourself out.
* Immediate e-mail alerts, configurable per event type as e-mail, log only, or off, with an hourly circuit breaker so a mass finding cannot flood a mail server.
* Diagnostics screen showing how the site sees your address, and a what-if test for any other address.
* Complete German translation.

= 1.0.0 =
* Initial scaffolding release.

== Upgrade Notice ==

= 1.1.1 =
Required if your copy of this plugin is hosted in a private GitHub repository: without it, automatic updates are detected but cannot be downloaded. Install this version once by hand, and every later update will work on its own.

= 1.1.0 =
The first release that actually does anything. Review Settings after upgrading: alerts are off until recipients are set, and login blocking stays in monitor mode until you arm it.

= 1.0.0 =
Initial release.
