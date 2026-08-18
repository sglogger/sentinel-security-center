# Sentinel Security Center

Security monitoring and alerting for WordPress. It watches what an attacker has
to touch in order to keep a foothold — plugins, themes, administrators, roles,
configuration, files, and where logins come from — records it in a searchable
log, and e-mails you immediately when it matters.

Distributed through wordpress.org. The plugin ships no updater of its own —
updates arrive the ordinary way, through WordPress.

**Status:** feature complete as of 1.1.0. See [CHANGELOG.md](CHANGELOG.md).

---

## Design principles

Two goals pull against each other here — miss as little as possible, and raise
as few false alarms as possible. Every decision below follows from that.

- **Every event type is individually configurable** as immediate e-mail, log
  only, or off.
- **Blocking is never on by default.** Login blocking ships in monitor mode, so
  you can see what a rule *would* have done before arming it.
- **Failed logins are recorded, not acted on.** `login.failed` is written to the
  log at Info, log-only, so the attempts are there when you need them — but
  there are no counters, no thresholds and no lockouts. Rate limiting belongs in
  the firewall, CDN or fail2ban, where it can act before the request reaches
  PHP. Every rule this plugin *enforces* reacts only to authentication that
  actually succeeded.
- **The plugin never modifies, quarantines or deletes a scanned file.** It
  reports; recovery is your call. A false positive must never be able to break a
  working site.
- **Administrator-only.** No front-end output, no REST routes, no shortcodes,
  and a blocked login is byte-identical to an ordinary wrong password.

## What is monitored

| Area | Events |
|---|---|
| Plugins | installed, activated, deactivated, updated, deleted, auto-updated, an update becoming available, and plugins that appear with no matching install (an SFTP drop) |
| Themes | installed, activated, updated, deleted |
| Users | created, deleted, role changed, promoted to administrator, demoted, administrator deleted |
| Administrators | e-mail changed, password changed or reset, capabilities written directly, and changes an administrator makes to their **own** account |
| Out-of-band | user rows altered directly in the database, found by an hourly reconciliation scan against a stored baseline |
| Configuration | `siteurl`, `home`, `admin_email`, `users_can_register`, `default_role`, `blog_public`, `wp-config.php` and `.htaccess` hashes, WordPress core files against the official checksums, cron jobs, new must-use plugins, XML-RPC state, file-editor state, application passwords |
| Filesystem | new or changed files in `wp-content/mu-plugins/`, any PHP file under `wp-content/uploads/`, and backdoor signatures in new PHP files |
| Logins | failed attempts, successful logins, logins from a country outside the allow list, and logins refused by the IP deny list — with optional blocking |
| Two-factor | enrolment, removal, wrong codes after a correct password, recovery-code and e-mail-fallback use |

## Hardening report

A read-only screen — **Security Center → Hardening** — grading the installation
against the official
[Hardening WordPress](https://developer.wordpress.org/advanced-administration/security/hardening/)
guide. 22 checks in five groups: code execution, wp-config and file permissions,
staying current, accounts and access, and monitoring. Every check says what is
true now, what to change and where, and links to the section of the guide it
comes from.

Four verdicts, not three. Alongside Good / Fix this / Worth fixing there is
**Your call**, for the decisions that depend on how the site is run.
`DISALLOW_FILE_MODS` is the archetype: it removes plugin and theme installation
entirely, which is excellent — and it removes every update along with it, which
on a site that has no other deployment path is worse than leaving it unset. A
pass/fail badge on that is a lie either way, so the trade-off is written out
instead. Moving wp-config.php, changing the table prefix and renaming the
"admin" account get the same treatment, because the guide itself is lukewarm on
all three.

Nothing on the page changes anything, and nothing is written.

## Two-factor authentication

A TOTP code from any authenticator app, asked for after the password is
accepted. Enrolment is per account and voluntary by default; a site setting can
additionally require it for everyone who can `manage_options`, with a grace
period whose clock starts when the requirement is switched on.

How it holds together:

- **The session is issued only after the second factor.** `wp_login` fires after
  WordPress has already set the cookie, so the first thing that happens is that
  the session it just created is destroyed again — by token, so other sessions
  the user has open elsewhere are untouched.
- **Secrets are encrypted at rest** with AES-256-GCM under a key derived from
  `SECURE_AUTH_SALT`. A database dump without `wp-config.php` yields nothing
  usable.
- **A code is accepted once.** The last accepted time step is recorded, so a
  code captured over the shoulder cannot be replayed for the rest of its window.
- **The QR code is generated locally.** Sending the provisioning URI to an
  external QR service would hand the shared secret to a third party.
- **Nothing is switched on until a code is proven**, so a mistyped setup key
  cannot lock anyone out.

### If the authenticator is lost

1. **Recovery codes.** Ten single-use codes, issued at enrolment and shown once.
   Stored as hashes — which is also why they still work after a salt rotation,
   when the encrypted TOTP secrets no longer decrypt.
2. **A one-time code by e-mail**, off by default. It reduces the second factor
   to whoever can read the mailbox, and on many sites that mailbox lives on the
   same hosting account — so it is a deliberate, logged, opt-in weakening for
   sites where losing a phone would otherwise mean losing the site.
3. **An administrator reset.** Any user with `edit_user` can clear someone
   else's second factor from that user's profile screen. It is a reset, not a
   bypass: they must enrol again, and the event is logged as `2fa.reset_by_admin`.

Application passwords, REST and XML-RPC are not challenged. There is nobody at
the keyboard to type a code, and an application password is already a separate
credential that can be revoked on its own.

## IP deny list

A list of addresses and CIDR blocks — IPv4 and IPv6 — that can never sign in,
on **Settings → Login & Location**. It is the strongest rule in
[`Access_Policy`](includes/geo/class-access-policy.php): it sits ahead of every
other rail, so it overrides the allow list, an allowed country and the
private-network exemption, and it applies whether or not country checking is on.
Only `WPSEC_DISABLE_BLOCKING` stands it down.

- **No bypass link is issued for a denied address.** That token exists to rescue
  someone a *country* rule caught by accident; mailing a way around an explicit
  deny would undo the instruction.
- **The settings screen refuses an entry matching the address you are saving
  from**, and says which ones it dropped. Otherwise the setting saves, the
  session survives, and the door shuts at the next login.
- The check runs **after** the password is verified, so a `login.blocked_denylist`
  entry means someone at that address had working credentials. The event
  defaults to log-only: a deny list doing its job is a working control, not an
  incident.

It blocks the login, not the traffic. Denying the address at the firewall or CDN
is cheaper and remains the right place for volume.

## Geo-aware login control

Country is resolved in this order:

1. Your CDN or reverse proxy's country header (`CF-IPCountry` and friends) —
   but **only** when the connecting address is in your configured trusted-proxy
   list.
2. A local MaxMind GeoLite2 database.
3. Otherwise `ZZ`, unknown.

No external API is called during a login. `X-Forwarded-For` is ignored entirely
unless `REMOTE_ADDR` is a trusted proxy, walking the chain right to left to the
first untrusted hop — so the client IP cannot be spoofed by an attacker who can
reach the origin directly.

An unknown country is treated as **not allowed** and is blocked when blocking is
armed. VPN and Tor traffic therefore lands in this bucket; there is no dedicated
VPN detection, and an attacker exiting a VPN inside an allowed country will pass.
Treat this control as something that removes opportunistic foreign traffic, not
as a boundary.

### Locking yourself out

This is the real risk of country blocking, so there are four independent ways
back in:

1. **Monitor mode is the default.** Blocking must be armed deliberately, and the
   settings screen refuses to arm it while no working GeoIP database is present.
2. **IP/CIDR allow list**, exempt from every country rule.
3. **Kill switch.** Put this in `wp-config.php` and blocking stops immediately,
   even if you cannot reach the admin at all:
   ```php
   define( 'WPSEC_DISABLE_BLOCKING', true );
   ```
4. **Bypass link.** Every blocked login e-mails a single-use, time-limited link
   that allows your current IP for a few hours.

On top of that: private, loopback and link-local addresses are always allowed
and are never reported as a foreign login, and if the GeoIP subsystem as a whole
becomes unavailable, blocking automatically falls back to monitor mode and
raises a critical alert. A deleted database file cannot lock you out.

## Requirements

- PHP 8.1 or newer
- WordPress 6.5 or newer
- Single-site. Multisite is not supported; activation stops with a message.
- For country rules: a free MaxMind GeoLite2 licence key, or a CDN that supplies
  a country header. The database cannot be bundled — MaxMind's licence forbids
  redistribution.

## Configuration constants

All optional, all set in `wp-config.php`.

| Constant | Purpose |
|---|---|
| `WPSEC_DISABLE_BLOCKING` | Emergency kill switch; disables login blocking outright |
| `WPSEC_MAXMIND_LICENSE_KEY` | MaxMind licence key; takes precedence over the stored option, and keeps the key out of the database |
| `WPSEC_GEOIP_PATH` | Absolute path to a GeoLite2 `.mmdb`, for putting it outside the webroot |

## Local development

Requires Docker.

```sh
cp docker-compose.yml-example docker-compose.yml
cp .env.example .env
docker compose up -d
```

| Service | URL |
|---|---|
| WordPress | http://localhost:9090 |
| phpMyAdmin | http://localhost:9091 |
| Mailpit (catches every alert e-mail) | http://localhost:9025 |

`./local_wp_core` starts empty and is populated with WordPress core on first
boot. The repository root is mounted straight in as the plugin directory, so
edits are live with no build step.

```sh
# First-time setup
docker compose exec wpcli wp core install --url=http://localhost:9090 \
  --title="WPSec Dev" --admin_user=admin --admin_password=admin123 \
  --admin_email=admin@example.test --skip-email
docker compose exec wpcli wp plugin activate sentinel-security-center

# Useful during development
docker compose exec wpcli wp user create eve eve@example.test --role=subscriber
docker compose exec wpcli wp user set-role eve administrator
docker compose exec wpcli wp cron event run wpsec_user_scan
docker compose exec wpcli wp db tables --all-tables-with-prefix | grep wpsec
docker compose exec wordpress php -l wp-content/plugins/sentinel-security-center/includes/class-logger.php
```

Note that `wp db tables` **without** `--all-tables-with-prefix` lists only
WordPress core tables, so it will never show this plugin's tables.

The official `wordpress` image does not ship WP-CLI; that is what the separate
`wpcli` service is for.

### Tests and linting

```sh
composer install
composer test    # PHPUnit — WordPress-free unit tests
composer lint    # PHPCS, WordPress-Extra + PHPCompatibility
composer fix     # PHPCBF
```

`phpcs.xml.dist` records a handful of deliberate exemptions, each with the
reason next to it — direct filesystem access in the scanners (WP_Filesystem is
not initialised during cron, which is when they run), and custom-table SQL where
the table name is interpolated from `$wpdb->prefix` while every value is bound.
If you add a query to one of those files, that rule still stands: **table name
interpolated, values always bound.**

`phpcbf` must not be run over `admin/views/` unattended. Whitespace inside a
`<textarea>` is significant, and the embedded-PHP sniffs will happily reformat
it onto its own lines and inject newlines into saved field values. The relevant
sniffs are switched off for that directory.

The unit suite deliberately does not boot WordPress. The logic worth testing —
IP resolution, trusted-proxy validation, IPv4/IPv6 CIDR matching, the access
decision, backdoor signatures — was factored into WordPress-free classes for
exactly that reason.

## Coding conventions

- `declare( strict_types = 1 );` in every file, then the namespace, then the
  `ABSPATH` guard.
- Namespace `WPSecurityCenter`. Constants `WPSEC_*`, options, hooks and tables
  `wpsec_*`. Text domain `sentinel-security-center`.
- `final class Under_Score` in `class-kebab-case.php`, WordPress core style.
- Every component exposes `register(): void` that does nothing but add hooks.
  Nothing happens at file-load time.
- **No autoloader in production.** `sentinel-security-center.php` holds an explicit
  `require_once` list in dependency order. Composer's autoloader is pulled in
  lazily, only for the MaxMind reader, and a missing `vendor/` must degrade
  gracefully rather than fatal.
- Short array syntax, tabs, Yoda conditions, WPCS spacing.
- `index.php` ("Silence is golden") in every directory.

## Releasing (maintainer)

The version lives in three places and CI fails the build if they disagree:

1. `sentinel-security-center.php` — the `Version:` header
2. `sentinel-security-center.php` — `define( 'WPSEC_VERSION', ... )`
3. `readme.txt` — `Stable tag:`

Add the release notes to both [CHANGELOG.md](CHANGELOG.md) and the
`== Changelog ==` section of `readme.txt` (the latter is what the plugin details
modal renders), then:

```sh
git commit -am "release v1.0.1"
git push origin main
```

`.github/workflows/auto-tag.yml` takes it from there: it cross-checks the three
versions, tags, installs runtime dependencies with `--no-dev`, asserts no dev
package leaked into `vendor/`, compiles the `.po` files, builds the ZIP and
publishes the GitHub release. The plugin carries no updater of its own: updates
reach sites through WordPress.org once the release is published there.

## Translations

Source strings are English. A complete German translation ships in
`languages/`. To regenerate after changing strings:

```sh
docker compose exec wpcli wp i18n make-pot wp-content/plugins/sentinel-security-center \
  wp-content/plugins/sentinel-security-center/languages/sentinel-security-center.pot \
  --exclude=vendor,tests,dev,local_wp_core --slug=sentinel-security-center
docker compose exec wpcli sh -c 'cd /var/www/html/wp-content/plugins/sentinel-security-center \
  && wp i18n make-mo languages/ languages/'
```

Only the `.po` is tracked; the release workflow compiles the `.mo` so the two
can never drift apart.

## Licence

GPL-2.0-or-later. See [LICENSE.txt](LICENSE.txt).
