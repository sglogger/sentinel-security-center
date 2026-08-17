# WP Security Center

Security monitoring and alerting for WordPress. It watches what an attacker has
to touch in order to keep a foothold — plugins, themes, administrators, roles,
configuration, files, and where logins come from — records it in a searchable
log, and e-mails you immediately when it matters.

Distributed from GitHub Releases, not wordpress.org. The plugin updates itself
in place; no helper plugin is required.

**Status:** in development. See [CHANGELOG.md](CHANGELOG.md) for what exists.

---

## Design principles

Two goals pull against each other here — miss as little as possible, and raise
as few false alarms as possible. Every decision below follows from that.

- **Every event type is individually configurable** as immediate e-mail, log
  only, or off.
- **Blocking is never on by default.** Login blocking ships in monitor mode, so
  you can see what a rule *would* have done before arming it.
- **Failed logins are not processed at all.** No counters, no thresholds, no
  lockouts. Rate limiting belongs in the firewall, CDN or fail2ban, where it can
  act before the request reaches PHP. This plugin reacts only to authentication
  that actually succeeded.
- **The plugin never modifies, quarantines or deletes a scanned file.** It
  reports; recovery is your call. A false positive must never be able to break a
  working site.
- **Administrator-only.** No front-end output, no REST routes, no shortcodes,
  and a blocked login is byte-identical to an ordinary wrong password.

## What is monitored

| Area | Events |
|---|---|
| Plugins | installed, activated, deactivated, updated, deleted, auto-updated, and plugins that appear with no matching install (an SFTP drop) |
| Themes | installed, activated, updated, deleted |
| Users | created, deleted, role changed, promoted to administrator, demoted, administrator deleted |
| Administrators | e-mail changed, password changed or reset, capabilities written directly, and changes an administrator makes to their **own** account |
| Out-of-band | user rows altered directly in the database, found by an hourly reconciliation scan against a stored baseline |
| Configuration | `siteurl`, `home`, `admin_email`, `users_can_register`, `default_role`, `blog_public`, auto-update options, `wp-config.php` and `.htaccess` hashes, WordPress core files against the official checksums, cron jobs, new must-use plugins, XML-RPC state, file-editor state, application passwords |
| Filesystem | new or changed files in `wp-content/mu-plugins/`, any PHP file under `wp-content/uploads/`, and backdoor signatures in new PHP files |
| Logins | successful login from a country outside the allow list, with optional blocking |

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
| `WPSEC_GITHUB_TOKEN` | GitHub token for update checks against a private repository or to lift the rate limit |

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
docker compose exec wpcli wp plugin activate wp-security-center

# Useful during development
docker compose exec wpcli wp user create eve eve@example.test --role=subscriber
docker compose exec wpcli wp user set-role eve administrator
docker compose exec wpcli wp cron event run wpsec_user_scan
docker compose exec wpcli wp db tables --all-tables-with-prefix | grep wpsec
docker compose exec wordpress php -l wp-content/plugins/wp-security-center/includes/class-logger.php
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

The unit suite deliberately does not boot WordPress. The logic worth testing —
IP resolution, trusted-proxy validation, IPv4/IPv6 CIDR matching, the access
decision, backdoor signatures — was factored into WordPress-free classes for
exactly that reason.

## Coding conventions

- `declare( strict_types = 1 );` in every file, then the namespace, then the
  `ABSPATH` guard.
- Namespace `WPSecurityCenter`. Constants `WPSEC_*`, options, hooks and tables
  `wpsec_*`. Text domain `wp-security-center`.
- `final class Under_Score` in `class-kebab-case.php`, WordPress core style.
- Every component exposes `register(): void` that does nothing but add hooks.
  Nothing happens at file-load time.
- **No autoloader in production.** `wp-security-center.php` holds an explicit
  `require_once` list in dependency order. Composer's autoloader is pulled in
  lazily, only for the MaxMind reader, and a missing `vendor/` must degrade
  gracefully rather than fatal.
- Short array syntax, tabs, Yoda conditions, WPCS spacing.
- `index.php` ("Silence is golden") in every directory.

## Releasing (maintainer)

The version lives in three places and CI fails the build if they disagree:

1. `wp-security-center.php` — the `Version:` header
2. `wp-security-center.php` — `define( 'WPSEC_VERSION', ... )`
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
publishes the GitHub release. Sites running an older version pick it up through
the built-in updater.

## Licence

GPL-2.0-or-later. See [LICENSE.txt](LICENSE.txt).
