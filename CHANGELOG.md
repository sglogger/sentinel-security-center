# Changelog

All notable changes to WP Security Center are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

When a release goes out, the same summary must also be added to the
`== Changelog ==` section of `readme.txt` — that is what WordPress shows in the
plugin details modal.

## [1.1.0] - 2026-08-18

The first release that does anything. 1.0.0 was scaffolding.

### Added

- **Event log.** Custom table with a `WP_List_Table` viewer: sorting, paging,
  search, filters by category, severity, timeframe and IP, and a CSV export that
  carries exactly the filters on screen.
- **Plugin and theme monitoring** — install, activate, deactivate, update,
  delete, auto-update, plus plugins that appear on disk with no install recorded
  (an SFTP drop).
- **User and administrator monitoring** — creation, deletion, role changes,
  promotion to and demotion from administrator, e-mail and password changes,
  application passwords, and the case that matters most after a session
  takeover: an administrator changing their own account.
- **Out-of-band change detection.** An hourly reconciliation compares the users
  table against a stored baseline of row hashes. This is the only way to see a
  changed login name, because WordPress offers no code path that produces one.
- **Configuration monitoring** — critical options with old and new values,
  `wp-config.php` and `.htaccess` hashes, WordPress core files against the
  official checksums, cron jobs, new must-use plugins, XML-RPC and file-editor
  state.
- **File integrity** for `wp-content/mu-plugins` and any PHP file under uploads,
  with weighted backdoor-signature heuristics. Scanned files are opened
  read-only and are never modified, quarantined or deleted.
- **Geo-aware login control.** Country from a trusted CDN header or a local
  MaxMind GeoLite2 database, never an external API call during login. Monitor
  mode by default; optional blocking with four independent recovery paths.
- **Immediate e-mail alerts**, configurable per event type as e-mail, log only,
  or off, with an hourly circuit breaker so a mass finding cannot flood a mail
  server. A test-alert button proves delivery works.
- **Diagnostics screen** showing how the site resolved your address and why,
  plus a what-if test for any other address.
- **Status screen** covering login protection, the GeoIP database (including a
  live check that it is not reachable over the web), alert budget and scheduled
  scans.
- **Complete German translation** of the interface and the alert e-mails.
- Unit tests for the WordPress-free security logic: CIDR matching, proxy-aware
  IP resolution, the access decision table, and the backdoor heuristics.

### Fixed

- `preg_replace` with the removed `/e` modifier was never detected: the rule
  looked for the modifier after the PHP string's closing quote instead of inside
  the pattern, where it actually lives.
- The GeoIP health check reported "healthy" whenever trusted proxies and a
  country header name were merely configured, without either a database or an
  actual header. Under the fail-closed rule that kept blocking armed with no way
  to resolve anything, which would have locked out every user. It now requires a
  header to actually be present on the request.
- A phantom "role changed" and "password changed" event fired for every newly
  created user, because both signals arrive before `user_register`.
- A promotion to administrator was reported as an ordinary role change with the
  wrong previous roles, because `WP_User::set_role()` fires `remove_user_role`
  first and the buffered roles were already partly rewritten.
- Activating a plugin also produced a false "the active plugin list was written
  directly" alert, because the marker distinguishing a legitimate activation was
  set after the option had already been written.
- The uploads scanner alarmed about the plugin's own GeoIP directory, which
  lives under uploads and contains an `index.php`.

## [1.0.0] - 2026-08-17

Initial scaffolding: plugin bootstrap, installer, database schema, admin menu,
GitHub Releases self-updater, CI and the local development environment.

### Fixed

- Updater: a failed GitHub lookup cached an empty array that was then read back
  as though it were a valid release, producing a fatal error on the Plugins
  screen. Affects any repository without a published release.

[1.1.0]: https://github.com/sglogger/wp-security-center/releases/tag/v1.1.0
[1.0.0]: https://github.com/sglogger/wp-security-center/releases/tag/v1.0.0
