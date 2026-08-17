# Changelog

All notable changes to WP Security Center are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

When a release goes out, the same summary must also be added to the
`== Changelog ==` section of `readme.txt` — that is what WordPress shows in the
plugin details modal.

## [Unreleased]

### Added

- Project scaffolding: plugin bootstrap, singleton, installer, admin menu and
  the GitHub Releases self-updater.
- Database schema: event log, user baseline and file baseline tables, created
  via `dbDelta()` and verified to be idempotent on re-run.
- Six scheduled maintenance jobs (user reconciliation, file scan, config scan,
  core checksums, GeoIP refresh, log retention), each with a randomised first
  run so a fleet of sites does not stampede an upstream service.
- Self-healing schema check: a missing table is recreated even when the stored
  data version claims to be current, so a partial restore cannot silently stop
  the audit trail.
- Multisite activation guard, plus PHP 8.1 / WordPress 6.5 platform guards that
  disable the plugin with an admin notice instead of fatalling.
- PHPUnit suite covering the safe-by-default contract, and a GitHub Actions
  workflow running it across PHP 8.1, 8.2 and 8.3 alongside PHPCS.
- Local development environment (WordPress, MariaDB, WP-CLI, Mailpit,
  phpMyAdmin) via Docker Compose.

### Fixed

- Updater: a failed GitHub lookup cached an empty array that was then read back
  as though it were a valid release, producing a fatal error on the Plugins
  screen. Affects any repository without a published release.

## [1.0.0] - Unreleased

Initial release.

[Unreleased]: https://github.com/sglogger/wp-security-center/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/sglogger/wp-security-center/releases/tag/v1.0.0
