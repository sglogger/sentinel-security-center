# Changelog

All notable changes to WP Security Center are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

When a release goes out, the same summary must also be added to the
`== Changelog ==` section of `readme.txt` — that is what WordPress shows in the
plugin details modal.

## [1.2.0] - 2026-08-18

### Added

- **Hardening screen.** A read-only report on what this installation currently
  looks like to someone trying to get into it: 22 checks across code execution,
  wp-config and file permissions, staying current, accounts and access, and
  monitoring. Each one states what is true right now, what to change and where,
  and links to the section of the official
  [WordPress hardening guide](https://developer.wordpress.org/advanced-administration/security/hardening/)
  it comes from, so the advice can be checked against the source instead of
  taken on trust.

  Verdicts are Good, Fix this, Worth fixing — and *Your call*, which is not a
  failing grade. `DISALLOW_FILE_MODS` is the case that made the fourth verdict
  necessary: it closes the "install a plugin that is really a shell" path
  outright, and it also blocks every security update, so a site with it set and
  no deployment pipeline behind it gets steadily less safe rather than more.
  Grading that pass or fail would be dishonest, so the trade-off is spelled out
  instead. The same applies to moving wp-config.php, to the table prefix, and to
  renaming the "admin" account — all three are cases where the guide itself is
  lukewarm, and the screen says so.

  The page also lists what it deliberately cannot grade — the host's patching,
  the machine you administer from, FTP versus SFTP, database user privileges —
  with links into the guide for each.

- **Two-factor authentication (TOTP).** A one-time code from any authenticator
  app, asked for after the password is accepted; the session is issued only once
  that code is right. Enrolment is per account and voluntary by default, with a
  site setting to require it for everyone who can `manage_options` after a grace
  period that starts when the requirement is switched on.

  - The secret is encrypted at rest with AES-256-GCM under a key derived from
    `SECURE_AUTH_SALT`, so a database dump without `wp-config.php` cannot mint
    codes.
  - Each code is accepted once. The last accepted time step is recorded, which
    closes the replay window a 30-second code would otherwise leave open.
  - The QR code is rendered locally as inline SVG — sending the provisioning URI
    to an external QR service would hand the shared secret to a third party.
  - Nothing is switched on until a code from the app has been accepted, so a
    mistyped setup key cannot lock anyone out.
  - Application passwords, REST and XML-RPC are not challenged, by design.

  **Recovery**, for the day the authenticator is gone: ten single-use recovery
  codes issued at enrolment and shown once; optionally a one-time code mailed to
  the account address, off by default because it reduces the second factor to
  whoever reads that mailbox; and as a last resort a reset by another
  administrator from the user's profile screen. Recovery codes are stored as
  hashes rather than encrypted, so they keep working after a salt rotation —
  which is exactly when the TOTP secrets stop decrypting.

  Eleven new event types under a *Two-factor authentication* heading in the
  alert matrix. Enrolment and passed challenges are Info; a wrong code after a
  correct password is a Warning, because whoever submitted it has working
  credentials; switching the factor off, using a recovery code, using the
  e-mail fallback and changing the policy all e-mail immediately.

  Adds one runtime dependency, `bacon/bacon-qr-code`, for the QR rendering.

- **Failed login attempts are now recorded** as `login.failed`, and appear in
  the alert matrix under Logins like every other event. The default is
  deliberately Info / log only: on a public site bots guess passwords around the
  clock, and mailing that out is how an inbox learns to ignore this plugin. The
  row carries the submitted user name, the IP and its country, the reason core
  gave (`invalid_username`, `incorrect_password`, …) and whether the account
  actually exists — so a spray across many names and a hammering of one account
  are distinguishable in the log. Still no counters, thresholds or lockouts:
  nothing is enforced on a failed attempt.

  A login refused by the country rule is not counted twice — it is already
  recorded as `login.blocked_geo`.

### Fixed

- **The scanner reported its own files.** `Geoip_Database::refresh()` read the
  state option before `directory()` created the GeoIP directory, then wrote the
  stale copy back — erasing the recorded path. The file scanner uses that path
  to recognise its own guard files, so from the first database refresh onward it
  reported `wpsec-geoip-*/index.php` and `wpsec-geoip-*/.htaccess` as a critical
  find. The exemption no longer depends on the option at all: a file is skipped
  only when it sits in a `wpsec-geoip-*` directory under uploads, carries one of
  our guard file names, and matches our bytes exactly — so a shell dropped in
  beside them, or written over them, is still reported.

- **A `.htaccess` in uploads was reported as an executable file.** It was walked
  with the PHP files and inherited their event and wording ("An executable file
  appeared … should never contain PHP"), which is wrong on both counts. It is
  now a separate scope with its own message and the `file.uploads_htaccess_changed`
  event — which the registry and the mailer already defined but nothing emitted.

- **Localised installs reported `wp-includes/version.php` as modified, forever.**
  Only `get_locale()` was consulted, so a site whose core package and current
  language differ was checked against a manifest that describes a different
  build. The lookup now prefers `$wp_local_package`, and accepts a manifest only
  once its `version.php` matches the file on disk.

- **"View details" disappeared whenever GitHub could not be reached.** The
  updater returned early on a failed release lookup, leaving the plugin out of
  the `update_plugins` transient — and WordPress renders that link only for
  plugins it finds there. It now always registers, falling back to the version
  and readme data on disk. The modal also stops offering a WordPress.org plugin
  page that does not exist, and orders its tabs Description → Installation → FAQ
  → Changelog.

## [1.1.1] - 2026-08-18

### Fixed

- Updating from a **private** GitHub repository failed at the download step,
  after the update had already been advertised — the worst possible order. The
  release asset was fetched from its `browser_download_url`, which cannot carry
  credentials; a private repository requires the API asset URL together with the
  token and `Accept: application/octet-stream`. Public repositories were never
  affected.

  Because the fix lives in the updater itself, an install already running 1.1.0
  against a private repository has to be updated to 1.1.1 by hand once. From
  1.1.1 onward it updates itself.

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

[1.1.1]: https://github.com/sglogger/wp-security-center/releases/tag/v1.1.1
[1.1.0]: https://github.com/sglogger/wp-security-center/releases/tag/v1.1.0
[1.0.0]: https://github.com/sglogger/wp-security-center/releases/tag/v1.0.0
