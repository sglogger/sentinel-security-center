# Changelog

All notable changes to Sentinel Security Center are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

When a release goes out, the same summary must also be added to the
`== Changelog ==` section of `readme.txt` — that is what WordPress shows in the
plugin details modal.

## [1.6.5] - 2026-08-18

### Added

- **A plugin with an update waiting is now an event of its own.**
  `plugin.update_available` is raised once per available version by a new daily
  check, carrying the installed version, the version on offer, and whether the
  plugin is active. It starts at log only; set it to e-mail in Settings →
  Events on a site nobody reads the dashboard of, because an unpatched plugin
  is the most common way a WordPress site is taken over. The check only reads
  the update information WordPress collects on its own schedule — nothing here
  checks for, downloads or installs anything.

### Removed

- **The `option.auto_update_changed` event.** Watching the `auto_update_*`
  options made the plugin scanner read the plugin as taking part in updates,
  and the check was not worth the ambiguity. The Hardening screen still reports
  whether automatic updates are on, and `config.autoupdate_constant_changed`
  still catches `AUTOMATIC_UPDATER_DISABLED` being set in `wp-config.php`.

## [1.6.0] - 2026-08-18

### Removed

- **The GitHub Releases self-updater.** The `Update URI` header, the
  `pre_set_site_transient_update_plugins` / `site_transient_update_plugins` /
  `plugins_api` / `upgrader_source_selection` filters and the cached release
  lookup are gone, along with `includes/class-updater.php` and the
  `WPSEC_GITHUB_TOKEN` constant. A plugin hosted on wordpress.org may not
  install or serve updates from an external source; updates are distributed
  through wordpress.org.

## [1.5.2] - 2026-08-18

### Fixed

- **"Check again" reported no update for up to six hours after one was
  released.** The GitHub release lookup is cached for six hours to stay under
  the unauthenticated API rate limit, but `update-core.php?force-check=1` only
  clears the caches WordPress itself owns — it calls `wp_version_check()` and,
  via `load-update-core.php`, `wp_update_plugins()`, and never
  `wp_clean_update_cache()`. The forced check therefore replayed our own cached
  answer: the button truthfully said "no updates" while an update existed. A
  forced check now bypasses the cache and re-queries GitHub. It is gated on the
  `update_plugins` capability, because `force-check` is a query argument any
  visitor can set and an anonymous request coinciding with a scheduled refresh
  would otherwise spend one of the 60 API calls an hour.

### Added

- **The plugin now has its own icon in the WordPress update screens.** Every
  screen that pictures a plugin fell back to the generic puzzle piece:
  `update-core.php` walks `$update->icons` (svg, 2x, 1x, default) and otherwise
  prints `dashicons-admin-plugins`, and the details modal does the same with
  `$api->icons`. Both are now supplied, SVG first. The admin menu keeps its
  `dashicons-shield-alt`, which is deliberate — the menu icon is a silhouette
  in a strip of other silhouettes, and a colour logo reads as an advert there.

### Changed

- **The 1024px icon master is kept out of the release ZIP.** It is a source
  asset for store listings; nothing in the plugin references it, and at ~730 KB
  it weighed twice as much as the entire rest of the package. The SVG and the
  256px PNG — the two the updater points WordPress at — do ship.

## [1.5.1] - 2026-08-18

### Fixed

- **`composer.lock` was out of date with `composer.json`.** The 1.4.0 rename
  changed the package name in `composer.json`, and the package name is part of
  the content hash Composer records in the lock — so `composer validate
  --strict` failed the CI test job on every run since. The lock has been
  regenerated; only the hash changed, no dependency versions moved.

- **The release workflow ran a Node 20 action.** GitHub deprecated the Node 20
  Actions runtime, so `softprops/action-gh-release@v2` was being force-run on
  Node 24 with a warning on every release. Pinned to `v3`, whose only change
  from `v2.6.2` is that runtime bump; the inputs are identical.

## [1.5.0] - 2026-08-18

### Fixed

- **`Tested up to` in readme.txt carried a patch number.** The field is defined
  as a WordPress *major* version, so `7.0.4` is rejected by the plugin review
  checks rather than merely tidied up. It now reads `7.0`.

- **The release ZIP shipped `vendor/` without `composer.json`.** The packaging
  step deliberately excluded every tooling config from the plugin root, but
  `vendor/` is installed by Composer and does ship, and a Composer-built
  dependency tree with no manifest describing it is flagged by the review
  tooling. `composer.json` is now staged into the ZIP with the rest of the
  plugin; `composer.lock` and the remaining dev configs stay out.

## [1.4.0] - 2026-08-18

### Changed

- **The plugin is now called Sentinel Security Center.** WordPress.org does not
  allow a plugin display name or permalink to begin with "wp", so the name, the
  slug and the text domain all had to change: `wp-security-center` became
  `sentinel-security-center`, and the main plugin file was renamed to match. The
  GitHub repository moved to `sglogger/sentinel-security-center`; the old URLs
  redirect, and the updater now queries the new one.

  Nothing you have configured is lost. Option names, hook names, the database
  tables and the GeoIP directory under `uploads/` all keep their `wpsec` prefix
  and are untouched, so your settings, the log, the file and user baselines and
  any downloaded GeoIP database survive the upgrade unchanged.

  **This upgrade needs one manual step.** WordPress deactivates a plugin before
  updating it and reactivates it afterwards by the path it recorded — and that
  path, the old main file, no longer exists. The reactivation therefore fails
  and the plugin is left switched off. Open the Plugins screen and activate
  Sentinel Security Center by hand; monitoring resumes with your existing
  settings and baselines, and no further action is needed. Until you do,
  nothing is being monitored. Sites installing the plugin for the first time
  are unaffected.

  Upgraded sites keep the old `wp-security-center` directory name, because the
  updater installs into the directory the plugin already occupies. That is
  cosmetic: every path in the plugin is derived from its own location. To tidy
  it up, deactivate, delete and install the new ZIP — settings and log survive,
  as they live in the database.

## [1.3.0] - 2026-08-18

### Security

- **Two-factor authentication could be bypassed entirely through xmlrpc.php.**
  The challenge hangs off `wp_login`, which only `wp_signon()` fires — but
  XML-RPC calls `wp_authenticate()` directly, so a stolen password typed into
  xmlrpc.php walked straight past the second factor it was set up to survive.
  Primary-password API authentication is now refused for any account with a
  second factor (event: `2fa.api_auth_refused`, wearing the ordinary
  wrong-password message so the endpoint does not reveal which accounts have
  2FA). Application passwords are unaffected — they are the documented,
  revocable credential for integrations.

- **The GitHub token could leak to an arbitrary host.** The updater attaches
  its token on the `http_request_args` filter, which sees every HTTP request
  WordPress makes, and matched its own asset URL by substring — so any request
  to a URL merely *containing* `api.github.com/repos/…/releases/assets/`
  (for example in a query string) got the `Authorization` header attached and
  sent to whatever host it was really for. The URL is now parsed and matched
  structurally: HTTPS, host exactly `api.github.com`, path prefix exact.

- **CSV export was a formula-injection carrier.** The log records hostile input
  by design — a user name typed into the login form, a request path, a user
  agent — and Excel executes exported cells starting with `=`, `+`, `-` or `@`
  as formulas. Text cells with such a first character are now prefixed with a
  quote, which spreadsheets render as plain text.

- **The two-factor attempt limit is now also enforced per user**, not only per
  user-and-address (25 vs 10 per 15 minutes). Rotating addresses no longer
  multiplies the guess budget for a six-digit code by the size of the botnet.

### Added

- **IP deny list.** A list of addresses and CIDR blocks — IPv4 and IPv6 — that
  can never sign in, on the *Login & Location* settings tab beside the allow
  list. It is the strongest rule in the decision table and sits ahead of every
  other rail: it overrides the allow list, an allowed country, and the
  private-network exemption, and it applies whether or not country checking is
  switched on, because typing an address into it is an instruction in its own
  right. Only the `WPSEC_DISABLE_BLOCKING` constant stands it down — the escape
  hatch exists for exactly the case where this list is what locked the
  administrator out.

  Two deliberate refusals. A denied address gets **no bypass link**: that token
  exists to rescue someone a country rule caught by accident, and mailing a way
  around an explicit deny would undo the instruction. And the settings screen
  **refuses to store an entry matching the address you are saving from**,
  reporting which entries it dropped — otherwise the setting would save, the
  current session would survive, and the door would shut at the next login.

  The check runs after the password is verified, so a `login.blocked_denylist`
  entry means someone at that address had working credentials — high signal,
  and worth reading as such. The event defaults to **Info level action: log
  only**, configurable per event like every other, because a deny list doing its
  job on a hostile address is a working control rather than an incident.

  This blocks the login, not the traffic. Refusing the address at the firewall
  or CDN is still cheaper and still the right place for volume.

### Changed

- **The log search box now covers every column the log shows.** It searched the
  description, the object and the user; it now also searches the event type, the
  IP address and the timestamp. Time is both stored and displayed as UTC in the
  same format, so `2026-08-18`, `14:32` or `08-18 14` match what is on screen
  with no timezone arithmetic in between — which is the point, since a search
  box that cannot find a row you are looking straight at is worse than none.

- **readme.txt now declares WordPress 7.0.4** rather than 6.9 under *Tested up
  to*, so the details modal stops reporting the plugin as untested on a current
  install. Note that this value is compared with `version_compare`, so it has to
  be the full `7.0.4` — `7.0` would still read as untested against 7.0.4.

### Fixed

- **The plugins screen went on offering an update that was already installed.**
  WordPress checks for updates about twice a day and reads the cached answer in
  between, and only an update applied *through the updater* clears that cache.
  Update the files any other way — git pull, rsync, an unzipped upload — and the
  screen keeps saying "version 1.2.0 is available" for hours after 1.2.0 is
  running. Two changes: the cached transient is now corrected on read, so an
  offer of a version at or below the installed one is moved to "up to date"
  immediately; and the plugin notices when its own version on disk has changed
  since the last request and throws away both cached checks. A genuinely newer
  release is untouched.

- **The details modal showed the changelog of the version you already had.** The
  bundled readme.txt was preferred over the release notes unconditionally, so
  "View version 1.2.0 details" answered with 1.1.1's changelog — the one thing
  the reader is certainly not asking about. The notes for the offered release
  now go on top, with the bundled history underneath, and the version shown is
  the newer of the release and the installed copy instead of always the release
  (a development checkout ahead of the last tag used to describe itself with an
  older version number).

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

[1.4.0]: https://github.com/sglogger/sentinel-security-center/releases/tag/v1.4.0
[1.1.1]: https://github.com/sglogger/sentinel-security-center/releases/tag/v1.1.1
[1.1.0]: https://github.com/sglogger/sentinel-security-center/releases/tag/v1.1.0
[1.0.0]: https://github.com/sglogger/sentinel-security-center/releases/tag/v1.0.0
