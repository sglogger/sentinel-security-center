<?php
/**
 * Self-contained GitHub release updater.
 *
 * Lets WordPress update the plugin straight from GitHub Releases — no helper
 * plugin (Git Updater etc.) required. It hooks the three core extension points:
 *
 *   - `pre_set_site_transient_update_plugins`  → advertise a newer version.
 *   - `plugins_api`                            → feed the "View details" modal.
 *   - `upgrader_source_selection`              → rename the extracted GitHub
 *                                                folder to our plugin slug.
 *
 * The GitHub API response is cached in a transient to stay well under the
 * unauthenticated rate limit (60 req/h). For a private repo, supply a token
 * via the `WPSEC_GITHUB_TOKEN` constant or the
 * `wpsec_github_token` filter.
 *
 * Requirements on the release side: cut GitHub Releases whose tag is the
 * semver version matching the plugin header `Version:` (a leading "v" is fine).
 *
 * @package WPSecurityCenter
 */

declare( strict_types = 1 );

namespace WPSecurityCenter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Updater {

	/** GitHub repository in "owner/name" form. */
	private const REPO = 'sglogger/sentinel-security-center';

	/** How long to cache the GitHub release lookup, in seconds. */
	private const CACHE_TTL = 6 * HOUR_IN_SECONDS;

	/** Transient holding the cached GitHub release payload. */
	private const CACHE_KEY = 'wpsec_gh_release';

	/** Plugin basename, e.g. "sentinel-security-center/sentinel-security-center.php". */
	private string $basename;

	/** Plugin directory slug, e.g. "sentinel-security-center". */
	private string $slug;

	/** Currently installed version. */
	private string $version;

	/** Transient key for the cached GitHub release payload. */
	private string $cache_key;

	public function __construct() {
		$this->basename  = WPSEC_BASENAME;
		$this->slug      = dirname( $this->basename );
		$this->version   = WPSEC_VERSION;
		$this->cache_key = self::CACHE_KEY;
	}

	public function register(): void {
		add_filter( 'pre_set_site_transient_update_plugins', [ $this, 'inject_update' ] );
		add_filter( 'site_transient_update_plugins', [ $this, 'drop_stale_offer' ] );
		add_filter( 'plugins_api', [ $this, 'plugin_info' ], 10, 3 );
		add_filter( 'upgrader_source_selection', [ $this, 'rename_source' ], 10, 4 );
		add_action( 'upgrader_process_complete', [ $this, 'flush_cache' ], 10, 0 );
		add_filter( 'http_request_args', [ $this, 'authorise_download' ], 10, 2 );
	}

	/**
	 * Attach credentials when WordPress downloads our release asset.
	 *
	 * A public repository serves the browser_download_url to anyone. A private
	 * one does not: the asset has to be fetched from the API URL with a token
	 * AND `Accept: application/octet-stream`, otherwise GitHub returns JSON
	 * metadata (or a 404) and the upgrade fails after having already reported
	 * an available update — the worst of both worlds.
	 *
	 * @param array<string, mixed> $args HTTP request arguments.
	 * @param string               $url  Request URL.
	 * @return array<string, mixed>
	 */
	public function authorise_download( $args, $url ) {
		if ( ! is_string( $url ) || ! $this->is_our_asset_url( $url ) ) {
			return $args;
		}

		$token = $this->token();

		if ( '' === $token ) {
			return $args;
		}

		$args['headers'] = array_merge(
			(array) ( $args['headers'] ?? [] ),
			[
				'Authorization' => 'Bearer ' . $token,
				'Accept'        => 'application/octet-stream',
				'User-Agent'    => 'sentinel-security-center',
			]
		);

		return $args;
	}

	/**
	 * Is this exactly our release-asset endpoint on api.github.com?
	 *
	 * This filter sees every HTTP request WordPress makes, and it attaches a
	 * repository token. Matching by substring would hand that token to any
	 * host whose URL merely *contains* the expected text — e.g.
	 * https://evil.example/?u=api.github.com/repos/<repo>/releases/assets/1 —
	 * so the host and path are checked structurally instead.
	 */
	private function is_our_asset_url( string $url ): bool {
		$parts = wp_parse_url( $url );

		if ( ! is_array( $parts ) ) {
			return false;
		}

		if ( 'https' !== strtolower( (string) ( $parts['scheme'] ?? '' ) ) ) {
			return false;
		}

		if ( 'api.github.com' !== strtolower( (string) ( $parts['host'] ?? '' ) ) ) {
			return false;
		}

		return str_starts_with( (string) ( $parts['path'] ?? '' ), '/repos/' . self::REPO . '/releases/assets/' );
	}

	// -------------------------------------------------------------------------
	// Core hooks
	// -------------------------------------------------------------------------

	/**
	 * Add our plugin to the list of available updates when GitHub is ahead.
	 *
	 * @param object $transient The `update_plugins` site transient.
	 * @return object
	 */
	public function inject_update( $transient ) {
		if ( ! is_object( $transient ) ) {
			return $transient;
		}

		// A failed lookup must not make the plugin vanish from the transient.
		// WordPress only renders the "View details" link for a plugin it finds
		// in response or no_update, so bailing out here would take the details
		// modal down with it every time GitHub is unreachable, rate-limited or
		// has no release yet.
		$release = $this->get_release() ?? $this->local_release();

		if ( version_compare( $release['version'], $this->version, '>' ) ) {
			$transient->response[ $this->basename ] = $this->build_response( $release );

			return $transient;
		}

		// Nothing newer exists. Report the version that is actually installed
		// rather than the last release: on a copy ahead of the last tag — every
		// development checkout, and any site updated by hand — the release
		// number understates what is running.
		$release['version'] = $this->version;

		// Reported so WordPress shows "up to date" rather than nothing.
		$transient->no_update[ $this->basename ] = $this->build_response( $release );

		return $transient;
	}

	/**
	 * Correct a cached offer of a version that is already installed.
	 *
	 * WordPress checks for updates roughly twice a day and reads the cached
	 * answer in between, so an update applied any other way — git pull, rsync,
	 * an unzipped upload — leaves the plugins screen advertising an update to
	 * the version already on disk, for hours. This runs on the read side and
	 * moves such an entry to no_update, where "up to date" comes from.
	 *
	 * Deliberately does no lookup of its own: this fires on every read of the
	 * transient, including on the front end, and must stay free of HTTP
	 * requests and writes.
	 *
	 * @param mixed $transient The cached `update_plugins` transient.
	 * @return mixed
	 */
	public function drop_stale_offer( $transient ) {
		if ( ! is_object( $transient ) || empty( $transient->response[ $this->basename ] ) ) {
			return $transient;
		}

		$offer = $transient->response[ $this->basename ];

		if ( version_compare( (string) ( $offer->new_version ?? '0' ), $this->version, '>' ) ) {
			return $transient;
		}

		unset( $transient->response[ $this->basename ] );

		// Kept rather than dropped: no_update is what makes WordPress say the
		// plugin is current, and it is where the "View details" link comes from.
		$transient->no_update[ $this->basename ] = $offer;

		return $transient;
	}

	/**
	 * Forget the cached GitHub lookup.
	 */
	public static function forget_release(): void {
		delete_transient( self::CACHE_KEY );
	}

	/**
	 * Supply the data shown in the "View version X.Y.Z details" modal.
	 *
	 * @param false|object|array $result The result object/array, or false.
	 * @param string             $action The API action being performed.
	 * @param object             $args   Arguments including the requested slug.
	 * @return false|object|array
	 */
	public function plugin_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action ) {
			return $result;
		}
		if ( ! isset( $args->slug ) || $args->slug !== $this->slug ) {
			return $result;
		}

		// Most of the modal is populated from the bundled readme.txt, exactly
		// like the WordPress.org / Git Updater experience. The release lookup
		// only supplies the downloadable version + package (and may be null if
		// GitHub is unreachable — we still render the readme-based modal).
		$readme  = $this->readme();
		$release = $this->get_release();

		// Whose version is this modal describing? WordPress opens it from a
		// "View version X details" link, so it has to be the newer of the two:
		// the release being offered, or — on a copy that is ahead of the last
		// release, which is every development checkout — what is installed.
		$newer   = null !== $release && version_compare( (string) $release['version'], $this->version, '>' );
		$version = $newer ? (string) $release['version'] : $this->version;

		$sections = $readme['sections'];

		// The bundled readme.txt describes the copy on disk. When a newer
		// release exists, that is the one release notes the reader is asking
		// about, so they go on top and the bundled history stays underneath.
		// Getting this the wrong way round is why the modal used to answer
		// "what is new in the update?" with the changelog of the version you
		// already had.
		if ( $newer && '' !== (string) $release['changelog'] ) {
			$sections['changelog'] = $release['changelog'] . $sections['changelog'];
		} elseif ( empty( $sections['changelog'] ) && null !== $release ) {
			$sections['changelog'] = $release['changelog'];
		}

		if ( empty( $sections['changelog'] ) ) {
			$sections['changelog'] = '<p>' . esc_html__( 'See the GitHub release notes for details.', 'sentinel-security-center' ) . '</p>';
		}

		$info = [
			'name'              => 'Sentinel Security Center',
			'slug'              => $this->slug,
			// Without this WordPress offers a "WordPress.org Plugin Page" link
			// built from the slug, and this plugin has no page there.
			'external'          => true,
			'version'           => $version,
			'author'            => '<a href="https://www.glogger.ch">Steven Glogger</a>',
			'author_profile'    => 'https://www.glogger.ch',
			'homepage'          => 'https://github.com/' . self::REPO,
			'download_link'     => $release['package'] ?? '',
			'requires'          => $readme['requires'],
			'requires_php'      => $readme['requires_php'],
			'tested'            => $readme['tested'],
			// Only meaningful when the release really is the version on show;
			// dating a development build by an older release is worse than
			// leaving it blank.
			'last_updated'      => $newer ? (string) $release['published_at'] : '',
			'added'             => $newer ? (string) $release['published_at'] : '',
			'short_description' => $readme['short_description'],
			'sections'          => $this->order_sections( $sections ),
			'contributors'      => $readme['contributors'],
			'banners'           => [],
			'icons'             => [],
		];

		return (object) $info;
	}

	/**
	 * Put the modal's tabs in the order WordPress.org uses, and drop the ones
	 * it never shows there. The first entry is the tab that opens by default,
	 * so "Description" has to come first whatever order readme.txt is in.
	 *
	 * @param array<string, string> $sections Parsed readme sections.
	 * @return array<string, string>
	 */
	private function order_sections( array $sections ): array {
		unset( $sections['upgrade_notice'] );

		$ordered = [];

		foreach ( [ 'description', 'installation', 'faq', 'screenshots', 'changelog' ] as $key ) {
			if ( ! empty( $sections[ $key ] ) ) {
				$ordered[ $key ] = $sections[ $key ];
				unset( $sections[ $key ] );
			}
		}

		return array_merge( $ordered, $sections );
	}

	/**
	 * GitHub zips extract to a versioned/hashed folder; rename it to our slug
	 * so the upgraded files land in the correct plugin directory.
	 *
	 * @param string $source        Path to the extracted source folder.
	 * @param string $remote_source Path to the parent of the extracted folder.
	 * @param object $upgrader      The WP_Upgrader instance.
	 * @param array  $hook_extra    Extra args, includes the target plugin file.
	 * @return string|\WP_Error
	 */
	public function rename_source( $source, $remote_source, $upgrader, $hook_extra = [] ) {
		global $wp_filesystem;

		if ( ! isset( $hook_extra['plugin'] ) || $hook_extra['plugin'] !== $this->basename ) {
			return $source;
		}

		$desired = trailingslashit( $remote_source ) . $this->slug . '/';
		if ( trailingslashit( $source ) === $desired ) {
			return $source;
		}

		if ( $wp_filesystem && $wp_filesystem->move( $source, $desired, true ) ) {
			return $desired;
		}

		return new \WP_Error(
			'wpsec_rename_failed',
			esc_html__( 'Could not rename the downloaded update folder.', 'sentinel-security-center' )
		);
	}

	/**
	 * Drop the cached release so the next check re-queries GitHub.
	 */
	public function flush_cache(): void {
		delete_transient( $this->cache_key );
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Shape the update object WordPress expects in the transient.
	 *
	 * @param array<string, mixed> $release Normalised release data.
	 * @return object
	 */
	private function build_response( array $release ): object {
		return (object) [
			'slug'         => $this->slug,
			'plugin'       => $this->basename,
			'new_version'  => $release['version'],
			'url'          => 'https://github.com/' . self::REPO,
			'package'      => $release['package'],
			'tested'       => $release['tested'],
			'requires'     => $release['requires'],
			'requires_php' => $release['requires_php'],
		];
	}

	/**
	 * What we know without asking GitHub: the installed version, described by
	 * the bundled readme.txt. Used whenever the release lookup comes back
	 * empty so the plugin still has an entry in the update transient.
	 *
	 * @return array<string, mixed>
	 */
	private function local_release(): array {
		$readme = $this->readme();

		return [
			'version'      => $this->version,
			'package'      => '',
			'changelog'    => $readme['sections']['changelog'] ?? '',
			'published_at' => '',
			'requires'     => $readme['requires'],
			'requires_php' => $readme['requires_php'],
			'tested'       => $readme['tested'],
		];
	}

	/**
	 * Fetch (and cache) the latest GitHub release, normalised to our shape.
	 *
	 * @return array<string, mixed>|null Null when the lookup fails.
	 */
	private function get_release(): ?array {
		$cached = get_transient( $this->cache_key );
		if ( is_array( $cached ) ) {
			// An empty array is the negative-cache marker written after a
			// failed lookup. Returning it as though it were a release would
			// hand callers an array with no 'version' key — which is a fatal
			// error in inject_update(). This is exactly what happens on a repo
			// that has no releases yet.
			return $this->is_usable( $cached ) ? $cached : null;
		}

		$response = wp_remote_get(
			'https://api.github.com/repos/' . self::REPO . '/releases/latest',
			[
				'timeout' => 10,
				'headers' => $this->api_headers(),
			]
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			// Cache a short negative result to avoid hammering the API.
			set_transient( $this->cache_key, [], 30 * MINUTE_IN_SECONDS );
			return null;
		}

		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $body ) || empty( $body['tag_name'] ) ) {
			set_transient( $this->cache_key, [], 30 * MINUTE_IN_SECONDS );
			return null;
		}

		$release = $this->normalise( $body );

		if ( ! $this->is_usable( $release ) ) {
			set_transient( $this->cache_key, [], 30 * MINUTE_IN_SECONDS );
			return null;
		}

		set_transient( $this->cache_key, $release, self::CACHE_TTL );

		return $release;
	}

	/**
	 * A release payload is only usable once it carries the two fields every
	 * caller dereferences without checking.
	 *
	 * @param array<string, mixed> $release Candidate release data.
	 */
	private function is_usable( array $release ): bool {
		return ! empty( $release['version'] ) && ! empty( $release['package'] );
	}

	/**
	 * Turn GitHub's release JSON into the fields we actually use.
	 *
	 * @param array<string, mixed> $body Decoded GitHub release object.
	 * @return array<string, mixed>
	 */
	private function normalise( array $body ): array {
		$version = ltrim( (string) $body['tag_name'], 'vV' );

		// Prefer an uploaded .zip asset; fall back to the source zipball.
		$package = (string) ( $body['zipball_url'] ?? '' );
		$token   = $this->token();

		if ( ! empty( $body['assets'] ) && is_array( $body['assets'] ) ) {
			foreach ( $body['assets'] as $asset ) {
				if ( ! isset( $asset['name'] ) || '.zip' !== strtolower( substr( (string) $asset['name'], -4 ) ) ) {
					continue;
				}

				// With a token, take the API asset URL — it is the only one
				// that can be authenticated, and therefore the only one that
				// works for a private repository. Without a token the browser
				// URL is correct and needs no credentials.
				$package = ( '' !== $token && ! empty( $asset['url'] ) )
					? (string) $asset['url']
					: (string) ( $asset['browser_download_url'] ?? '' );

				break;
			}
		}

		$readme = $this->readme();

		return [
			'version'      => $version,
			'package'      => $package,
			'changelog'    => $this->markup_to_html( (string) ( $body['body'] ?? '' ) ),
			'published_at' => isset( $body['published_at'] )
				? gmdate( 'Y-m-d', strtotime( (string) $body['published_at'] ) )
				: '',
			// Compatibility data is read from the bundled readme.txt headers so
			// the "tested up to" value is real and not the running WP version.
			'requires'     => $readme['requires'],
			'requires_php' => $readme['requires_php'],
			'tested'       => $readme['tested'],
		];
	}

	/**
	 * Parse the bundled readme.txt into the pieces the details modal needs.
	 *
	 * Returns header fields (requires / tested / requires_php / contributors),
	 * the short description and each `== Section ==` rendered to HTML. Parsed
	 * once per request. Mirrors the WordPress.org readme format closely enough
	 * for the "View details" modal.
	 *
	 * @return array{requires:string,tested:string,requires_php:string,contributors:array<string,array<string,string>>,short_description:string,sections:array<string,string>}
	 */
	private function readme(): array {
		static $parsed = null;
		if ( null !== $parsed ) {
			return $parsed;
		}

		$defaults = [
			'requires'          => WPSEC_MIN_WP,
			'tested'            => '',
			'requires_php'      => WPSEC_MIN_PHP,
			'contributors'      => [],
			'short_description' => '',
			'sections'          => [],
		];

		$file = WPSEC_DIR . 'readme.txt';
		if ( ! is_readable( $file ) ) {
			$parsed = $defaults;
			return $parsed;
		}

		$raw   = (string) file_get_contents( $file ); // phpcs:ignore -- reading our own bundled file.
		$lines = preg_split( '/\r\n|\r|\n/', $raw );

		$headers      = [];
		$short        = [];
		$sections_raw = [];
		$current      = null;
		$state        = 'title';

		foreach ( (array) $lines as $line ) {
			if ( 'title' === $state ) {
				if ( preg_match( '/^===\s*.+?\s*===\s*$/', (string) $line ) ) {
					$state = 'headers';
				}
				continue;
			}

			if ( 'headers' === $state ) {
				if ( '' === trim( (string) $line ) ) {
					$state = 'short';
					continue;
				}
				if ( preg_match( '/^([A-Za-z][A-Za-z \-]+):\s*(.*)$/', (string) $line, $m ) ) {
					$headers[ strtolower( trim( $m[1] ) ) ] = trim( $m[2] );
					continue;
				}
				$state = 'short'; // No blank line before content; fall through.
			}

			if ( preg_match( '/^==\s*(.+?)\s*==\s*$/', (string) $line, $m ) ) {
				$state                    = 'sections';
				$current                  = $this->section_key( $m[1] );
				$sections_raw[ $current ] = [];
				continue;
			}

			if ( 'short' === $state ) {
				$short[] = (string) $line;
			} elseif ( 'sections' === $state && null !== $current ) {
				$sections_raw[ $current ][] = (string) $line;
			}
		}

		$sections = [];
		foreach ( $sections_raw as $key => $body ) {
			$sections[ $key ] = $this->markup_to_html( implode( "\n", $body ) );
		}

		$contributors = [];
		foreach ( array_filter( array_map( 'trim', explode( ',', $headers['contributors'] ?? '' ) ) ) as $user ) {
			$contributors[ $user ] = [
				'display_name' => $user,
				'profile'      => 'https://profiles.wordpress.org/' . $user . '/',
				'avatar'       => '',
			];
		}

		$parsed = [
			'requires'          => $headers['requires at least'] ?? $defaults['requires'],
			'tested'            => $headers['tested up to'] ?? $defaults['tested'],
			'requires_php'      => $headers['requires php'] ?? $defaults['requires_php'],
			'contributors'      => $contributors,
			'short_description' => trim( (string) preg_replace( '/\s+/', ' ', implode( ' ', $short ) ) ),
			'sections'          => $sections,
		];

		return $parsed;
	}

	/**
	 * Map a readme section title to the key WordPress uses for its modal tabs.
	 */
	private function section_key( string $title ): string {
		$title = strtolower( trim( $title ) );
		if ( false !== strpos( $title, 'frequently asked' ) ) {
			return 'faq';
		}
		return trim( (string) preg_replace( '/[^a-z0-9]+/', '_', $title ), '_' );
	}

	/**
	 * Convert the lightweight markup used in readme.txt / GitHub release notes
	 * (lists, `= headings =`, inline code/bold/links) into the HTML the details
	 * modal renders. Everything is escaped first, so it is safe for untrusted
	 * release bodies.
	 *
	 * @param string $markup Raw readme/release text.
	 * @return string
	 */
	private function markup_to_html( string $markup ): string {
		$lines     = preg_split( '/\r\n|\r|\n/', $markup );
		$html      = '';
		$paragraph = [];
		$li        = '';
		$list_tag  = ''; // '', 'ul' or 'ol' — empty means no list is open.

		$flush_paragraph = function () use ( &$html, &$paragraph ) {
			if ( $paragraph ) {
				$html     .= '<p>' . $this->inline( implode( ' ', $paragraph ) ) . '</p>';
				$paragraph = [];
			}
		};
		$flush_list      = function () use ( &$html, &$li, &$list_tag ) {
			if ( '' !== $li ) {
				$html .= '<li>' . $this->inline( $li ) . '</li>';
				$li    = '';
			}
			if ( '' !== $list_tag ) {
				$html    .= '</' . $list_tag . '>';
				$list_tag = '';
			}
		};

		foreach ( (array) $lines as $raw ) {
			$line = trim( (string) $raw );

			if ( '' === $line ) {
				$flush_paragraph();
				$flush_list();
				continue;
			}

			$want = '';
			if ( preg_match( '/^[*-]\s+(.*)$/', $line, $m ) ) {
				$want = 'ul';
			} elseif ( preg_match( '/^\d+[.)]\s+(.*)$/', $line, $m ) ) {
				$want = 'ol';
			}
			if ( '' !== $want ) {
				$flush_paragraph();
				if ( '' !== $li ) {
					$html .= '<li>' . $this->inline( $li ) . '</li>';
					$li    = '';
				}
				if ( $list_tag !== $want ) {
					if ( '' !== $list_tag ) {
						$html .= '</' . $list_tag . '>';
					}
					$html    .= '<' . $want . '>';
					$list_tag = $want;
				}
				$li = $m[1];
				continue;
			}

			if ( preg_match( '/^=+\s*(.+?)\s*=+$/', $line, $m )
				|| preg_match( '/^#{1,6}\s+(.*)$/', $line, $m ) ) {
				$flush_paragraph();
				$flush_list();
				$html .= '<h4>' . $this->inline( $m[1] ) . '</h4>';
				continue;
			}

			// Continuation of the current list item, otherwise a paragraph line.
			if ( '' !== $li ) {
				$li .= ' ' . $line;
			} else {
				$paragraph[] = $line;
			}
		}

		$flush_paragraph();
		$flush_list();

		return $html;
	}

	/**
	 * Apply inline markup (code, bold, links) to an already-trimmed line. The
	 * text is HTML-escaped first; only the recognised tokens become tags.
	 */
	private function inline( string $text ): string {
		$text = esc_html( $text );
		$text = (string) preg_replace_callback(
			'/\[([^\]]+)\]\(([^)\s]+)\)/',
			static function ( $m ) {
				return '<a href="' . esc_url( html_entity_decode( $m[2] ) ) . '">' . $m[1] . '</a>';
			},
			$text
		);
		$text = (string) preg_replace( '/`([^`]+)`/', '<code>$1</code>', $text );
		$text = (string) preg_replace( '/\*\*([^*]+)\*\*/', '<strong>$1</strong>', $text );
		return $text;
	}

	/**
	 * The configured GitHub token, if any.
	 */
	private function token(): string {
		$token = '';

		if ( defined( 'WPSEC_GITHUB_TOKEN' ) && WPSEC_GITHUB_TOKEN ) {
			$token = (string) WPSEC_GITHUB_TOKEN;
		}

		/** Allow a token to be supplied at runtime (e.g. for a private repo). */
		return (string) apply_filters( 'wpsec_github_token', $token );
	}

	/**
	 * Request headers for the GitHub API, including auth when a token exists.
	 *
	 * @return array<string, string>
	 */
	private function api_headers(): array {
		$headers = [
			'Accept'     => 'application/vnd.github+json',
			'User-Agent' => 'sentinel-security-center',
		];

		$token = $this->token();

		if ( '' !== $token ) {
			$headers['Authorization'] = 'Bearer ' . $token;
		}

		return $headers;
	}
}
