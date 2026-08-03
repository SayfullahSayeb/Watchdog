<?php
/**
 * Trust model: every plugin/theme is assigned a trust level instead of
 * being treated equally.
 *
 *   official  - verified WordPress.org package (checksums verified or
 *               on the built-in known-good list). Lowest suspicion.
 *   trusted   - commercial/private plugins the administrator explicitly
 *               marked as trusted. Low suspicion.
 *   unknown   - anything else, including newly uploaded or unverifiable
 *               packages. Higher scrutiny.
 *
 * Trust levels downgrade MALICIOUS verdicts (unless obfuscation, mobile
 * gating or malware signatures are present) and never affect SAFE or
 * EXPECTED verdicts.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * Trust
 */
final class Trust {

    public const OFFICIAL = 'official';
    public const TRUSTED = 'trusted';
    public const UNKNOWN = 'unknown';

    /**
     * Built-in known-good WordPress.org plugin slugs. Only used as a
     * starting point; every level is editable in the dashboard.
     */
    private const DEFAULT_OFFICIAL = 'akismet
hello-dolly
jetpack
woocommerce
woocommerce-paypal-payments
woocommerce-gateway-stripe
elementor
elementor-pro
wordpress-seo
seo-by-rank-math
rank-math
redirection
polylang
sitepress-multilingual-cms
really-simple-ssl
litespeed-cache
wp-super-cache
w3-total-cache
autoptimize
wp-rocket
duplicator
updraftplus
contact-form-7
wpforms-lite
wordfence
sucuri-scanner
wp-mail-smtp
fluent-smtp
mailchimp-for-wp
wp-maintenance-mode
wp-fastest-cache
all-in-one-wp-migration
backwpup
smush
wp-super-minify
wp-optimize';

    /**
     * Trust level for a plugin or theme slug.
     *
     * @param string $slug Folder name of the plugin/theme.
     * @param string $kind 'plugin' or 'theme'.
     */
    public static function level(string $slug, string $kind = 'plugin'): string {
        $slug = strtolower(trim($slug));
        if ($slug === '') {
            return self::UNKNOWN;
        }

        $option = $kind === 'theme' ? 'watchdog_trust_themes' : 'watchdog_trust_plugins';
        $map = (array) get_option($option, []);

        if (isset($map[$slug])) {
            return self::normalize($map[$slug]);
        }

        // Verification results (Wordfence known-files equivalent) derive
        // trust from WordPress.org itself, not from a maintained list:
        // a package checksum-verified against the official zip — or a
        // known WP.org package at a non-latest version — is official by
        // definition. This covers themes automatically, which the static
        // plugin list never could. A 'modified' package is deliberately
        // NOT trusted here: its files can no longer be proven untouched
        // official code and the checksum engine reports it separately.
        if (class_exists('Watchdog\Checksums')) {
            $result = Checksums::packageResult($kind, $slug);
            $status = (string) ($result['status'] ?? '');
            if ($status === 'clean' || $status === 'version-mismatch') {
                return self::OFFICIAL;
            }
        }

        if ($kind === 'theme') {
            return self::UNKNOWN; // themes are only trusted explicitly
        }

        $defaults = self::lines(self::DEFAULT_OFFICIAL);
        return in_array($slug, $defaults, true) ? self::OFFICIAL : self::UNKNOWN;
    }

    /**
     * Set the trust level for a slug (dashboard form).
     */
    public static function set(string $slug, string $level, string $kind = 'plugin'): void {
        $slug = strtolower(sanitize_file_name($slug));
        $level = self::normalize($level);
        if ($slug === '' || $level === '') {
            return;
        }
        $option = $kind === 'theme' ? 'watchdog_trust_themes' : 'watchdog_trust_plugins';
        $map = (array) get_option($option, []);
        if ($level === self::UNKNOWN) {
            unset($map[$slug]);
        } else {
            $map[$slug] = $level;
        }
        update_option($option, $map, false);
    }

    /**
     * Built-in known-good slugs as a list (single source for the scanner
     * and for the generated MU guard).
     *
     * @return array<int, string>
     */
    public static function defaultOfficial(): array {
        return self::lines(self::DEFAULT_OFFICIAL);
    }

    /**
     * All slugs installed on the site (folder names).
     *
     * @return array<int, array{slug: string, kind: string, level: string}>
     */
    public static function installed(): array {
        $out = [];

        $pluginsDir = rtrim((string) WP_PLUGIN_DIR, '/\\');
        if (is_dir($pluginsDir)) {
            foreach (scandir($pluginsDir, SCANDIR_SORT_ASCENDING) ?: [] as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                if (is_dir($pluginsDir . DIRECTORY_SEPARATOR . $entry)) {
                    $out[] = ['slug' => $entry, 'kind' => 'plugin', 'level' => self::level($entry, 'plugin')];
                } elseif (preg_match('/\.php$/', $entry)) {
                    $slug = pathinfo($entry, PATHINFO_FILENAME);
                    $out[] = ['slug' => $slug, 'kind' => 'plugin', 'level' => self::level($slug, 'plugin')];
                }
            }
        }

        $themesDir = rtrim((string) WP_CONTENT_DIR, '/\\') . DIRECTORY_SEPARATOR . 'themes';
        if (is_dir($themesDir)) {
            foreach (scandir($themesDir, SCANDIR_SORT_ASCENDING) ?: [] as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                if (is_dir($themesDir . DIRECTORY_SEPARATOR . $entry)) {
                    $out[] = ['slug' => $entry, 'kind' => 'theme', 'level' => self::level($entry, 'theme')];
                }
            }
        }

        return $out;
    }

    /**
     * Unknown (higher-scrutiny) sources for the given origin map.
     */
    public static function originUnknown(array $origin): bool {
        if (!empty($origin['plugin'])) {
            return self::level($origin['plugin'], 'plugin') === self::UNKNOWN;
        }
        if (!empty($origin['theme'])) {
            return self::level($origin['theme'], 'theme') === self::UNKNOWN;
        }
        return false;
    }

    /**
     * Persist the trust tables submitted by the dashboard settings form.
     * Only installed slugs are stored; unknown selections unset the entry.
     */
    public static function saveFromRequest(array $plugins, array $themes): void {
        $map = [];
        foreach ($plugins as $slug => $level) {
            $slug = strtolower(sanitize_file_name((string) $slug));
            $level = self::normalize((string) $level);
            if ($slug !== '' && $level !== self::UNKNOWN) {
                $map[$slug] = $level;
            }
        }
        update_option('watchdog_trust_plugins', $map, false);

        $map = [];
        foreach ($themes as $slug => $level) {
            $slug = strtolower(sanitize_file_name((string) $slug));
            $level = self::normalize((string) $level);
            if ($slug !== '' && $level !== self::UNKNOWN) {
                $map[$slug] = $level;
            }
        }
        update_option('watchdog_trust_themes', $map, false);
    }

    /**
     * Count installed packages at a given trust level.
     */
    public static function installedCount(string $kind, string $level): int {
        $count = 0;
        foreach (self::installed() as $item) {
            if ($item['kind'] === $kind && $item['level'] === $level) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Non-empty trimmed lines of a multi-line string.
     */
    public static function lines(string $raw): array {
        $out = [];
        foreach (explode("\n", $raw) as $line) {
            $line = strtolower(trim($line));
            if ($line !== '') {
                $out[] = $line;
            }
        }
        return $out;
    }

    /**
     * Normalize a level value; unknown levels map to UNKNOWN.
     */
    private static function normalize(string $level): string {
        $level = strtolower(trim($level));
        if ($level === self::OFFICIAL || $level === self::TRUSTED) {
            return $level;
        }
        return self::UNKNOWN;
    }
}
