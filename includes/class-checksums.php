<?php
/**
 * Checksums: Secure Update Verification against official WordPress.org
 * packages.
 *
 *  - Core: wp-admin/wp-includes/root files are compared against the
 *    official core checksums API (cached 24h).
 *  - Plugins/themes: when the installed version matches the latest
 *    WordPress.org release, the official package zip is downloaded and
 *    every installed file is compared against it (hashmap cached 7d).
 *  - Packages that verify clean are marked 'official' in the trust model;
 *    packages not hosted on WordPress.org stay 'unknown' (higher
 *    scrutiny) — absence of a checksum match is never treated as proof
 *    of infection.
 *
 * All verification runs in the background cron or via explicit dashboard
 * actions — never in page-load requests. No telemetry leaves the site
 * other than requests to the official WordPress.org APIs.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * Checksums
 */
final class Checksums {

    private const CORE_CACHE_SECONDS = DAY_IN_SECONDS;
    private const PKG_CACHE_SECONDS = 7 * DAY_IN_SECONDS;
    private const MAX_ZIP_SIZE = 31457280; // 30 MB
    private const MAX_HASH_SIZE = 5242880; // 5 MB
    private const HTTP_TIMEOUT = 15;
    private const SUMMARY_OPTION = 'watchdog_verify_summary';

    /**
     * Transient showing which verification is running right now (label,
     * auto-expires so a crashed process never looks "stuck").
     */
    public const ACTIVE_TRANSIENT = 'watchdog_verify_active';

    /**
     * Mark a verification as currently running (dashboard live panel).
     */
    public static function markActive(string $label): void {
        set_transient(self::ACTIVE_TRANSIENT, $label, 120);
    }

    /**
     * Clear the running marker (verification finished).
     */
    public static function markIdle(): void {
        delete_transient(self::ACTIVE_TRANSIENT);
    }

    /**
     * Live verification status for the dashboard panel + AJAX poller.
     */
    public static function verifyStatus(): array {
        $core = self::coreVerifyResult();
        $active = get_transient(self::ACTIVE_TRANSIENT);
        $summary = (array) get_option(self::SUMMARY_OPTION, []);
        $packages = isset($summary['packages']) && is_array($summary['packages']) ? $summary['packages'] : [];

        $byStatus = [];
        $modified = [];
        foreach ($packages as $key => $status) {
            $status = (string) $status;
            $byStatus[$status] = (int) ($byStatus[$status] ?? 0) + 1;
            if ($status === 'modified') {
                $modified[] = $key;
            }
        }

        return [
            'active'   => is_string($active) ? $active : '',
            'core'     => [
                'result'   => $core,
                'pending'  => (int) get_option('watchdog_pending_core_verify', 0) > 0,
                'queuedAt' => (int) get_option('watchdog_pending_core_verify', 0),
            ],
            'packages' => [
                'queued'    => count((array) get_option('watchdog_pending_verify', [])),
                'installed' => (int) ($summary['installed'] ?? 0),
                'byStatus'  => $byStatus,
                'modified'  => $modified,
                'last'      => (int) ($summary['last'] ?? 0),
            ],
            'updated'  => time(),
        ];
    }

    /**
     * AJAX endpoint for the verification panel (live polling).
     */
    public static function ajaxVerifyStatus(): void {
        check_ajax_referer('watchdog_verify_status', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(null, 403);
        }
        wp_send_json_success(self::verifyStatus());
    }

    /**
     * Remember how many installed packages exist (used for the
     * "verified X of Y" display on the dashboard).
     */
    public static function markInstalledCount(int $count): void {
        $summary = (array) get_option(self::SUMMARY_OPTION, []);
        $summary['installed'] = $count;
        update_option(self::SUMMARY_OPTION, $summary, false);
    }

    /**
     * Verify WordPress core against the official checksums.
     *
     * @return array{time: int, verified: int, mismatches: array, missing: array, status: string}
     */
    public static function verifyCore(): array {
        self::markActive('core');
        $version = get_bloginfo('version');
        $locale = get_locale() !== '' ? get_locale() : 'en_US';
        $checksums = self::fetchCoreChecksums($version, $locale);

        $result = ['time' => time(), 'verified' => 0, 'mismatches' => [], 'missing' => [], 'status' => 'error'];
        if ($checksums === null) {
            update_option('watchdog_core_verify', $result, false);
            self::markIdle();
            return $result;
        }
        if (empty($checksums['checksums'])) {
            $result['status'] = 'unavailable';
            update_option('watchdog_core_verify', $result, false);
            self::markIdle();
            return $result;
        }

        $mismatches = [];
        $missing = [];
        $verified = 0;
        foreach ($checksums['checksums'] as $rel => $hash) {
            $local = ABSPATH . $rel;
            if (!is_file($local)) {
                $missing[] = $rel;
                continue;
            }
            $size = @filesize($local);
            if ($size === false || $size > self::MAX_HASH_SIZE) {
                continue;
            }
            $verified++;
            if (@hash_file('sha256', $local) !== $hash) {
                $mismatches[] = $rel;
            }
        }

        $result['verified'] = $verified;
        $result['mismatches'] = $mismatches;
        $result['missing'] = $missing;
        $result['status'] = empty($mismatches) ? 'clean' : 'modified';

        update_option('watchdog_core_verify', $result, false);
        Logger::log(
            $result['status'] === 'modified' ? 'core_modified' : 'core_verified',
            $result['status'] === 'modified' ? 'critical' : 'info',
            'wordpress-core ' . $version,
            ['verified' => $verified, 'mismatches' => $mismatches, 'missing' => $missing]
        );

        if (!empty($mismatches) && count($mismatches) <= 50) {
            Reporter::alert(
                'Watchdog: WordPress core files differ from official checksums',
                '<p>' . esc_html((string) count($mismatches)) . ' core file(s) differ from the official package:</p><ul>'
                . implode('', array_map(static function ($p) {
                    return '<li><code>' . esc_html($p) . '</code></li>';
                }, $mismatches))
                . '</ul>'
            );
        }

        self::markIdle();

        return $result;
    }

    /**
     * Verify one plugin or theme package against the official repository.
     *
     * @return array{status: string, version: string, checked: int, mismatches: array}
     */
    public static function verifyPackage(string $kind, string $slug): array {
        $kind = $kind === 'theme' ? 'theme' : 'plugin';
        $slug = strtolower(sanitize_file_name($slug));
        $result = ['status' => 'error', 'version' => '', 'checked' => 0, 'mismatches' => []];

        if ($slug === '') {
            return $result;
        }

        $installedDir = $kind === 'theme'
            ? WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . $slug
            : WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $slug;
        if (!is_dir($installedDir)) {
            return $result;
        }
        self::markActive($kind . ':' . $slug);

        $installedVersion = self::installedVersion($kind, $slug, $installedDir);
        $remote = self::fetchPackageInfo($kind, $slug);

        if ($remote === null || empty($remote['version'])) {
            // Not hosted on WordPress.org (or unreachable): stay unknown.
            $result['status'] = 'not-on-wordpress';
            self::storePackageResult($kind, $slug, $result);
            self::markIdle();
            return $result;
        }
        $result['version'] = (string) $remote['version'];

        // Only official WordPress.org download hosts are ever contacted.
        if (!self::isOfficialHost($remote['download_link'])) {
            $result['status'] = 'download-error';
            self::storePackageResult($kind, $slug, $result);
            self::markIdle();
            return $result;
        }

        if ($installedVersion !== '' && $installedVersion !== (string) $remote['version']) {
            // Installed version differs from the latest release: the
            // official zip cannot be compared directly. Not an error.
            $result['status'] = 'version-mismatch';
            self::storePackageResult($kind, $slug, $result);
            self::markIdle();
            return $result;
        }

        // Cached hashmap of the official package for this version.
        $cacheKey = 'watchdog_pkg_' . $kind . '_' . $slug . '_' . $remote['version'];
        $package = get_transient($cacheKey);
        if (!is_array($package)) {
            $package = self::downloadAndIndexPackage($remote['download_link']);
            if ($package === null) {
                $result['status'] = 'download-error';
                self::storePackageResult($kind, $slug, $result);
                self::markIdle();
                return $result;
            }
            set_transient($cacheKey, $package, self::PKG_CACHE_SECONDS);
        }
        // Version-stable map for scan-time known-good lookups.
        set_transient('watchdog_pkgmap_' . $kind . '_' . $slug, $package, self::PKG_CACHE_SECONDS);

        $mismatches = [];
        $checked = 0;
        foreach ($package as $rel => $hash) {
            $local = $installedDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
            if (!is_file($local)) {
                continue;
            }
            $size = @filesize($local);
            if ($size === false || $size > self::MAX_HASH_SIZE) {
                continue;
            }
            $checked++;
            if (@hash_file('sha256', $local) !== $hash) {
                $mismatches[] = $rel;
            }
        }

        $result['status'] = empty($mismatches) ? 'clean' : 'modified';
        $result['checked'] = $checked;
        $result['mismatches'] = $mismatches;
        self::storePackageResult($kind, $slug, $result);

        if ($result['status'] === 'clean') {
            Trust::set($slug, Trust::OFFICIAL, $kind);
            Logger::log('package_verified', 'info', $kind . ': ' . $slug, $result);
        } else {
            Logger::log('package_modified', 'critical', $kind . ': ' . $slug, $result);
            Reporter::alert(
                'Watchdog: modified files in ' . $kind . ' ' . $slug,
                '<p>' . esc_html((string) count($mismatches)) . ' file(s) in ' . esc_html($kind) . ' <strong>' . esc_html($slug) . '</strong> differ from the official package.</p>'
            );
        }

        self::markIdle();

        return $result;
    }

    /**
     * Last core verification result (dashboard).
     */
    public static function coreVerifyResult(): array {
        return (array) get_option('watchdog_core_verify', []);
    }

    /**
     * Is this file hash-verified against an official WordPress.org
     * package (core checksums or verified plugin/theme)?
     *
     * Mirrors how Wordfence treats known-good files: a file whose hash
     * matches the official package is clean by definition — heuristic
     * signature hits on it are false positives, because WordPress core
     * ships getID3 (gzuncompress + hex escapes), class-json.php (eval
     * fallback), backbone.js (RegExp.exec), oembed hidden iframes and
     * accessibility skip-links with display:none.
     *
     * @param string $absPath absolute path of the file
     * @param string $sha256   computed sha256 of its content
     */
    public static function knownGoodFile(string $absPath, string $sha256): bool {
        $absPath = str_replace('\\', '/', $absPath);
        $abspath = str_replace('\\', '/', ABSPATH);
        $rel = '';

        if ($abspath && strpos($absPath, $abspath) === 0) {
            $rel = ltrim(substr($absPath, strlen($abspath)), '/');
        }

        // 1) Hash-based proof: official core checksums (cached by
        //    fetchCoreChecksums when verification ran).
        if ($rel !== ''
            && (strpos($rel, 'wp-admin/') === 0 || strpos($rel, 'wp-includes/') === 0)
            && function_exists('get_bloginfo') && function_exists('get_locale')) {
            $cacheKey = 'watchdog_core_checksums_' . sanitize_key(get_bloginfo('version')) . '_' . sanitize_key(get_locale());
            $cached = get_transient($cacheKey);
            if (is_array($cached) && isset($cached['checksums']) && is_array($cached['checksums'])) {
                return isset($cached['checksums'][$rel])
                    && is_string($cached['checksums'][$rel])
                    && hash_equals((string) $cached['checksums'][$rel], (string) $sha256);
            }
        }

        // 2) Verified package: compare against the official hash map.
        //    The map is REQUIRED — a 'clean' status without a map must
        //    not trust files, because files outside the official zip
        //    (an injected backdoor next to a verified plugin) would
        //    otherwise be treated as known-good. A 'modified' result is
        //    never trusted either: we cannot prove the file is untouched
        //    official code.
        $origin = \Watchdog\RedirectEngine::originOf($absPath);
        if ($origin['plugin'] !== '') {
            $dir = str_replace('\\', '/', WP_PLUGIN_DIR) . '/' . $origin['plugin'] . '/';
            $relPath = strpos($absPath, $dir) === 0 ? substr($absPath, strlen($dir)) : '';
            if ($relPath !== '') {
                $map = get_transient('watchdog_pkgmap_plugin_' . $origin['plugin']);
                return is_array($map)
                    && isset($map[$relPath])
                    && is_string($map[$relPath])
                    && hash_equals($map[$relPath], (string) $sha256);
            }
            return false;
        }
        if ($origin['theme'] !== '') {
            $dir = str_replace('\\', '/', WP_CONTENT_DIR) . '/themes/' . $origin['theme'] . '/';
            $relPath = strpos($absPath, $dir) === 0 ? substr($absPath, strlen($dir)) : '';
            if ($relPath !== '') {
                $map = get_transient('watchdog_pkgmap_theme_' . $origin['theme']);
                return is_array($map)
                    && isset($map[$relPath])
                    && is_string($map[$relPath])
                    && hash_equals($map[$relPath], (string) $sha256);
            }
            return false;
        }

        return false;
    }

    /**
     * Path-based trust fallback for the official core tree when no
     * checksum data has been fetched yet. wp-admin/ and wp-includes/
     * ship with WordPress itself; a real backdoor inside core is a
     * *modified* file, which the checksum engine reports separately.
     * Root-level wp-*.php files are core too (wp-activate.php,
     * wp-comments-post.php, wp-login.php, ...). Critical signatures
     * are still honored (see Scanner).
     */
    public static function coreTreeTrust(string $absPath): bool {
        $absPath = str_replace('\\', '/', $absPath);
        $abspath = str_replace('\\', '/', ABSPATH);
        if (!$abspath || strpos($absPath, $abspath) !== 0) {
            return false;
        }
        $rel = ltrim(substr($absPath, strlen($abspath)), '/');
        if ($rel === '') {
            return false;
        }
        if (strpos($rel, 'wp-admin/') === 0 || strpos($rel, 'wp-includes/') === 0) {
            return true;
        }
        // Same root-file list as RedirectEngine::originOf().
        return preg_match('/^(?:index\.php|wp-config\.php|wp-config-sample\.php|wp-settings\.php|wp-load\.php|wp-login\.php|wp-cron\.php|wp-activate\.php|wp-comments-post\.php|wp-blog-header\.php|wp-mail\.php|wp-signup\.php|wp-trackback\.php|wp-links-opml\.php|xmlrpc\.php)$/i', $rel) === 1;
    }

    /**
     * Stored verification result for one package (dashboard).
     */
    public static function packageResult(string $kind, string $slug): array {
        return (array) get_option('watchdog_pkg_' . $kind . '_' . $slug, []);
    }

    /**
     * Fetch official core checksums for a version+locale (cached).
     */
    private static function fetchCoreChecksums(string $version, string $locale): ?array {
        $cacheKey = 'watchdog_core_checksums_' . sanitize_key($version) . '_' . sanitize_key($locale);
        $cached = get_transient($cacheKey);
        if (is_array($cached)) {
            return $cached;
        }

        $url = add_query_arg(
            ['version' => $version, 'locale' => $locale],
            'https://api.wordpress.org/core/checksums/1.0/'
        );
        $response = wp_remote_get($url, ['timeout' => self::HTTP_TIMEOUT, 'sslverify' => true]);
        if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }
        $data = json_decode(wp_remote_retrieve_body($response), true);
        if (!is_array($data)) {
            return null;
        }
        set_transient($cacheKey, $data, self::CORE_CACHE_SECONDS);
        return $data;
    }

    /**
     * Fetch package metadata from the WordPress.org API (cached 6h).
     */
    private static function fetchPackageInfo(string $kind, string $slug): ?array {
        $cacheKey = 'watchdog_pkg_info_' . $kind . '_' . $slug;
        $cached = get_transient($cacheKey);
        if (is_array($cached)) {
            return $cached;
        }

        $url = $kind === 'theme'
            ? 'https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]=' . rawurlencode($slug)
            : 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . rawurlencode($slug);

        $response = wp_remote_get($url, ['timeout' => self::HTTP_TIMEOUT, 'sslverify' => true]);
        if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }
        $data = json_decode(wp_remote_retrieve_body($response), true);
        if (!is_array($data)) {
            return null;
        }
        $info = [
            'version'       => isset($data['version']) ? (string) $data['version'] : '',
            'download_link' => isset($data['download_link']) ? (string) $data['download_link'] : '',
        ];
        if ($info['version'] === '' || $info['download_link'] === '') {
            return null;
        }
        set_transient($cacheKey, $info, 6 * HOUR_IN_SECONDS);
        return $info;
    }

    /**
     * Download the official package and index file hashes.
     *
     * Entries are validated against zip-slip traversal and only files up
     * to MAX_HASH_SIZE are read; no extraction to disk ever happens.
     *
     * @return array<string, string>|null relative path => sha256
     */
    private static function downloadAndIndexPackage(string $url): ?array {
        $zipFile = tempnam(get_temp_dir(), 'watchdog-');
        if ($zipFile === false) {
            return null;
        }

        $response = wp_remote_get($url, [
            'timeout'    => 60,
            'sslverify'  => true,
            'stream'     => true,
            'filename'   => $zipFile,
        ]);
        if (is_wp_error($response)) {
            @unlink($zipFile);
            return null;
        }
        $size = @filesize($zipFile);
        if ($size === false || $size > self::MAX_ZIP_SIZE) {
            @unlink($zipFile);
            return null;
        }

        $package = self::indexZip($zipFile);
        @unlink($zipFile);

        return $package;
    }

    /**
     * Index a package zip in memory: validate every entry path against
     * traversal (zip-slip), then hash files up to MAX_HASH_SIZE. No
     * entries are ever extracted to disk.
     *
     * @return array<string, string>|null relative path => sha256
     */
    public static function indexZip(string $zipFile): ?array {
        if (!class_exists('ZipArchive')) {
            return null;
        }
        $zip = new \ZipArchive();
        if ($zip->open($zipFile) !== true) {
            return null;
        }

        $package = [];
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = $zip->getNameIndex($i);
            if ($name === false || $name === '') {
                continue;
            }
            $norm = str_replace('\\', '/', $name);
            if (substr($norm, -1) === '/') {
                continue; // directory entry
            }
            if (self::unsafeZipEntry($norm)) {
                continue; // traversal / absolute / NUL — never touched
            }
            $rel = preg_replace('/^[^\/]+\//', '', $norm); // strip slug folder
            if ($rel === '') {
                continue;
            }
            $stat = $zip->statIndex($i);
            $entrySize = $stat === false ? 0 : (int) $stat['size'];
            if ($entrySize === 0 || $entrySize > self::MAX_HASH_SIZE) {
                continue;
            }
            $content = $zip->getFromIndex($i);
            if ($content === false) {
                continue;
            }
            $hash = hash('sha256', $content);
            if ($hash !== false) {
                $package[$rel] = $hash;
            }
        }
        $zip->close();

        return $package ? $package : null;
    }

    /**
     * Reject zip entries that escape the archive root: '..' segments,
     * absolute paths, drive letters, NUL bytes.
     */
    public static function unsafeZipEntry(string $name): bool {
        if (strpos($name, "\0") !== false) {
            return true;
        }
        $parts = explode('/', $name);
        foreach ($parts as $part) {
            if ($part === '..' || $part === '') {
                return true;
            }
            if (preg_match('/^[a-zA-Z]:$/', $part) === 1) {
                return true;
            }
        }
        return false;
    }

    /**
     * Only official WordPress.org download hosts are contacted.
     */
    private static function isOfficialHost(string $url): bool {
        $host = strtolower((string) wp_parse_url($url, PHP_URL_HOST));
        return $host === 'downloads.wordpress.org' || $host === 'wordpress.org' || substr($host, -strlen('.wordpress.org')) === '.wordpress.org';
    }

    /**
     * Installed version of a plugin/theme from its headers.
     */
    private static function installedVersion(string $kind, string $slug, string $dir): string {
        if ($kind === 'theme') {
            $theme = wp_get_theme($slug);
            return $theme->exists() ? (string) $theme->get('Version') : '';
        }
        foreach (glob($dir . DIRECTORY_SEPARATOR . '*.php') ?: [] as $file) {
            $data = get_plugin_data($file, false, false);
            if (!empty($data['Name']) && !empty($data['Version'])) {
                return (string) $data['Version'];
            }
        }
        return '';
    }

    /**
     * Persist a package verification result for the dashboard, and keep
     * the compact summary option the live panel polls.
     */
    private static function storePackageResult(string $kind, string $slug, array $result): void {
        $result['time'] = time();
        update_option('watchdog_pkg_' . $kind . '_' . $slug, $result, false);

        $summary = (array) get_option(self::SUMMARY_OPTION, []);
        $packages = isset($summary['packages']) && is_array($summary['packages']) ? $summary['packages'] : [];
        $packages[$kind . ':' . $slug] = isset($result['status']) ? (string) $result['status'] : 'error';
        $summary['packages'] = $packages;
        $summary['last'] = time();
        update_option(self::SUMMARY_OPTION, $summary, false);
    }
}
