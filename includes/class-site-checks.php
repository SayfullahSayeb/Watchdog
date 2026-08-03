<?php
/**
 * SiteChecks: site-level checks mirroring the Wordfence "High Sensitivity"
 * scan option set.
 *
 * These checks do not map to files — they inspect configuration, users,
 * passwords, posts/comments content, versions, disk space and file
 * locations. All checks are enabled by default (the Wordfence High
 * Sensitivity equivalent); each one can be disabled from the settings
 * page. Results are stored with the scan summary and rendered on the
 * dashboard and in scan report emails.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * SiteChecks
 */
final class SiteChecks {

    /**
     * Check id => human-readable settings label. Every check defaults to
     * ON, matching Wordfence's High Sensitivity scan type.
     */
    public const OPTIONS = [
        'watchdog_check_readable_config'    => 'Check for publicly readable configuration files',
        'watchdog_check_suspicious_options' => 'Check for suspicious WordPress options',
        'watchdog_check_suspicious_users'   => 'Check for suspicious admin users',
        'watchdog_check_passwords'          => 'Check admin passwords against known weak passwords',
        'watchdog_check_posts'              => 'Scan posts and comments for spam/malware content',
        'watchdog_check_old_versions'       => 'Check for outdated WordPress core',
        'watchdog_check_disk_space'         => 'Check disk space',
        'watchdog_check_suspected_files'    => 'Check for suspected files (PHP in uploads, shell names)',
        'watchdog_scan_images'              => 'Scan images and binaries as if executable (High Sensitivity)',
        'watchdog_scan_outside'             => 'Scan files outside the WordPress installation (High Sensitivity)',
    ];

    private const SPAM_PATTERNS = [
        'Hidden spam iframe'     => '/<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0)/i',
        'Hidden SEO link'        => '/<a[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|position\s*:\s*absolute|font-size\s*:\s*0)/i',
        'SEO spam keywords'      => '/\b(?:viagra|cialis|casino|nike|louis\s+vuitton|gucci|replica\s+watches)\b/i',
        'Crypto miner code'      => '/(?:coinhive|coin-hive|authedmine|webminepool|cryptoloot|reese84)/i',
        'Encoded payload'        => '/(?:base64_decode|gzinflate|gzuncompress|eval)\s*\(/i',
        'Link shortener'         => '/\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.me)\b/i',
    ];

    // Common weak passwords tested against admin hashes. Bounded on
    // purpose: bcrypt verification is slow, and Wordfence-equivalent
    // coverage of obvious credentials is the goal, not hash cracking.
    private const WEAK_PASSWORDS = [
        'admin', 'password', '123456', '12345678', '123456789',
        'password123', 'admin123', 'qwerty', 'letmein', 'welcome',
        '111111', 'abc123', '123123', 'iloveyou', '000000', 'password1',
    ];

    /**
     * Is the given check enabled? All default to ON (High Sensitivity).
     */
    public static function enabled(string $option): bool {
        return (int) get_option($option, 1) === 1;
    }

    /**
     * Run every enabled check with a shared time budget.
     *
     * @return array<int, array{id: string, sev: string, label: string,
     *                          details: string}>
     */
    public static function run(int $budgetSeconds = 25): array {
        $findings = [];
        $deadline = microtime(true) + max(5, $budgetSeconds);

        $checkers = [
            ['watchdog_check_readable_config', 'readableConfig'],
            ['watchdog_check_suspicious_options', 'suspiciousOptions'],
            ['watchdog_check_suspicious_users', 'suspiciousUsers'],
            ['watchdog_check_passwords', 'passwords'],
            ['watchdog_check_posts', 'postsComments'],
            ['watchdog_check_old_versions', 'oldVersions'],
            ['watchdog_check_disk_space', 'diskSpace'],
        ];
        foreach ($checkers as [$option, $method]) {
            if (microtime(true) > $deadline) {
                break;
            }
            if (!self::enabled($option)) {
                continue;
            }
            $found = self::$method();
            if (is_array($found)) {
                foreach ($found as $item) {
                    if (!is_array($item) || empty($item['id'])) {
                        continue;
                    }
                    $findings[] = [
                        'id'      => (string) $item['id'],
                        'sev'     => isset($item['sev']) ? (string) $item['sev'] : 'info',
                        'label'   => isset($item['label']) ? (string) $item['label'] : '',
                        'details' => isset($item['details']) ? (string) $item['details'] : '',
                    ];
                }
            }
        }

        // File-walk checks run last (they are the slowest) and only when
        // enough budget remains.
        if (microtime(true) <= $deadline && self::enabled('watchdog_check_suspected_files')) {
            foreach (self::suspectedFiles() as $item) {
                $findings[] = $item;
            }
        }
        if (microtime(true) <= $deadline && self::enabled('watchdog_scan_images')) {
            foreach (self::scanImages($deadline - microtime(true)) as $item) {
                $findings[] = $item;
            }
        }
        if (microtime(true) <= $deadline && self::enabled('watchdog_scan_outside')) {
            foreach (self::scanOutside($deadline - microtime(true)) as $item) {
                $findings[] = $item;
            }
        }

        return $findings;
    }

    /**
     * The reason a filename looks like a dropped shell, or ''.
     */
    public static function suspectedName(string $name): string {
        $phpExt = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar'];
        $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
        if (!in_array($ext, $phpExt, true)) {
            return '';
        }
        // WordPress core ships xmlrpc.php in the site root; the 'x' kit
        // prefix below would otherwise flag it.
        if (strtolower($name) === 'xmlrpc.php') {
            return '';
        }
        if (preg_match('/^[a-f0-9]{16,}\.php$/i', $name) === 1
            || preg_match('/^(?:x|c99|r57|wso|b374k)[a-z0-9_-]*\.php$/i', $name) === 1) {
            return 'Suspected webshell filename: ' . $name;
        }
        return '';
    }

    /**
     * WordPress.org's checksums/releases API exposes a version-check
     * endpoint; reuse the core checksum cache when present.
     *
     * @return array{id: string, sev: string, label: string, details: string}
     */
    private static function oldVersions(): array {
        $findings = [];

        $installed = function_exists('get_bloginfo') ? (string) get_bloginfo('version') : '';
        $latest = self::latestCoreVersion();
        if ($installed !== '' && $latest !== '' && version_compare($installed, $latest, '<')) {
            $sameMinor = substr($installed, 0, strrpos($installed, '.')) === substr($latest, 0, strrpos($latest, '.'));
            $findings[] = [
                'id'      => 'old_core_version',
                'sev'     => $sameMinor ? 'info' : 'warning',
                'label'   => 'WordPress core is outdated',
                'details' => 'Installed ' . $installed . ', latest release is ' . $latest . '.',
            ];
        }

        // Surfaced verification results (verifyPackage already compares
        // installed vs latest release for plugins/themes).
        $slugs = [];
        foreach (array_keys(function_exists('get_plugins') ? get_plugins() : []) as $file) {
            $slugs[] = 'plugin_' . dirname($file);
        }
        foreach (array_keys(function_exists('wp_get_themes') ? wp_get_themes() : []) as $slug) {
            $slugs[] = 'theme_' . $slug;
        }
        $count = 0;
        foreach ($slugs as $key) {
            if ($count >= 10) {
                break;
            }
            $result = Checksums::packageResult(...explode('_', $key, 2));
            if (isset($result['status']) && $result['status'] === 'version-mismatch') {
                $count++;
                $findings[] = [
                    'id'      => 'outdated_package',
                    'sev'     => 'info',
                    'label'   => ($key[0] === 't' ? 'Theme' : 'Plugin') . ' is not the latest version',
                    'details' => $key . ' (installed ' . (isset($result['version']) ? $result['version'] : '?') . ').',
                ];
            }
        }

        return $findings;
    }

    /**
     * Latest WordPress core release, cached 12h. Null on failure.
     */
    private static function latestCoreVersion(): string {
        $cache = get_transient('watchdog_core_latest');
        if (is_string($cache) && $cache !== '') {
            return $cache;
        }
        if (!function_exists('wp_remote_get')) {
            return '';
        }
        $response = wp_remote_get('https://api.wordpress.org/core/version-check/1.7/', ['timeout' => 8]);
        if (is_wp_error($response)) {
            return '';
        }
        $body = wp_remote_retrieve_body($response);
        $data = json_decode((string) $body, true);
        $version = isset($data['offers'][0]['version']) ? (string) $data['offers'][0]['version'] : '';
        if ($version !== '') {
            set_transient('watchdog_core_latest', $version, 12 * HOUR_IN_SECONDS);
        }
        return $version;
    }

    /**
     * Suspicious wp_options: open registration, privileged default role,
     * empty admin email, XML-RPC and disabled auto-updates.
     *
     * @return array
     */
    private static function suspiciousOptions(): array {
        $findings = [];

        if ((int) get_option('users_can_register', 0) === 1) {
            $findings[] = [
                'id'      => 'open_registration',
                'sev'     => 'warning',
                'label'   => 'Open user registration is enabled',
                'details' => 'Anyone can create an account. Combine with the default role setting below.',
            ];
        }
        $defaultRole = (string) get_option('default_role', 'subscriber');
        if ($defaultRole === 'administrator') {
            $findings[] = [
                'id'      => 'privileged_default_role',
                'sev'     => 'warning',
                'label'   => 'New users default to the Administrator role',
                'details' => 'options default_role is set to administrator.',
            ];
        }
        if (trim((string) get_option('admin_email', '')) === '') {
            $findings[] = [
                'id'      => 'empty_admin_email',
                'sev'     => 'warning',
                'label'   => 'The site admin email is empty',
                'details' => 'Set a valid admin email so security notices reach you.',
            ];
        }
        if (function_exists('apply_filters') && (bool) apply_filters('xmlrpc_enabled', true)) {
            $findings[] = [
                'id'      => 'xmlrpc_enabled',
                'sev'     => 'info',
                'label'   => 'XML-RPC is enabled',
                'details' => 'XML-RPC can be abused for brute force amplification; disable it if unused.',
            ];
        }
        if (!defined('DISALLOW_FILE_EDIT')) {
            $findings[] = [
                'id'      => 'file_edit_enabled',
                'sev'     => 'info',
                'label'   => 'The plugin/theme editor is enabled',
                'details' => 'Define DISALLOW_FILE_EDIT to harden against admin-account compromise.',
            ];
        }

        return $findings;
    }

    /**
     * Administrator accounts: default "admin" login, account count and
     * recently created admins.
     *
     * @return array
     */
    private static function suspiciousUsers(): array {
        $findings = [];
        if (!function_exists('get_users')) {
            return $findings;
        }
        $admins = get_users([
            'role'   => 'administrator',
            'fields' => ['ID', 'user_login', 'user_registered'],
        ]);
        if (!is_array($admins)) {
            return $findings;
        }
        $count = count($admins);
        if ($count === 0) {
            return $findings;
        }

        foreach ($admins as $admin) {
            $login = isset($admin->user_login) ? (string) $admin->user_login : '';
            if (strtolower($login) === 'admin') {
                $findings[] = [
                    'id'      => 'default_admin_user',
                    'sev'     => 'warning',
                    'label'   => 'Default administrator account "admin" exists',
                    'details' => 'Rename it and never use "admin" as a login.',
                ];
                break;
            }
        }

        if ($count > 3) {
            $findings[] = [
                'id'      => 'many_admins',
                'sev'     => 'info',
                'label'   => 'Site has ' . $count . ' administrator accounts',
                'details' => 'Review them: every admin account is an attack surface.',
            ];
        }

        $recent = 0;
        $threshold = time() - 30 * DAY_IN_SECONDS;
        foreach ($admins as $admin) {
            $registered = isset($admin->user_registered) ? strtotime((string) $admin->user_registered) : false;
            if ($registered !== false && $registered > $threshold) {
                $recent++;
            }
        }
        if ($recent > 0) {
            $findings[] = [
                'id'      => 'recent_admin',
                'sev'     => 'info',
                'label'   => $recent . ' administrator account(s) created in the last 30 days',
                'details' => 'Expected if you just hired help; verify otherwise.',
            ];
        }

        return $findings;
    }

    /**
     * Weak-password detection for administrator accounts using
     * wp_check_password against a common-password list.
     *
     * @return array
     */
    private static function passwords(): array {
        $findings = [];
        if (!function_exists('get_users') || !function_exists('wp_check_password')) {
            return $findings;
        }
        $admins = get_users([
            'role'   => 'administrator',
            'fields' => ['ID', 'user_login', 'user_pass'],
        ]);
        if (!is_array($admins)) {
            return $findings;
        }

        $deadline = microtime(true) + 8;
        foreach (array_slice($admins, 0, 20) as $admin) {
            if (microtime(true) > $deadline) {
                break;
            }
            $login = isset($admin->user_login) ? (string) $admin->user_login : '';
            $hash  = isset($admin->user_pass) ? (string) $admin->user_pass : '';
            $id    = isset($admin->ID) ? (int) $admin->ID : 0;
            if ($login === '' || $hash === '') {
                continue;
            }
            foreach (self::WEAK_PASSWORDS as $candidate) {
                if (@wp_check_password($candidate, $hash, $id)) {
                    $findings[] = [
                        'id'      => 'weak_admin_password',
                        'sev'     => 'warning',
                        'label'   => 'Administrator "' . $login . '" uses a weak password',
                        'details' => 'Matches the common password "' . $candidate . '". Change it immediately.',
                    ];
                    break;
                }
            }
        }

        return $findings;
    }

    /**
     * Posts and comments content scanned with the spam/malware pattern
     * set. Chunked and bounded; posts win over comments when the cap is
     * hit.
     *
     * @return array
     */
    private static function postsComments(): array {
        global $wpdb;
        $findings = [];
        if (!$wpdb || !function_exists('current_time')) {
            return $findings;
        }
        $cap = 20;
        $checked = 0;

        $limit = 1000;
        for ($offset = 0; $offset < 5000; $offset += $limit) {
            $rows = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT ID, post_title, post_content, post_status, post_type
                     FROM {$wpdb->posts}
                     WHERE post_content <> ''
                       AND post_status IN ('publish', 'pending', 'draft')
                     ORDER BY ID DESC
                     LIMIT %d OFFSET %d",
                    $limit,
                    $offset
                ),
                ARRAY_A
            );
            foreach ($rows as $row) {
                $checked++;
                if (count($findings) >= $cap) {
                    break 2;
                }
                $label = self::matchSpam((string) $row['post_content']);
                if ($label !== '') {
                    $findings[] = [
                        'id'      => 'suspicious_post',
                        'sev'     => 'warning',
                        'label'   => 'Suspicious content in post: ' . $label,
                        'details' => 'Post #' . (int) $row['ID'] . ' "' . mb_substr((string) $row['post_title'], 0, 80) . '" (' . $row['post_type'] . '/' . $row['post_status'] . ')',
                    ];
                }
            }
        }

        for ($offset = 0; $offset < 5000 && count($findings) < $cap; $offset += $limit) {
            $rows = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT comment_ID, comment_content
                     FROM {$wpdb->comments}
                     WHERE comment_approved = '1'
                     ORDER BY comment_ID DESC
                     LIMIT %d OFFSET %d",
                    $limit,
                    $offset
                ),
                ARRAY_A
            );
            foreach ($rows as $row) {
                if (count($findings) >= $cap) {
                    break 2;
                }
                $label = self::matchSpam((string) $row['comment_content']);
                if ($label !== '') {
                    $findings[] = [
                        'id'      => 'suspicious_comment',
                        'sev'     => 'warning',
                        'label'   => 'Suspicious content in comment: ' . $label,
                        'details' => 'Comment #' . (int) $row['comment_ID'],
                    ];
                }
            }
        }

        return $findings;
    }

    /**
     * First spam/malware pattern matched by the content, or ''.
     */
    public static function matchSpam(string $content): string {
        foreach (self::SPAM_PATTERNS as $label => $pattern) {
            if (@preg_match($pattern, $content) === 1) {
                return $label;
            }
        }
        return '';
    }

    /**
     * Disk space: < 100 MB is a warning (scans and backups fail), < 1 GB
     * is informational.
     *
     * @return array
     */
    private static function diskSpace(): array {
        $free = @disk_free_space(ABSPATH);
        if ($free === false) {
            return [];
        }
        if ($free < 100 * 1024 * 1024) {
            return [[
                'id'      => 'disk_space',
                'sev'     => 'warning',
                'label'   => 'Very low disk space',
                'details' => number_format($free / (1024 * 1024), 1) . ' MB free — backups and scans will fail soon.',
            ]];
        }
        if ($free < 1024 * 1024 * 1024) {
            return [[
                'id'      => 'disk_space',
                'sev'     => 'info',
                'label'   => 'Low disk space',
                'details' => number_format($free / (1024 * 1024), 1) . ' MB free.',
            ]];
        }
        return [];
    }

    /**
     * Publicly readable configuration: HTTP probe of wp-config.php (and
     * .htaccess when present) plus overly-permissive file permissions as
     * a fallback when probing is not possible.
     *
     * @return array
     */
    private static function readableConfig(): array {
        $findings = [];

        $probed = false;
        if (function_exists('wp_remote_get') && function_exists('site_url') && function_exists('wp_remote_retrieve_response_code') && function_exists('wp_remote_retrieve_body')) {
            $probed = true;
            foreach (['/wp-config.php', '/.htaccess'] as $probePath) {
                $abs = ABSPATH . ltrim($probePath, '/');
                if (!file_exists($abs)) {
                    continue;
                }
                $response = wp_remote_get(site_url($probePath), [
                    'timeout'     => 6,
                    'redirection' => 0,
                    'sslverify'   => true,
                ]);
                if (is_wp_error($response)) {
                    continue;
                }
                $code = (int) wp_remote_retrieve_response_code($response);
                if ($code === 200) {
                    $body = (string) wp_remote_retrieve_body($response);
                    $exposed = strpos($body, 'DB_NAME') !== false
                        || strpos($body, 'DB_PASSWORD') !== false
                        || strpos($body, 'ABSPATH') !== false
                        || strpos($body, 'DB_HOST') !== false;
                    $findings[] = [
                        'id'      => 'readable_config',
                        'sev'     => $exposed ? 'warning' : 'info',
                        'label'   => 'Configuration file responds over HTTP: ' . $probePath,
                        'details' => $exposed
                            ? 'The server returned the file contents — restrict access immediately.'
                            : 'HTTP 200 with no obvious secrets; verify manually.',
                    ];
                }
            }
        }

        if (!$probed) {
            foreach (['wp-config.php', '.htaccess', '.user.ini'] as $name) {
                $abs = ABSPATH . $name;
                if (!file_exists($abs) || !is_writable($abs)) {
                    continue;
                }
                $perms = @fileperms($abs);
                if ($perms !== false && (($perms & 0x0002) || ($perms & 0x0004))) {
                    $findings[] = [
                        'id'      => 'writable_config',
                        'sev'     => 'info',
                        'label'   => 'Configuration file is group/world writable: ' . $name,
                        'details' => 'Restrict permissions to the web server user only.',
                    ];
                }
            }
        }

        return $findings;
    }

    /**
     * Files that should not exist: PHP in uploads, double-extension
     * payloads, shell-named files in the site root.
     *
     * @return array
     */
    public static function suspectedFiles(string $uploadsRoot = ''): array {
        $findings = [];
        $phpExt = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar'];

        $uploads = $uploadsRoot !== ''
            ? $uploadsRoot
            : (function_exists('wp_upload_dir') ? wp_upload_dir()['basedir'] : '');
        if ($uploads !== '' && is_dir($uploads)) {
            $it = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($uploads, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );
            $it->setMaxDepth(4);
            $seen = 0;
            foreach ($it as $file) {
                if (!$file->isFile() || $seen++ > 4000) {
                    continue;
                }
                $path = $file->getPathname();
                $name = $file->getFilename();
                $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
                if (!in_array($ext, $phpExt, true)) {
                    continue;
                }
                if ($file->getSize() > 2097152) {
                    continue;
                }
                $why = 'PHP file in the uploads directory';
                if (preg_match('/\.(?:jpg|jpeg|png|gif|webp|ico|pdf)\.php$/i', $name) === 1
                    || preg_match('/\.php\.(?:jpg|jpeg|png|gif|webp)$/i', $name) === 1) {
                    $why = 'Double-extension PHP payload';
                }
                $findings[] = [
                    'id'      => 'suspected_file',
                    'sev'     => 'warning',
                    'label'   => $why . ': ' . str_replace(ABSPATH, '', $path),
                    'details' => 'PHP must never execute from uploads.',
                ];
                if (count($findings) >= 25) {
                    break;
                }
            }
        }

        // Site root: webshell-shaped names.
        $root = rtrim(ABSPATH, '/\\');
        $items = @scandir($root);
        if (is_array($items)) {
            foreach ($items as $name) {
                if ($name === '.' || $name === '..') {
                    continue;
                }
                $why = self::suspectedName($name);
                if ($why === '') {
                    continue;
                }
                $findings[] = [
                    'id'      => 'suspected_file',
                    'sev'     => 'warning',
                    'label'   => $why,
                    'details' => 'Random/kit names are a hallmark of dropped shells.',
                ];
            }
        }

        return $findings;
    }

    /**
     * Images and binary files scanned for embedded PHP/JavaScript
     * payloads (Wordfence "scan images as if executable"). Bounded by
     * time; findings capped.
     *
     * @return array
     */
    public static function scanImages(float $budget = 15.0, string $root = ''): array {
        $findings = [];
        $deadline = microtime(true) + max(2.0, $budget);
        $exts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'ico', 'tiff', 'svg', 'pdf', 'zip', 'swf'];
        $checked = 0;
        $root = rtrim($root !== '' ? $root : ABSPATH, '/\\');
        if (!is_dir($root)) {
            return $findings;
        }

        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($it as $file) {
            if (microtime(true) > $deadline || $checked > 8000 || count($findings) >= 25) {
                break;
            }
            if (!$file->isFile()) {
                continue;
            }
            $path = $file->getPathname();
            if (Scanner::isSkipped($path)) {
                continue;
            }
            $ext = strtolower($file->getExtension());
            if (!in_array($ext, $exts, true)) {
                continue;
            }
            $size = $file->getSize();
            if ($size === false || $size === 0 || $size > 2097152) {
                continue;
            }
            $checked++;
            $content = @file_get_contents($path);
            if ($content === false) {
                continue;
            }
            $label = self::matchImagePayload($content);
            if ($label === '') {
                continue;
            }
            $critical = preg_match('/\b(?:eval|assert|base64_decode|system|shell_exec|passthru)\s*\(/i', $content) === 1;
            $findings[] = [
                'id'      => 'image_payload',
                'sev'     => $critical ? 'warning' : 'info',
                'label'   => 'Embedded payload in ' . $ext . ' file: ' . $label,
                'details' => str_replace(ABSPATH, '', $path) . ($critical ? ' — contains executable calls.' : ''),
            ];
        }

        return $findings;
    }

    /**
     * Detect an embedded executable payload in image/binary content.
     */
    public static function matchImagePayload(string $content): string {
        $content = (string) $content;
        if (strpos($content, '<?php') !== false || strpos($content, '<?=') !== false) {
            if (preg_match('/\b(?:eval|assert|base64_decode|system|shell_exec|passthru|gzinflate|gzuncompress)\s*\(/i', $content) === 1) {
                return 'PHP payload with executable calls';
            }
            return 'PHP code embedded in image';
        }
        if (strpos($content, '<script') !== false) {
            return 'JavaScript embedded in SVG/HTML payload';
        }
        if (preg_match('/(?:onload|onclick|onerror)\s*=\s*["\']?javascript:/i', $content) === 1) {
            return 'Event-handler JavaScript payload';
        }
        return '';
    }

    /**
     * Files outside the WordPress installation (parent directory walk,
     * bounded depth). Only signature-bearing files are reported.
     *
     * @return array
     */
    public static function scanOutside(float $budget = 10.0, string $parent = ''): array {
        $findings = [];
        $deadline = microtime(true) + max(2.0, $budget);
        $parent = str_replace('\\', '/', rtrim($parent !== '' ? $parent : dirname(rtrim(ABSPATH, '/\\')), '/\\'));
        $abspath = str_replace('\\', '/', rtrim(ABSPATH, '/\\'));
        if ($parent === $abspath || $parent === '/' || $parent === '' || !is_dir($parent)) {
            return $findings;
        }

        $phpExt = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar'];
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($parent, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );
        $it->setMaxDepth(2);
        foreach ($it as $file) {
            if (microtime(true) > $deadline || count($findings) >= 25) {
                break;
            }
            if (!$file->isFile()) {
                continue;
            }
            $path = str_replace('\\', '/', $file->getPathname());
            if (strpos($path . '/', $abspath . '/') === 0) {
                continue; // Inside the WordPress tree.
            }
            if (Scanner::isSkipped($path)) {
                continue;
            }
            $ext = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));
            if (!in_array($ext, $phpExt, true)) {
                continue;
            }
            $size = $file->getSize();
            if ($size === false || $size === 0 || $size > 2097152) {
                continue;
            }
            $content = @file_get_contents($path);
            if ($content === false) {
                continue;
            }
            $signatures = Heuristics::scan($content, $ext);
            if ($signatures === []) {
                continue;
            }
            $classification = Heuristics::classify($signatures);
            if ($classification['sev'] === '') {
                continue;
            }
            $findings[] = [
                'id'      => 'outside_wp',
                'sev'     => $classification['sev'] === 'critical' ? 'warning' : 'info',
                'label'   => 'Suspicious file outside WordPress: ' . str_replace($parent . '/', '', $path),
                'details' => implode(', ', array_slice($signatures, 0, 3)),
            ];
        }

        return $findings;
    }
}
