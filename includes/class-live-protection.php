<?php
/**
 * LiveProtection: reacts the moment files change — without running full
 * scans inside the triggering request.
 *
 * Every file-change event debounces a background incremental scan and
 * queues targeted verification of exactly the changed package (Secure
 * Update Verification). Only cheap, single-file checks (uploads) run
 * synchronously.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * LiveProtection
 */
final class LiveProtection {

    public static function init(): void {
        add_action('upgrader_process_complete', [self::class, 'onUpgrade'], 10, 2);
        add_action('activated_plugin', [self::class, 'onPluginActivated'], 10, 2);
        add_action('switch_theme', [self::class, 'onThemeSwitch'], 10, 2);
        add_action('save_post', [self::class, 'onSavePost'], 10, 1);
        add_action('updated_option', [self::class, 'onUpdatedOption'], 10, 3);
    }

    /**
     * After any update (core, plugin, theme): queue targeted verification
     * of the changed package and a debounced incremental scan. The update
     * request itself is never blocked by scanning.
     */
    public static function onUpgrade($upgrader, $hookExtra): void {
        $type = isset($hookExtra['type']) ? (string) $hookExtra['type'] : '';
        $plugin = isset($hookExtra['plugin']) ? (string) $hookExtra['plugin'] : '';
        $theme = isset($hookExtra['theme']) ? (string) $hookExtra['theme'] : '';

        if ($type === 'core') {
            update_option('watchdog_pending_core_verify', 1, false);
        } elseif ($type === 'plugin' && $plugin !== '') {
            $slug = strtolower(dirname($plugin));
            self::queueVerification('plugin', $slug);
            self::queueDirScan(WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $slug);
        } elseif ($type === 'theme' && $theme !== '') {
            self::queueVerification('theme', strtolower((string) $theme));
            self::queueDirScan(WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . $theme);
        }

        Cron::debounce();
    }

    /**
     * When a plugin is activated: queue a targeted scan of its folder.
     * If CRITICAL findings appear, the plugin is deactivated, files are
     * quarantined and the admin is alerted — all from the background
     * scan, never during activation itself.
     */
    public static function onPluginActivated($plugin, $networkWide): void {
        $dir = realpath(WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . dirname((string) $plugin));
        if ($dir && is_dir($dir)) {
            self::queueDirScan($dir, (string) $plugin);
        }
        Cron::debounce();
    }

    /**
     * Theme switch: queue a targeted scan of the new theme.
     */
    public static function onThemeSwitch($newName, $newTheme): void {
        $dir = $newTheme instanceof \WP_Theme ? $newTheme->get_stylesheet_directory() : '';
        if ($dir !== '' && is_dir($dir)) {
            self::queueDirScan($dir);
        }
        Cron::debounce();
    }

    /**
     * Scan a newly uploaded attachment synchronously (single file, cheap)
     * so infected uploads are quarantined immediately.
     */
    public static function onSavePost($postId): void {
        if (get_post_type($postId) !== 'attachment') {
            return;
        }
        $file = get_attached_file((int) $postId);
        if (!$file || !is_file($file)) {
            return;
        }

        $scan = Scanner::scanFile($file);
        if ($scan['severity'] !== 'critical') {
            return;
        }

        $result = Quarantine::quarantineFile($file);
        $body = '<p>Watchdog quarantined an uploaded file with critical signatures:</p>'
            . '<p>' . esc_html($file) . '</p>'
            . '<p>Signatures: ' . esc_html(implode(', ', $scan['signatures'])) . '</p>';

        Reporter::alert('Watchdog quarantined infected upload', $body);
        Logger::log('upload_quarantined', 'critical', $file, [
            'signatures'      => $scan['signatures'],
            'quarantine_file' => $result ? $result['name'] : '',
        ]);
    }

    /**
     * Rescan when plugin options change (activation lists etc.). Our own
     * options are ignored to avoid feedback loops. Debounced, never
     * synchronous.
     */
    public static function onUpdatedOption($option, $oldValue, $newValue): void {
        if (strpos((string) $option, 'watchdog') === 0) {
            return;
        }
        if (!in_array((string) $option, ['active_plugins', 'recently_activated', 'uninstall_plugins'], true)) {
            return;
        }
        Cron::debounce();
    }

    /**
     * Queue a package verification (runs from the background cron).
     */
    public static function queueVerification(string $kind, string $slug): void {
        if ($slug === '' || $slug === 'wp' || $slug === 'wp-cli') {
            return;
        }
        $pending = (array) get_option('watchdog_pending_verify', []);
        $pending[$kind . ':' . $slug] = time();
        update_option('watchdog_pending_verify', $pending, false);
    }

    /**
     * Queue verification of every installed plugin and theme (dashboard
     * "Verify All" action). Returns the number of queued packages.
     */
    public static function queueAllVerifications(): int {
        $count = 0;
        foreach (array_keys(get_plugins()) as $pluginFile) {
            $slug = strtolower(dirname($pluginFile));
            if ($slug !== '' && $slug !== '.') {
                self::queueVerification('plugin', $slug);
                $count++;
            }
        }
        foreach (wp_get_themes() as $slug => $theme) {
            self::queueVerification('theme', strtolower((string) $slug));
            $count++;
        }
        Checksums::markInstalledCount($count);
        return $count;
    }

    /**
     * Queue a targeted directory scan (runs from the background cron).
     */
    public static function queueDirScan(string $dir, string $plugin = ''): void {
        $dir = realpath($dir);
        if (!$dir || !is_dir($dir)) {
            return;
        }
        $pending = (array) get_option('watchdog_pending_dirs', []);
        $pending[$dir] = ['dir' => $dir, 'plugin' => $plugin, 'queued' => time()];
        update_option('watchdog_pending_dirs', $pending, false);
    }

    /**
     * Process queued verifications and targeted directory scans.
     * Called from the background cron; respects the scan lock.
     */
    public static function processQueue(): void {
        if (Scanner::scanLocked()) {
            return;
        }

        $dirs = (array) get_option('watchdog_pending_dirs', []);
        if ($dirs) {
            foreach ($dirs as $item) {
                if (empty($item['dir']) || !is_dir($item['dir'])) {
                    continue;
                }
                self::handleDirScan($item['dir'], isset($item['plugin']) ? (string) $item['plugin'] : '');
            }
            delete_option('watchdog_pending_dirs');
        }

        $pending = (array) get_option('watchdog_pending_verify', []);
        if ($pending) {
            foreach ($pending as $key => $unused) {
                $parts = explode(':', $key, 2);
                if (count($parts) === 2) {
                    Checksums::verifyPackage($parts[0], $parts[1]);
                }
            }
            delete_option('watchdog_pending_verify');
        }
    }

    /**
     * Targeted scan of one directory; act on CRITICAL findings.
     */
    private static function handleDirScan(string $dir, string $plugin): void {
        $critical = self::scanDirForCritical($dir);
        if (empty($critical)) {
            return;
        }

        if ($plugin !== '') {
            Quarantine::disablePlugin($plugin);
        }

        $quarantined = [];
        foreach ($critical as $path => $data) {
            $result = Quarantine::quarantineFile($path);
            if ($result !== null) {
                $quarantined[] = $path;
            }
            foreach ((array) ($data['redirects'] ?? []) as $finding) {
                if (isset($finding['confidence']) && in_array($finding['confidence'], [ExecutionContext::CONFIDENCE_HIGH, ExecutionContext::CONFIDENCE_CRITICAL], true)) {
                    $finding['path'] = $path;
                    Reporter::incident($finding);
                }
            }
        }

        $body = '<p>Watchdog found critical signatures in <strong>' . esc_html($plugin !== '' ? $plugin : basename($dir)) . '</strong>.</p><ul>';
        foreach ($critical as $path => $data) {
            $body .= '<li>' . esc_html($path) . ' — ' . esc_html(implode(', ', $data['signatures'])) . '</li>';
        }
        $body .= '</ul>';

        Reporter::alert('Watchdog: critical signatures after update', $body);
        Logger::log('plugin_activation_blocked', 'critical', $plugin !== '' ? $plugin : $dir, [
            'files'       => array_keys($critical),
            'quarantined' => $quarantined,
        ]);
    }

    /**
     * Walk a directory (respecting scan rules) and return CRITICAL files.
     */
    private static function scanDirForCritical(string $dir): array {
        $critical = [];
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $path = $file->getRealPath();
                if (!$path || Scanner::isSkipped($path)) {
                    continue;
                }
                $scan = Scanner::scanFile($path);
                if ($scan['severity'] === 'critical') {
                    $critical[$path] = $scan;
                }
            }
        } catch (\Exception $e) {
            error_log('Watchdog live protection error: ' . $e->getMessage());
        }
        return $critical;
    }
}
