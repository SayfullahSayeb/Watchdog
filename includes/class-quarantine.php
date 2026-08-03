<?php
/**
 * Quarantine: move infected files out of the web tree (with backup copy),
 * disable plugins, rename plugin folders and restore on demand.
 * Nothing is ever deleted automatically.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * Quarantine
 */
final class Quarantine {

    public const DIR_NAME = 'watchdog-quarantine';
    private const MAP_OPTION = 'watchdog_quarantine_map';

    /**
     * Quarantine directory. Can be moved outside the web root via the
     * 'watchdog_quarantine_dir' filter (recommended on nginx where
     * .htaccess is ignored).
     */
    public static function dir(): string {
        return (string) apply_filters(
            'watchdog_quarantine_dir',
            WP_CONTENT_DIR . DIRECTORY_SEPARATOR . self::DIR_NAME
        );
    }

    /**
     * Create the directory with denial + silence files. When the directory
     * is inside the web root, deny direct access via .htaccess and
     * .user.ini (the latter also covers some non-Apache setups).
     */
    public static function ensureDir(): void {
        $dir = self::dir();
        if (!wp_mkdir_p($dir)) {
            return;
        }
        if (!file_exists($dir . '/.htaccess')) {
            @file_put_contents($dir . '/.htaccess', "Require all denied\n");
        }
        if (!file_exists($dir . '/.user.ini')) {
            @file_put_contents($dir . '/.user.ini', "; Watchdog quarantine protection\n; Block direct execution of quarantined files.\n");
        }
        if (!file_exists($dir . '/index.php')) {
            @file_put_contents($dir . '/index.php', "<?php // Silence is golden.\n");
        }
    }

    /**
     * Move a file into quarantine, keeping a backup copy next to it.
     *
     * Only plugin, theme and upload files can be quarantined; core files
     * (wp-config.php, wp-includes, root files) and the quarantine
     * directory itself are never touched.
     *
     * @return array{name: string, original: string}|false
     */
    public static function quarantineFile(string $path): ?array {
        self::ensureDir();
        $path = realpath($path);
        if (!$path || !is_file($path)) {
            return null;
        }
        $abspath = realpath(ABSPATH);
        if (!$abspath || strpos($path, $abspath) !== 0) {
            return null;
        }
        if (strpos($path, realpath(self::dir())) === 0) {
            return null;
        }
        if (!self::insideContentTree($path)) {
            return null;
        }

        $name = sanitize_file_name(basename($path)) . '.' . gmdate('YmdHis') . '.quarantined';
        $target = self::dir() . DIRECTORY_SEPARATOR . $name;

        // Backup copy before the move (never delete automatically).
        if (!@copy($path, $target . '.bak')) {
            return null;
        }
        if (!@rename($path, $target)) {
            return null;
        }

        self::addToMap($name, $path);
        return ['name' => $name, 'original' => $path];
    }

    /**
     * True when a path lives under plugins, themes or uploads.
     */
    private static function insideContentTree(string $path): bool {
        $bases = [
            realpath(WP_PLUGIN_DIR),
            realpath(WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'themes'),
            realpath(WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'uploads'),
        ];
        foreach ($bases as $base) {
            if ($base && strpos($path, $base . DIRECTORY_SEPARATOR) === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Restore a quarantined file to its original location.
     */
    public static function restore(string $name): bool {
        $name = basename(sanitize_file_name($name));
        $map = self::map();
        $original = isset($map[$name]) ? $map[$name] : '';

        $target = self::dir() . DIRECTORY_SEPARATOR . $name;
        if (!is_file($target)) {
            return false;
        }

        if ($original === '' || !is_dir(dirname($original))) {
            $original = ABSPATH . ltrim($name, '/\\');
        }

        if (file_exists($original)) {
            return false; // never overwrite an existing file
        }
        if (!@rename($target, $original)) {
            return false;
        }

        self::removeFromMap($name);
        Logger::log('restored', 'info', $original, ['quarantine_file' => $name]);
        return true;
    }

    /**
     * List quarantined files.
     *
     * @return array<int, array{name: string, original: string, size: int, mtime: int}>
     */
    public static function list(): array {
        $dir = self::dir();
        if (!is_dir($dir)) {
            return [];
        }
        $map = self::map();
        $items = [];
        foreach (glob($dir . DIRECTORY_SEPARATOR . '*.quarantined') ?: [] as $file) {
            $name = basename($file);
            $items[] = [
                'name'     => $name,
                'original' => isset($map[$name]) ? $map[$name] : '',
                'size'     => (int) @filesize($file),
                'mtime'    => (int) @filemtime($file),
            ];
        }
        usort($items, static function ($a, $b) {
            return $b['mtime'] <=> $a['mtime'];
        });
        return $items;
    }

    /**
     * Deactivate a plugin.
     */
    public static function disablePlugin(string $pluginFile): bool {
        $pluginFile = plugin_basename($pluginFile);
        if ($pluginFile === '' || strpos($pluginFile, '..') !== false || !file_exists(WP_PLUGIN_DIR . '/' . $pluginFile)) {
            return false;
        }
        deactivate_plugins($pluginFile);
        return true;
    }

    /**
     * Stream a zip of all quarantined files (download).
     */
    public static function exportZip(): void {
        $items = self::list();
        if (!$items || !class_exists('ZipArchive')) {
            status_header(404);
            echo 'No quarantined files or ZipArchive unavailable.';
            exit;
        }

        $zipFile = get_temp_dir() . 'watchdog-export-' . bin2hex(random_bytes(6)) . '.zip';
        $zip = new \ZipArchive();
        if ($zip->open($zipFile, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== true) {
            status_header(500);
            echo 'Unable to create archive.';
            exit;
        }
        foreach ($items as $item) {
            $path = self::dir() . DIRECTORY_SEPARATOR . $item['name'];
            if (is_file($path)) {
                $zip->addFile($path, $item['name']);
            }
        }
        $zip->close();

        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="watchdog-quarantine-' . gmdate('Ymd-His') . '.zip"');
        header('Content-Length: ' . (string) @filesize($zipFile));
        @readfile($zipFile);
        @unlink($zipFile);
        exit;
    }

    /**
     * Number of quarantined files (dashboard badge).
     */
    public static function count(): int {
        $dir = self::dir();
        if (!is_dir($dir)) {
            return 0;
        }
        return count(glob($dir . DIRECTORY_SEPARATOR . '*.quarantined') ?: []);
    }

    /**
     * Rename a plugin folder to a .disabled suffix. All plugins inside are
     * deactivated first.
     */
    public static function renamePluginFolder(string $pluginFile): bool {
        $pluginFile = plugin_basename($pluginFile);
        if ($pluginFile === '' || strpos($pluginFile, '..') !== false || !file_exists(WP_PLUGIN_DIR . '/' . $pluginFile)) {
            return false;
        }

        $folder = WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . dirname($pluginFile);
        if (!is_dir($folder)) {
            return false;
        }

        $basename = basename($folder);
        if (!preg_match('/^[a-z0-9._-]+$/i', $basename)) {
            return false;
        }

        deactivate_plugins([$pluginFile], false, true);

        $newName = $basename . '.disabled-' . gmdate('YmdHis');
        if (!@rename($folder, WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $newName)) {
            return false;
        }

        Logger::log('plugin_renamed', 'critical', $pluginFile, ['renamed_to' => $newName]);
        return true;
    }

    /**
     * Find the main plugin file for a path inside the plugins directory.
     */
    public static function pluginMainFile(string $path): ?string {
        $path = realpath($path);
        if (!$path) {
            return null;
        }
        $plugins = realpath(WP_PLUGIN_DIR);
        if (!$plugins || strpos($path, $plugins) !== 0) {
            return null;
        }

        if (!is_dir($path)) {
            $path = dirname($path);
        }
        if (!is_dir($path)) {
            return null;
        }

        foreach (glob($path . '/*.php') as $file) {
            if (is_file($file) && is_readable($file)) {
                $data = get_plugin_data($file, false, false);
                if (!empty($data['Name'])) {
                    return plugin_basename($file);
                }
            }
        }
        $guess = $path . DIRECTORY_SEPARATOR . basename($path) . '.php';
        if (is_file($guess)) {
            return plugin_basename($guess);
        }
        return null;
    }

    /**
     * quarantine filename => original path.
     */
    public static function map(): array {
        return (array) get_option(self::MAP_OPTION, []);
    }

    private static function addToMap(string $name, string $original): void {
        $map = self::map();
        $map[$name] = $original;
        update_option(self::MAP_OPTION, $map, false);
    }

    private static function removeFromMap(string $name): void {
        $map = self::map();
        if (isset($map[$name])) {
            unset($map[$name]);
            update_option(self::MAP_OPTION, $map, false);
        }
    }
}
