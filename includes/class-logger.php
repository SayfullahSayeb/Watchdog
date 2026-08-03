<?php
/**
 * Event logger. Writes security events to a dedicated table and queries
 * them for the dashboard timeline and statistics. All SQL is prepared.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * Logger
 */
final class Logger {

    private const TABLE = 'watchdog_events';
    private const NOTICE_TRANSIENT = 'watchdog_notice';

    /**
     * Full table name including WP prefix.
     */
    public static function table(): string {
        global $wpdb;
        return $wpdb->prefix . self::TABLE;
    }

    /**
     * Create the events table (dbDelta, idempotent).
     */
    public static function install(): void {
        global $wpdb;
        $table = self::table();
        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            event_time DATETIME NOT NULL,
            type VARCHAR(40) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            source VARCHAR(255) NOT NULL DEFAULT '',
            details LONGTEXT NULL,
            ip VARCHAR(64) NOT NULL DEFAULT '',
            username VARCHAR(100) NOT NULL DEFAULT '',
            PRIMARY KEY  (id),
            KEY type (type),
            KEY severity (severity),
            KEY event_time (event_time)
        ) {$charset};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    /**
     * Insert one event. Returns the row id.
     *
     * @param string $type     Event type, e.g. malware_detected, redirect_blocked.
     * @param string $severity safe|info|warning|critical.
     * @param string $source   File path, plugin name or domain.
     * @param array  $details  Free-form detail map (json-encoded into column).
     */
    public static function log(string $type, string $severity, string $source = '', array $details = []): ?int {
        global $wpdb;

        if ($source === '') {
            $source = self::callingFile();
        }

        $ok = $wpdb->insert(
            self::table(),
            [
                'event_time' => current_time('mysql'),
                'type'       => self::cut($type, 40),
                'severity'   => self::cut($severity, 20),
                'source'     => self::cut($source, 255),
                'details'    => wp_json_encode($details),
                'ip'         => self::clientIp(),
                'username'   => self::currentUser(),
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s', '%s']
        );

        return $ok ? (int) $wpdb->insert_id : null;
    }

    /**
     * Latest events, newest first. Optional type filter.
     */
    public static function query(int $limit = 100, string $type = ''): array {
        global $wpdb;
        $table = self::table();
        $limit = max(1, min(500, $limit));

        if ($type !== '') {
            return (array) $wpdb->get_results(
                $wpdb->prepare("SELECT * FROM {$table} WHERE type = %s ORDER BY id DESC LIMIT %d", $type, $limit),
                ARRAY_A
            );
        }
        return (array) $wpdb->get_results(
            $wpdb->prepare("SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", $limit),
            ARRAY_A
        );
    }

    /**
     * Count events of a type since local midnight (dashboard "today" stats).
     */
    public static function countToday(string $type): int {
        global $wpdb;
        $table = self::table();
        $since = date('Y-m-d 00:00:00', current_time('timestamp'));
        return (int) $wpdb->get_var(
            $wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE type = %s AND event_time >= %s", $type, $since)
        );
    }

    /**
     * All events (optionally filtered) for CSV export.
     */
    public static function export(int $limit = 5000, string $type = ''): array {
        global $wpdb;
        $table = self::table();
        $limit = max(1, min(20000, $limit));

        if ($type !== '') {
            return (array) $wpdb->get_results(
                $wpdb->prepare("SELECT * FROM {$table} WHERE type = %s ORDER BY id DESC LIMIT %d", $type, $limit),
                ARRAY_A
            );
        }
        return (array) $wpdb->get_results(
            $wpdb->prepare("SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", $limit),
            ARRAY_A
        );
    }

    /**
     * Event counts grouped by severity for the last N days.
     */
    public static function severityCounts(int $days = 7): array {
        global $wpdb;
        $table = self::table();
        $since = gmdate('Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS);

        $rows = (array) $wpdb->get_results(
            $wpdb->prepare("SELECT severity, COUNT(*) AS c FROM {$table} WHERE event_time > %s GROUP BY severity", $since),
            ARRAY_A
        );

        $counts = ['critical' => 0, 'warning' => 0, 'info' => 0, 'safe' => 0];
        foreach ($rows as $row) {
            if (isset($counts[$row['severity']])) {
                $counts[$row['severity']] = (int) $row['c'];
            }
        }
        return $counts;
    }

    /**
     * Daily per-severity counts for the last N days (dashboard chart).
     *
     * @return array<int, array{date: string, critical: int, warning: int, info: int, safe: int}>
     */
    public static function severitySeries(int $days = 30): array {
        global $wpdb;
        $table = self::table();
        $days = max(7, min(90, $days));
        $since = gmdate('Y-m-d', time() - $days * DAY_IN_SECONDS);

        $rows = (array) $wpdb->get_results(
            $wpdb->prepare("SELECT DATE(event_time) AS d, severity, COUNT(*) AS c FROM {$table} WHERE event_time >= %s GROUP BY d, severity", $since),
            ARRAY_A
        );

        $byDate = [];
        foreach ($rows as $row) {
            $byDate[$row['d']][$row['severity']] = (int) $row['c'];
        }

        $series = [];
        for ($i = $days - 1; $i >= 0; $i--) {
            $date = gmdate('Y-m-d', time() - $i * DAY_IN_SECONDS);
            $day = isset($byDate[$date]) ? $byDate[$date] : [];
            $series[] = [
                'date'     => $date,
                'critical' => isset($day['critical']) ? $day['critical'] : 0,
                'warning'  => isset($day['warning']) ? $day['warning'] : 0,
                'info'     => isset($day['info']) ? $day['info'] : 0,
                'safe'     => isset($day['safe']) ? $day['safe'] : 0,
            ];
        }
        return $series;
    }

    /**
     * Delete events older than N days.
     */
    public static function prune(int $days = 180): void {
        global $wpdb;
        $table = self::table();
        $cutoff = gmdate('Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS);
        $wpdb->query(
            $wpdb->prepare("DELETE FROM {$table} WHERE event_time < %s", $cutoff)
        );
    }

    /**
     * Remove scan-result events. Called when a scan completes so the Threat
     * Logs and overview stats only ever show the findings of the last scan
     * (older scan results are dropped automatically).
     */
    public static function clearFindings(): void {
        global $wpdb;
        $wpdb->query(
            $wpdb->prepare('DELETE FROM ' . self::table() . ' WHERE type = %s', 'scan_finding')
        );
    }

    /**
     * One-shot admin notice shown on the next page load.
     */
    public static function notice(string $message): void {
        set_transient(self::NOTICE_TRANSIENT, $message, 60);
    }

    /**
     * Read the one-shot notice without consuming it (dashboard does this).
     */
    public static function consumeNotice(): string {
        $notice = get_transient(self::NOTICE_TRANSIENT);
        if ($notice !== false) {
            delete_transient(self::NOTICE_TRANSIENT);
            return (string) $notice;
        }
        return '';
    }

    /**
     * Best-effort mb-safe substring.
     */
    private static function cut(string $value, int $length): string {
        if (function_exists('mb_substr')) {
            return mb_substr($value, 0, $length);
        }
        return substr($value, 0, $length);
    }

    /**
     * Find the file (relative to the plugins dir) that triggered the log.
     * Uses WP_PLUGIN_DIR so custom plugin locations are resolved too.
     */
    private static function callingFile(): string {
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 6);
        $pluginDir = realpath(WP_PLUGIN_DIR);
        if ($pluginDir === false) {
            return '';
        }
        $pluginDir .= DIRECTORY_SEPARATOR;
        foreach ($backtrace as $frame) {
            if (isset($frame['file']) && strpos($frame['file'], $pluginDir) === 0) {
                return str_replace($pluginDir, '', $frame['file']);
            }
        }
        return '';
    }

    private static function clientIp(): string {
        return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
    }

    private static function currentUser(): string {
        $user = wp_get_current_user();
        return $user->exists() ? (string) $user->user_login : '';
    }
}