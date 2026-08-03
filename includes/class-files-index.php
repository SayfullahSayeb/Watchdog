<?php
/**
 * FilesIndex: database-backed file index with per-file verdicts.
 *
 * One row per scanned file: path, hash, size, mtime, first/last seen and
 * the verdict (severity, class, label, signatures, redirects) produced by
 * the last content scan. This replaces the old in-option baseline and
 * result blobs, keeping scans and dashboard renders flat at any site size.
 *
 * All SQL is prepared.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * FilesIndex
 */
final class FilesIndex {

    private const TABLE = 'watchdog_files';
    private const RUNS_TABLE = 'watchdog_scan_runs';

    /**
     * Create both tables (dbDelta, idempotent).
     */
    public static function install(): void {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();

        $files = "CREATE TABLE {$wpdb->prefix}" . self::TABLE . " (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            path_hash CHAR(64) NOT NULL,
            path VARCHAR(767) NOT NULL,
            hash CHAR(64) NOT NULL DEFAULT '',
            size BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            mtime BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            severity VARCHAR(20) NOT NULL DEFAULT 'safe',
            verdict_class VARCHAR(20) NOT NULL DEFAULT '',
            label VARCHAR(255) NOT NULL DEFAULT '',
            signatures LONGTEXT NULL,
            redirects LONGTEXT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY path_hash (path_hash),
            KEY severity (severity),
            KEY last_seen (last_seen)
        ) {$charset};";

        $runs = "CREATE TABLE {$wpdb->prefix}" . self::RUNS_TABLE . " (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            started_at DATETIME NOT NULL,
            finished_at DATETIME NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'running',
            mode VARCHAR(20) NOT NULL DEFAULT 'incremental',
            total_files INT UNSIGNED NOT NULL DEFAULT 0,
            scanned_files INT UNSIGNED NOT NULL DEFAULT 0,
            result LONGTEXT NULL,
            PRIMARY KEY  (id)
        ) {$charset};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($files);
        dbDelta($runs);
        self::ensureIndexes();
    }

    /**
     * Get the index row for a path, or null.
     */
    public static function get(string $path): ?array {
        global $wpdb;
        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}" . self::TABLE . " WHERE path_hash = %s",
                hash('sha256', $path)
            ),
            ARRAY_A
        );
        return $row ? $row : null;
    }

    /**
     * Insert or update an index row.
     *
     * @param array{path: string, hash: string, size: int, mtime: int,
     *              severity: string, class: string, label: string,
     *              signatures: array, redirects: array} $data
     */
    public static function upsert(array $data): void {
        global $wpdb;
        $now = current_time('mysql');
        $row = self::get($data['path']);
        $existing = $row !== null;

        $fields = [
            'path'           => $data['path'],
            'hash'           => $data['hash'],
            'size'           => (int) $data['size'],
            'mtime'          => (int) $data['mtime'],
            'last_seen'      => $now,
            'severity'       => $data['severity'],
            'verdict_class'  => $data['class'],
            'label'          => isset($data['label']) ? (string) $data['label'] : '',
            'signatures'     => wp_json_encode($data['signatures']),
            'redirects'      => wp_json_encode($data['redirects']),
        ];

        if ($existing) {
            $fields['first_seen'] = $row['first_seen'];
            $wpdb->update(
                $wpdb->prefix . self::TABLE,
                $fields,
                ['id' => (int) $row['id']],
                ['%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s'],
                ['%d']
            );
            return;
        }

        $fields['first_seen'] = $now;
        $wpdb->insert($wpdb->prefix . self::TABLE, $fields, ['%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s']);
    }

    /**
     * Index rows for a set of paths (path => row) in bounded chunks, so
     * the scanner never loads the full index into memory on large sites.
     *
     * @param array<int, string> $paths
     *
     * @return array<string, array{path: string, hash: string, size: int, mtime: int, last_seen: string}>
     */
    public static function indexForPaths(array $paths): array {
        global $wpdb;
        $index = [];
        foreach (array_chunk($paths, 500) as $chunk) {
            $hashes = array_map(static function ($p) {
                return hash('sha256', (string) $p);
            }, $chunk);
            $placeholders = implode(', ', array_fill(0, count($hashes), '%s'));
            $rows = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT path, hash, size, mtime, last_seen FROM {$wpdb->prefix}" . self::TABLE . " WHERE path_hash IN ({$placeholders})",
                    $hashes
                ),
                ARRAY_A
            );
            foreach ($rows ?: [] as $row) {
                $index[$row['path']] = [
                    'path'      => $row['path'],
                    'hash'      => $row['hash'],
                    'size'      => (int) $row['size'],
                    'mtime'     => (int) $row['mtime'],
                    'last_seen' => $row['last_seen'],
                ];
            }
        }
        return $index;
    }

    /**
     * Bulk insert-or-update many rows (multi-row INSERT ... ON DUPLICATE
     * KEY UPDATE) so large scans do not issue one query per file.
     *
     * @param array<int, array{path: string, hash: string, size: int, mtime: int,
     *                         severity: string, class: string, label: string,
     *                         signatures: array, redirects: array}> $rows
     */
    public static function bulkUpsert(array $rows): void {
        global $wpdb;
        if (empty($rows)) {
            return;
        }
        $now = current_time('mysql');
        $values = [];
        $placeholders = [];
        foreach ($rows as $row) {
            $values[] = hash('sha256', $row['path']);
            $values[] = $row['path'];
            $values[] = $row['hash'];
            $values[] = (int) $row['size'];
            $values[] = (int) $row['mtime'];
            $values[] = $now;
            $values[] = $now;
            $values[] = $row['severity'];
            $values[] = $row['class'];
            $values[] = (string) $row['label'];
            $values[] = wp_json_encode($row['signatures']);
            $values[] = wp_json_encode($row['redirects']);
            $placeholders[] = '(%s, %s, %s, %d, %d, %s, %s, %s, %s, %s, %s, %s)';
        }

        // Chunked multi-row upsert (50 rows per statement).
        foreach (array_chunk($values, 12 * 50) as $chunkValues) {
            $chunkSql = "INSERT INTO {$wpdb->prefix}" . self::TABLE
                . ' (path_hash, path, hash, size, mtime, first_seen, last_seen, severity, verdict_class, label, signatures, redirects) VALUES '
                . implode(', ', array_slice($placeholders, 0, count($chunkValues) / 12))
                . ' ON DUPLICATE KEY UPDATE'
                . ' path = VALUES(path), hash = VALUES(hash), size = VALUES(size), mtime = VALUES(mtime),'
                . ' last_seen = VALUES(last_seen), severity = VALUES(severity), verdict_class = VALUES(verdict_class),'
                . ' label = VALUES(label), signatures = VALUES(signatures), redirects = VALUES(redirects)';
            $wpdb->query($wpdb->prepare($chunkSql, $chunkValues));
        }
    }

    /**
     * Rows by exact paths (path => row) for moved-file detection.
     *
     * @param array<int, string> $paths
     *
     * @return array<string, array{path: string, hash: string}>
     */
    public static function rowsByPath(array $paths): array {
        global $wpdb;
        if (empty($paths)) {
            return [];
        }
        $hashes = array_map(static function ($p) {
            return hash('sha256', (string) $p);
        }, $paths);
        $placeholders = implode(', ', array_fill(0, count($hashes), '%s'));
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT path, hash FROM {$wpdb->prefix}" . self::TABLE . " WHERE path_hash IN ({$placeholders})",
                $hashes
            ),
            ARRAY_A
        );
        $out = [];
        foreach ($rows ?: [] as $row) {
            $out[$row['path']] = $row;
        }
        return $out;
    }

    /**
     * Rows not seen since the given timestamp (deleted candidates),
     * optionally paged with an offset for bounded chunked reads.
     *
     * @return array<int, array{path: string, hash: string}>
     */
    public static function notSeenSince(string $since, int $limit = 50000, int $offset = 0): array {
        global $wpdb;
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT path, hash FROM {$wpdb->prefix}" . self::TABLE . " WHERE last_seen < %s LIMIT %d OFFSET %d",
                $since,
                $limit,
                $offset
            ),
            ARRAY_A
        );
        return $rows ? $rows : [];
    }

    /**
     * Reset flags on files that a finished scan did not touch. Called when a
     * scan completes so the index only ever holds the latest scan's verdicts:
     * findings left over from older runs or scopes not selected this time are
     * cleared, and the next scan starts from a clean slate.
     */
    public static function resetStaleFindings(string $since): void {
        global $wpdb;
        $wpdb->query(
            $wpdb->prepare(
                "UPDATE {$wpdb->prefix}" . self::TABLE
                . " SET severity = 'safe', verdict_class = '', label = '', signatures = NULL, redirects = NULL"
                . ' WHERE severity IN (%s, %s, %s) AND last_seen < %s',
                'critical',
                'warning',
                'info',
                $since
            )
        );
    }

    /**
     * Remove rows not seen for a long time (index garbage collection).
     */
    public static function purgeStale(int $days = 60): void {
        global $wpdb;
        $cutoff = gmdate('Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS);
        $wpdb->query(
            $wpdb->prepare("DELETE FROM {$wpdb->prefix}" . self::TABLE . " WHERE last_seen < %s", $cutoff)
        );
    }

    /**
     * Remove scan run history older than N days.
     */
    public static function purgeRuns(int $days = 90): void {
        global $wpdb;
        $cutoff = gmdate('Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS);
        $wpdb->query(
            $wpdb->prepare("DELETE FROM {$wpdb->prefix}" . self::RUNS_TABLE . " WHERE started_at < %s", $cutoff)
        );
    }

    /**
     * Ensure required indexes exist (dbDelta never adds indexes to an
     * existing table, so missing ones are added explicitly during
     * activation/upgrade).
     */
    public static function ensureIndexes(): void {
        global $wpdb;
        $table = $wpdb->prefix . self::TABLE;
        $required = [
            'severity'           => '(severity)',
            'last_seen'          => '(last_seen)',
            'severity_last_seen' => '(severity, last_seen)',
        ];
        $existing = [];
        foreach ((array) $wpdb->get_results("SHOW INDEX FROM {$table}") as $idx) {
            if (isset($idx->Key_name) && $idx->Key_name !== 'PRIMARY') {
                $existing[(string) $idx->Key_name] = true;
            }
        }
        foreach ($required as $name => $cols) {
            if (!isset($existing[$name])) {
                $wpdb->query("ALTER TABLE {$table} ADD KEY {$name} {$cols}");
            }
        }
    }

    /**
     * Files matching a severity (optionally a verdict class).
     *
     * @return array<string, array{severity: string, class: string, label: string, signatures: array, redirects: array}>
     */
    public static function findBySeverity(string $severity, string $class = '', int $limit = 500): array {
        global $wpdb;
        $sql = "SELECT path, severity, verdict_class, label, signatures, redirects FROM {$wpdb->prefix}" . self::TABLE
            . ' WHERE severity = %s';
        $args = [$severity];
        if ($class !== '') {
            $sql .= ' AND verdict_class = %s';
            $args[] = $class;
        }
        $sql .= ' ORDER BY last_seen DESC LIMIT %d';
        $args[] = $limit;

        $rows = $wpdb->get_results($wpdb->prepare($sql, $args), ARRAY_A);
        $out = [];
        foreach ($rows ?: [] as $row) {
            $out[$row['path']] = [
                'severity'   => $row['severity'],
                'class'      => $row['verdict_class'],
                'label'      => $row['label'],
                'signatures' => json_decode((string) $row['signatures'], true) ?: [],
                'redirects'  => json_decode((string) $row['redirects'], true) ?: [],
            ];
        }
        return $out;
    }

    /**
     * Severity counts over the whole index (dashboard cards).
     *
     * @return array{critical: int, warning: int, info: int, safe: int}
     */
    public static function severityCounts(): array {
        global $wpdb;
        $rows = $wpdb->get_results(
            "SELECT severity, COUNT(*) AS c FROM {$wpdb->prefix}" . self::TABLE . ' GROUP BY severity',
            ARRAY_A
        );
        $counts = ['critical' => 0, 'warning' => 0, 'info' => 0, 'safe' => 0];
        foreach ($rows ?: [] as $row) {
            if (isset($counts[$row['severity']])) {
                $counts[$row['severity']] = (int) $row['c'];
            }
        }
        return $counts;
    }

    /**
     * Total indexed files.
     */
    public static function total(): int {
        global $wpdb;
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}" . self::TABLE);
    }

    /**
     * Start a scan run record.
     */
    public static function startRun(string $mode): int {
        global $wpdb;
        $wpdb->insert(
            $wpdb->prefix . self::RUNS_TABLE,
            ['started_at' => current_time('mysql'), 'status' => 'running', 'mode' => $mode],
            ['%s', '%s', '%s']
        );
        return (int) $wpdb->insert_id;
    }

    /**
     * Persist the discovered file total early, so the dashboard can render
     * progress even while the first segment is still running.
     */
    public static function markRunTotal(int $runId, int $total): void {
        global $wpdb;
        $wpdb->update(
            $wpdb->prefix . self::RUNS_TABLE,
            ['total_files' => $total],
            ['id' => $runId],
            ['%d'],
            ['%d']
        );
    }

    /**
     * One scan run record by id (progress panel).
     */
    public static function runById(int $runId): array {
        global $wpdb;
        $row = $wpdb->get_row(
            $wpdb->prepare("SELECT * FROM {$wpdb->prefix}" . self::RUNS_TABLE . ' WHERE id = %d', $runId),
            ARRAY_A
        );
        return $row ? (array) $row : [];
    }

    /**
     * Update a scan run record.
     */
    public static function finishRun(int $runId, string $status, int $total, int $scanned, array $result): void {
        global $wpdb;
        $wpdb->update(
            $wpdb->prefix . self::RUNS_TABLE,
            [
                'finished_at'  => current_time('mysql'),
                'status'       => $status,
                'total_files'  => $total,
                'scanned_files' => $scanned,
                'result'       => wp_json_encode($result),
            ],
            ['id' => $runId],
            ['%s', '%s', '%d', '%d', '%s'],
            ['%d']
        );
    }

    /**
     * Most recent scan run summary (dashboard).
     */
    public static function lastRun(): array {
        global $wpdb;
        $row = $wpdb->get_row(
            "SELECT * FROM {$wpdb->prefix}" . self::RUNS_TABLE . ' ORDER BY id DESC LIMIT 1',
            ARRAY_A
        );
        if (!$row) {
            return [];
        }
        $row['result'] = json_decode((string) $row['result'], true) ?: [];
        return $row;
    }
}
