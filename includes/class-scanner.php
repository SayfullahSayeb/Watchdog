<?php
/**
 * Scanner: SHA-256 file integrity + combined signature/redirect analysis,
 * backed by the watchdog_files database index.
 *
 * Incremental by design:
 *  - fast path: size + mtime match the index -> no hash, no content scan.
 *  - metadata-only change (mtime/size but same hash) -> update stats only.
 *  - hash mismatch or new file -> full content scan + verdict.
 *  - deleted files are detected from stale last_seen rows; a reappearing
 *    file whose hash matches a deleted row is reported as moved.
 *
 * Runs are serialized with a scan lock and segmented with a time budget;
 * a paused run is continued by cron events until finished.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * Scanner
 */
final class Scanner {

    public const BASELINE_OPTION = 'watchdog_baseline';
    public const BASELINE_TIME_OPTION = 'watchdog_baseline_time';
    public const LAST_SCAN_OPTION = 'watchdog_last_scan';
    public const LOCK_TRANSIENT = 'watchdog_scan_lock';
    public const RESUME_OPTION = 'watchdog_scan_resume';
    public const CURRENT_OPTION = 'watchdog_scan_current';

    private const MAX_HASH_SIZE = 5242880; // 5 MB
    private const MAX_SCAN_SIZE = 2097152; // 2 MB
    private const BUDGET_SECONDS = 50;
    private const BATCH_SIZE = 200;

    /**
     * A paused run with no lock and no segment activity for this long is
     * considered dead (nobody is driving it): progress() cleans it up so
     * the dashboard can start a fresh scan.
     */
    private const STALE_RUN_SECONDS = 900;

    private const SCAN_EXTS = [
        'php', 'php3', 'php4', 'php5', 'php7', 'php8',
        'phtml', 'phar', 'inc', 'htaccess', 'ini',
        'js', 'mjs', 'cjs', 'htm', 'html',
    ];

    private const SKIP_DIRS = [
        'cache', 'node_modules', 'vendor', 'backup', 'backups',
        'ai1wm-backups', 'upgrade', 'watchdog-quarantine',
        '.git', '.svn', '.hg', '.idea', '.vscode',
    ];

    /**
     * True while a scan is running (or its lock has not expired).
     */
    public static function scanLocked(): bool {
        $lock = get_transient(self::LOCK_TRANSIENT);
        return is_array($lock) && time() < (int) ($lock['expires'] ?? 0);
    }

    /**
     * Live progress of the active scan run, or null when nothing is
     * running. Cumulative scanned count comes from the index rows marked
     * with this run's start timestamp (segments update them as they go),
     * the total comes from the run record.
     *
     * @return null|array{run_id: int, started: string, total: int,
     *                    scanned: int, running: bool, scope: array,
     *                    scope_label: string, segments: int,
     *                    current_path: string, current_updated: int,
     *                    current_files: array<int, array{path: string, ts: int}>}
     */
    public static function progress(): ?array {
        $resume = get_option(self::RESUME_OPTION, []);
        if (!is_array($resume) || empty($resume['run'])) {
            return null;
        }

        $runId = (int) $resume['run'];
        $run = FilesIndex::runById($runId);
        $total = is_array($run) ? (int) ($run['total_files'] ?? 0) : 0;
        $scope = self::normalizeScope(
            isset($resume['scope']) && is_array($resume['scope']) ? $resume['scope'] : []
        );

        global $wpdb;
        $scanned = (int) $wpdb->get_var(
            $wpdb->prepare(
                // Rows are stamped mid-segment by bulkUpsert (last_seen = now)
                // and re-marked to the run start at each pause, so an exact
                // match would make the counter dip while a segment runs.
                // Anything touched at or after the run start counts.
                "SELECT COUNT(*) FROM {$wpdb->prefix}watchdog_files WHERE last_seen >= %s",
                (string) ($resume['started'] ?? '')
            )
        );

        $current = get_option(self::CURRENT_OPTION, []);
        if (!is_array($current)) {
            $current = [];
        }

        // Dead-run cleanup: a paused run with no lock and no segment
        // activity for a long time is never going to continue (no cron,
        // no open dashboard). Release it so the Start button comes back
        // instead of showing "Scan queued" forever.
        $runStarted = is_array($run) && !empty($run['started_at']) ? (int) strtotime((string) $run['started_at']) : 0;
        $lastActivity = max((int) ($current['updated'] ?? 0), $runStarted);
        if (!self::scanLocked() && $lastActivity > 0 && (time() - $lastActivity) > self::STALE_RUN_SECONDS) {
            delete_option(self::RESUME_OPTION);
            delete_option(self::CURRENT_OPTION);
            delete_transient(self::LOCK_TRANSIENT);
            if (is_array($run) && !empty($run['id'])) {
                FilesIndex::finishRun(
                    (int) $run['id'],
                    'cancelled',
                    $total,
                    $scanned,
                    ['cancelled' => true, 'reason' => 'stale']
                );
            }
            return null;
        }

        return [
            'run_id'          => $runId,
            'started'         => (string) ($resume['started'] ?? ''),
            'total'           => $total,
            'scanned'         => min($scanned, $total),
            'running'         => self::scanLocked(),
            'scope'           => $scope,
            'scope_label'     => self::scopeLabel($scope),
            'segments'        => (int) ($resume['segments'] ?? 1),
            'current_path'    => (string) ($current['path'] ?? ''),
            'current_updated' => (int) ($current['updated'] ?? 0),
            'current_files'   => isset($current['files']) && is_array($current['files'])
                ? array_map(
                    static function ($entry): array {
                        if (!is_array($entry)) {
                            return ['path' => (string) $entry, 'ts' => 0];
                        }
                        return [
                            'path' => (string) ($entry['path'] ?? ''),
                            'ts'   => (int) ($entry['ts'] ?? 0),
                        ];
                    },
                    $current['files']
                )
                : [],
        ];
    }

    /**
     * AJAX endpoint for the dashboard progress panel (live polling).
     * While an admin is watching the dashboard the poll itself drives
     * the next segment, so the scan keeps moving even on hosts where
     * WP cron never fires (local dev without traffic, DISABLE_WP_CRON).
     */
    public static function ajaxProgress(): void {
        check_ajax_referer('watchdog_scan_progress', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(null, 403);
        }
        self::continueIfPaused();
        // Explicit data key: wp_send_json_success(null) omits it entirely
        // (isset() check in WP), and the dashboard poller treats a missing
        // payload as "run finished".
        wp_send_json(['success' => true, 'data' => self::progress()]);
    }

    /**
     * Run the next scan segment when the run is paused and the lock has
     * expired. The lock keeps overlapping polls/tabs from starting
     * duplicate segments; the resume scope always wins.
     */
    public static function continueIfPaused(): void {
        $resume = get_option(self::RESUME_OPTION, []);
        if (!is_array($resume) || empty($resume['run']) || self::scanLocked()) {
            return;
        }
        self::runScan('incremental');
    }

    /**
     * Run a scan segment. Returns a summary with status:
     * 'locked' | 'paused' (resume via cron) | 'finished'.
     *
     * @param string $mode 'incremental' (fast path) or 'deep' (re-hash + re-scan everything).
     * @param array  $scope Scopes to scan: 'all'|'core'|'plugins'|'themes'|'uploads'|'content'.
     *                      Ignored while a run is being resumed (the resume scope wins).
     */
    public static function runScan(string $mode = 'incremental', array $scope = []): array {
        $lock = get_transient(self::LOCK_TRANSIENT);
        if (is_array($lock) && time() < (int) ($lock['expires'] ?? 0)) {
            return ['status' => 'locked'];
        }

        $resume = get_option(self::RESUME_OPTION, []);
        if (is_array($resume) && !empty($resume['run']) && !empty($resume['started'])) {
            $runId = (int) $resume['run'];
            $runStart = (string) $resume['started'];
            $scope = isset($resume['scope']) && is_array($resume['scope']) ? self::normalizeScope($resume['scope']) : ['all'];
            // The mode travels with the resume: "Start Scan" begins a deep
            // run and every continuation (dashboard poll, cron) keeps
            // re-hashing until it is done; legacy resumes default to
            // incremental so old options never become full re-scans.
            if (isset($resume['mode']) && in_array((string) $resume['mode'], ['deep', 'incremental'], true)) {
                $mode = (string) $resume['mode'];
            } else {
                $mode = 'incremental';
            }
        } else {
            $scope = self::normalizeScope($scope);
            $runId = FilesIndex::startRun($mode);
            $runStart = date('Y-m-d H:i:s', current_time('timestamp'));
            update_option(self::RESUME_OPTION, ['run' => $runId, 'started' => $runStart, 'scope' => $scope, 'segments' => 1, 'mode' => $mode], false);
        }
        // Segment length: as long as safely possible for this request.
        // Clamped to the PHP time limit (when one is set) so a segment
        // can never be killed mid-file; the lock expires shortly after
        // the segment ends so the dashboard poller chains the next one
        // almost immediately (near-continuous scanning at full speed).
        $budget = (float) apply_filters('watchdog_scan_budget', self::BUDGET_SECONDS);
        $limit = (int) ini_get('max_execution_time');
        if ($limit > 0) {
            $budget = min($budget, max(5.0, (float) $limit - 8.0));
        }
        @set_time_limit((int) $budget + 20);
        set_transient(self::LOCK_TRANSIENT, ['run' => $runId, 'expires' => time() + (int) $budget + 15], 200);
        $startedAt = microtime(true);

        $pending = [];
        $scanned = 0;
        $changed = [];
        $new = [];
        $moved = [];
        $deleted = [];
        $domains = [];
        $counts = ['critical' => 0, 'warning' => 0, 'info' => 0, 'safe' => 0];
        $expected = 0;
        $walked = 0;
        $seen = [];
        $current = [];
        $lastCurrentWrite = 0.0;

        $files = self::collectFiles($scope);
        $total = count($files);
        $lastPauseCheck = 0;
        FilesIndex::markRunTotal($runId, $total);

        // Resumable walk: the file list is walked in the same stable
        // order by every segment, so the previous segment's last path
        // marks where to continue. Without this, every segment would
        // restart at file #1 and re-process the same prefix on each
        // budget — a deep scan of a large site would never finish.
        $lastPath = (string) ($resume['last_path'] ?? '');
        if ($lastPath !== '') {
            $skipIdx = array_search($lastPath, $files, true);
            // Continue right after the previous marker; an empty tail is
            // fine (that segment then just completes the run). If the file
            // order changed so the marker is gone, fall back to the top.
            if ($skipIdx !== false) {
                $files = array_slice($files, $skipIdx + 1);
            }
        }

        // Index lookups are chunked so the full index never sits in memory
        // at once, even on sites with 100k+ files.
        foreach (array_chunk($files, self::BATCH_SIZE * 5) as $batch) {
            $index = FilesIndex::indexForPaths($batch);
            foreach ($batch as $path) {
                $row = isset($index[$path]) ? $index[$path] : null;

                // Live "now scanning" marker for the dashboard panel:
                // written every ~2s of segment time, with a small ring
                // log (path + timestamp) of the most recent files.
                $now = microtime(true);
                if ($now - $lastCurrentWrite >= 2.0) {
                    $lastCurrentWrite = $now;
                    $current['path'] = $path;
                    $current['updated'] = time();
                    $current['files'] = array_slice(
                        array_merge(
                            [['path' => $path, 'ts' => time()]],
                            isset($current['files']) && is_array($current['files']) ? $current['files'] : []
                        ),
                        0,
                        15
                    );
                    update_option(self::CURRENT_OPTION, $current, false);
                }

                if ($mode === 'incremental' && $row !== null && self::fastPathMatches($path, $row)) {
                    $seen[$path] = true;
                    continue;
                }

                $verdict = self::scanFile($path);
                $scanned++;
                $seen[$path] = true;

                if ($verdict['severity'] !== '') {
                    $counts[$verdict['severity']]++;
                }
                if (!empty($verdict['expected'])) {
                    $expected++;
                }
                if (!empty($verdict['domains'])) {
                    foreach ($verdict['domains'] as $host => $dest) {
                        $domains[$host] = $dest;
                    }
                }

                if ($row === null) {
                    $new[$path] = true;
                } elseif ($row['hash'] !== '' && $row['hash'] !== $verdict['hash']) {
                    $changed[$path] = true;
                }

                $pending[] = self::rowFor($path, $verdict, $row);
                if (count($pending) >= self::BATCH_SIZE) {
                    FilesIndex::bulkUpsert($pending);
                    $pending = [];
                }

                // Time budget: pause before the next file when exceeded.
                $walked++;
                if ($walked - $lastPauseCheck >= 100 && (microtime(true) - $startedAt) > $budget) {
                    $lastPauseCheck = $walked;
                    FilesIndex::bulkUpsert($pending);
                    $pending = [];
                    self::applySeen($seen, $runStart);
                    FilesIndex::finishRun($runId, 'paused', $total, $scanned, self::summary($counts, $expected));

                    // Track the segment count and chain the next background
                    // segment. With the dashboard open, the progress poller
                    // starts it within seconds (the lock has expired by
                    // then); the ~2-minute cron event is the fallback for
                    // when nobody is watching the page.
                    $resumeNow = get_option(self::RESUME_OPTION, []);
                    $segments = (int) (is_array($resumeNow) ? ($resumeNow['segments'] ?? 0) : 0) + 1;
                    update_option(
                        self::RESUME_OPTION,
                        [
                            'run'       => $runId,
                            'started'   => $runStart,
                            'scope'     => $scope,
                            'segments'  => $segments,
                            'mode'      => $mode,
                            'last_path' => $path,
                        ],
                        false
                    );
                    Cron::scheduleFastContinue();

                    return [
                        'status'    => 'paused',
                        'run_id'    => $runId,
                        'total'     => $total,
                        'scanned'   => $scanned,
                        'processed' => $walked,
                    ];
                }
            }
            unset($index);
        }

        // Deleted detection (rows never seen this run segment), limited
        // to the selected scope so out-of-scope files are never flagged.
        $rows = self::staleRows($runStart, $scope);
        foreach ($rows as $row) {
            $deleted[$row['path']] = true;
        }

        // Persist verdicts before the moved-hash lookup.
        FilesIndex::bulkUpsert($pending);

        // Moved detection: a new/changed file whose hash matches a
        // deleted row's hash is reported as a move, not a new file.
        $deletedByHash = [];
        foreach ($rows as $row) {
            if ($row['hash'] !== '') {
                $deletedByHash[$row['hash']][] = $row['path'];
            }
        }
        foreach (FilesIndex::rowsByPath(array_merge(array_keys($new), array_keys($changed))) as $path => $row) {
            if (isset($deletedByHash[$row['hash']]) && count($deletedByHash[$row['hash']]) === 1) {
                $moved[$path] = $deletedByHash[$row['hash']][0];
                unset($deleted[$deletedByHash[$row['hash']][0]]);
                unset($new[$path]);
            }
        }

        self::applySeen(array_merge($seen, array_fill_keys(array_keys($deleted), true)), $runStart);
        FilesIndex::finishRun($runId, 'finished', $total, $scanned, self::summary($counts, $expected));
        delete_option(self::RESUME_OPTION);
        delete_option(self::CURRENT_OPTION);
        delete_transient(self::LOCK_TRANSIENT);

        $summary = self::summary($counts, $expected);
        $results = [
            'status'   => 'finished',
            'time'     => time(),
            'run_id'   => $runId,
            'mode'     => $mode,
            'total'    => $total,
            'scanned'  => $scanned,
            'changed'  => array_keys($changed),
            'new'      => array_keys($new),
            'deleted'  => array_keys($deleted),
            'moved'    => $moved,
            'domains'  => $domains,
            'counts'   => $summary,
            'expected' => $expected,
        ];

        // Only the last scan's findings survive: everything shown anywhere
        // in the plugin (dashboard, report, email) is the result of exactly
        // this one scan. Any older flags stay in the index only until this
        // run overwrites them.
        foreach (['malware', 'suspicious', 'info'] as $key) {
            $results[$key] = [];
        }
        foreach (self::runFindings($runStart) as $path => $row) {
            $map = $row['severity'] === 'critical' ? 'malware'
                : ($row['severity'] === 'warning' ? 'suspicious' : 'info');
            $results[$map][$path] = [
                'label'      => (string) ($row['label'] ?? ''),
                'signatures' => is_array($row['signatures']) ? $row['signatures'] : [],
                'redirects'  => is_array($row['redirects']) ? $row['redirects'] : [],
            ];
        }

        // Site-level checks (Wordfence High Sensitivity set): config
        // exposure, options, users, passwords, posts/comments, versions,
        // disk space, suspected files, suspected images-as-executable,
        // outside-WP files. Bounded by their own time budget.
        if (class_exists('Watchdog\SiteChecks')) {
            $results['checks'] = SiteChecks::run();
        }

        // Clean up before storing the fresh result: flags on files that were
        // not touched by this run (older scans, scopes not selected this time)
        // are reset, so a completed scan always replaces the previous one and
        // the plugin never mixes scan results from different runs.
        FilesIndex::resetStaleFindings($runStart);
        update_option(self::LAST_SCAN_OPTION, $results, false);

        // Threat Logs and the overview stats (7d/30d) must reflect exactly
        // this scan: drop the previous scan's findings and the daily dedupe
        // cache, then log the current ones (file + exact code lines).
        Logger::clearFindings();
        delete_option('watchdog_logged_findings');
        self::logFindings();

        return $results;
    }

    /**
     * Write one 'scan_finding' event per critical/warning file currently
     * flagged, with the signature names and the exact matching code
     * lines. Deduplicated per file per 24h so repeated incremental scans
     * do not flood the timeline.
     */
    private static function logFindings(): void {
        global $wpdb;
        $rows = (array) $wpdb->get_results(
            "SELECT path, severity, label, signatures FROM {$wpdb->prefix}watchdog_files"
            . " WHERE severity IN ('critical', 'warning') LIMIT 500",
            ARRAY_A
        );
        if ($rows === []) {
            return;
        }

        $now = time();
        $logged = (array) get_option('watchdog_logged_findings', []);
        $pruned = [];
        foreach ($logged as $p => $ts) {
            if ($now - (int) $ts < DAY_IN_SECONDS) {
                $pruned[(string) $p] = (int) $ts;
            }
        }
        $count = 0;
        foreach ($rows ?: [] as $row) {
            $path = (string) $row['path'];
            if ($path === '' || isset($pruned[$path]) || !@is_file($path)) {
                continue;
            }
            if ($count >= 50) {
                break;
            }
            $signatures = json_decode((string) ($row['signatures'] ?? '[]'), true) ?: [];
            if (!is_array($signatures)) {
                $signatures = [];
            }
            $signatures = array_values($signatures);
            $pruned[$path] = $now;
            $count++;
            Logger::log('scan_finding', (string) $row['severity'], $path, [
                'label'      => (string) ($row['label'] ?? ''),
                'signatures' => $signatures,
                'lines'      => Heuristics::locateLines($path, $signatures),
            ]);
        }
        update_option('watchdog_logged_findings', $pruned, false);
    }

    /**
     * Legacy alias: deep scan (optionally scoped).
     */
    public static function runFullScan(array $scope = []): array {
        return self::runScan('deep', $scope);
    }

    /**
     * Bootstrap a scan run without walking any files: create the run
     * record, write the resume marker and let the first segment be picked
     * up by the cron fast-continue chain or the dashboard progress poller.
     * The start request returns instantly instead of blocking for a full
     * segment, so a refresh right after "Start Scan" can never kill a
     * mid-walk segment or leave the dashboard confused.
     *
     * @return array{status: string, run_id: int}
     */
    public static function ensureRun(array $scope = []): array {
        $resume = get_option(self::RESUME_OPTION, []);
        if (is_array($resume) && !empty($resume['run'])) {
            return ['status' => 'running', 'run_id' => (int) $resume['run']];
        }
        $scope = self::normalizeScope($scope);
        $runId = FilesIndex::startRun('deep');
        $runStart = date('Y-m-d H:i:s', current_time('timestamp'));
        update_option(
            self::RESUME_OPTION,
            ['run' => $runId, 'started' => $runStart, 'scope' => $scope, 'segments' => 1, 'mode' => 'deep'],
            false
        );
        return ['status' => 'running', 'run_id' => $runId];
    }

    /**
     * Immediately stop the active scan run: release the lock, remove the
     * resume marker and mark the run record as cancelled.
     */
    public static function cancelScan(): void {
        $resume = get_option(self::RESUME_OPTION, []);
        if (is_array($resume) && !empty($resume['run'])) {
            $runId = (int) $resume['run'];
            $run = FilesIndex::runById($runId);
            FilesIndex::finishRun(
                $runId,
                'cancelled',
                (int) ($run['total_files'] ?? 0),
                (int) ($run['scanned_files'] ?? 0),
                ['cancelled' => true]
            );
        }
        delete_option(self::RESUME_OPTION);
        delete_option(self::CURRENT_OPTION);
        delete_transient(self::LOCK_TRANSIENT);
    }

    /**
     * Baseline helpers (legacy options kept for migration/compat).
     */
    public static function baseline(): array {
        return (array) get_option(self::BASELINE_OPTION, []);
    }

    public static function baselineTime(): int {
        return (int) get_option(self::BASELINE_TIME_OPTION, 0);
    }

    /**
     * Rebuild the trusted baseline: deep scan, then trust the current
     * state of every file (clear verdicts, reset first_seen).
     */
    public static function saveBaseline(): int {
        self::runScan('deep');
        global $wpdb;
        $wpdb->query(
            $wpdb->prepare(
                "UPDATE {$wpdb->prefix}watchdog_files SET first_seen = %s, severity = 'safe', verdict_class = '', label = '', signatures = NULL, redirects = NULL",
                current_time('mysql')
            )
        );
        // The stored report reflects the scan that just ran; the baseline now
        // trusts every file, so drop the previous scan's findings from it.
        $report = self::lastScan();
        foreach (['malware', 'suspicious', 'info'] as $key) {
            $report[$key] = [];
        }
        update_option(self::LAST_SCAN_OPTION, $report, false);
        Logger::clearFindings();
        delete_option('watchdog_logged_findings');
        update_option(self::BASELINE_TIME_OPTION, time(), false);
        return FilesIndex::total();
    }

    /**
     * Last scan summary stored in options (small: counts and path lists).
     */
    public static function lastScan(): array {
        return (array) get_option(self::LAST_SCAN_OPTION, []);
    }

    /**
     * Analyze one file: hash + signatures + redirect analysis + verdict.
     * Hashing is skipped entirely for extensions outside SCAN_EXTS or
     * files over MAX_SCAN_SIZE — hashing first would waste seconds per
     * big media file (uploads scope can contain GB-sized files).
     *
     * @param string $path
     */
    public static function scanFile(string $path): array {
        $size = (int) @filesize($path);
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $hash = '';
        if (in_array($ext, self::SCAN_EXTS, true) && $size <= self::MAX_SCAN_SIZE) {
            $hash = @hash_file('sha256', $path);
        }
        $result = [
            'hash'       => $hash,
            'signatures' => [],
            'redirects'  => [],
            'expected'   => [],
            'domains'    => [],
            'severity'   => '',
            'class'      => '',
            'label'      => null,
            'size'       => $size,
            'mtime'      => (int) @filemtime($path),
        ];
        if (!$hash) {
            return $result;
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            return $result;
        }

        $result['signatures'] = Heuristics::scan($content, $ext);
        $classification = Heuristics::classify($result['signatures']);
        $severity = $classification['sev'];
        $label = $classification['label'];

        $findings = RedirectAnalyzer::analyzeContent($content, basename($path));
        $engineResults = ExecutionContext::analyzeFile($content, $path);
        $engineByKey = [];
        foreach ($engineResults as $engineResult) {
            $engineByKey[($engineResult['line'] ?? 0) . '|' . ($engineResult['method'] ?? '')] = $engineResult;
        }
        $redirects = [];
        $expected = [];
        $usedEngine = [];
        foreach ($findings as $finding) {
            $key = ($finding['line'] ?? 0) . '|' . ($finding['method'] ?? '');
            if (isset($engineByKey[$key])) {
                $decision = $engineByKey[$key];
                $usedEngine[$key] = true;
            } else {
                $decision = RedirectEngine::classify($finding, $path, $result['signatures']);
            }
            $finding['class'] = $decision['class'];
            $finding['reason'] = $decision['reason'];
            $finding['severity'] = $decision['severity'];
            $finding['confidence'] = isset($decision['confidence']) ? $decision['confidence'] : '';

            if ($decision['class'] === RedirectEngine::EXPECTED) {
                $expected[] = $finding;
                continue;
            }
            if ($decision['class'] === RedirectEngine::SAFE) {
                $finding['severity'] = 'safe';
                $redirects[] = $finding;
                continue;
            }
            $redirects[] = $finding;
            if (Heuristics::rank($finding['severity']) > Heuristics::rank($severity)) {
                $severity = $finding['severity'];
            }
            if ($finding['dest']) {
                $host = strtolower((string) wp_parse_url($finding['dest'], PHP_URL_HOST));
                if ($host !== '' && $host !== strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST))) {
                    $result['domains'][$host] = $finding['dest'];
                }
            }
        }

        // Engine findings without a RedirectAnalyzer counterpart (e.g.
        // header() destinations, eval contexts, decoded destinations).
        foreach ($engineResults as $engineResult) {
            $key = ($engineResult['line'] ?? 0) . '|' . ($engineResult['method'] ?? '');
            if (isset($usedEngine[$key])) {
                continue;
            }
            $engineResult['class'] = $engineResult['class'];
            $engineResult['severity'] = $engineResult['severity'];
            if ($engineResult['class'] === RedirectEngine::EXPECTED) {
                $expected[] = $engineResult;
                continue;
            }
            if ($engineResult['class'] === RedirectEngine::SAFE) {
                $engineResult['severity'] = 'safe';
                $redirects[] = $engineResult;
                continue;
            }
            $redirects[] = $engineResult;
            if (Heuristics::rank($engineResult['severity']) > Heuristics::rank($severity)) {
                $severity = $engineResult['severity'];
            }
            if (!empty($engineResult['dest'])) {
                $host = strtolower((string) wp_parse_url($engineResult['dest'], PHP_URL_HOST));
                if ($host !== '' && $host !== strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST))) {
                    $result['domains'][$host] = $engineResult['dest'];
                }
            }
        }

        // Known-good suppression (Wordfence model) — final clamp after
        // all sources (heuristics, redirect analyzer, execution context)
        // have merged. A hash-verified official package file is clean by
        // definition; path-trusted core files (wp-admin/, wp-includes/,
        // root wp-*.php) are too — the checksum engine reports *modified*
        // core files separately. Escalated verdicts are pattern/context
        // collisions (moxie.js atob+mobile, plupload location usage,
        // webpack new Function() runtime, oembed hidden iframes) and only
        // a genuine hard critical signature (webshell, eval(request),
        // malware domain) survives this clamp.
        if (class_exists('Watchdog\Checksums')
            && (Checksums::knownGoodFile($path, $hash) || Checksums::coreTreeTrust($path))
            && $severity !== 'info'
            && $severity !== 'safe'
            && !Heuristics::hasCriticalSignature($result['signatures'])) {
            $severity = 'info';
            $label = null;
        }

        $result['redirects'] = $redirects;
        $result['expected'] = $expected;
        $result['severity'] = $severity === '' ? ($expected ? 'info' : 'safe') : $severity;
        $result['class'] = ($severity === '' && $expected) ? RedirectEngine::EXPECTED : '';
        $result['label'] = $label;

        return $result;
    }

    /**
     * Collect files to monitor, applying skip, exclusion, size and scope
     * rules. An empty scope (or 'all') collects the whole site.
     *
     * @param array $scope 'all'|'core'|'plugins'|'themes'|'uploads'|'content'
     */
    public static function collectFiles(array $scope = []): array {
        $scope = self::normalizeScope($scope);
        $files = [];
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator(ABSPATH, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $path = $file->getRealPath();
                if (!$path || self::isSkipped($path) || !self::inScope($path, $scope)) {
                    continue;
                }
                $size = $file->getSize();
                if ($size === false) {
                    continue;
                }
                $files[] = $path;
            }
        } catch (\Exception $e) {
            error_log('Watchdog scan error: ' . $e->getMessage());
        }
        return $files;
    }

    /**
     * Known scan scopes with their display labels.
     *
     * @return array<string, string>
     */
    public static function scopes(): array {
        return [
            'all'     => __('Everything (full site scan)', 'watchdog'),
            'core'    => __('WordPress core (root files, wp-admin, wp-includes)', 'watchdog'),
            'plugins' => __('All plugins', 'watchdog'),
            'themes'  => __('All themes', 'watchdog'),
            'uploads' => __('Uploads', 'watchdog'),
            'content' => __('Other wp-content (mu-plugins, languages, cache, …)', 'watchdog'),
        ];
    }

    /**
     * Reduce a raw scope list to known values; 'all' (or nothing) wins.
     */
    public static function normalizeScope(array $scope): array {
        $allowed = array_keys(self::scopes());
        $clean = [];
        foreach ($scope as $key) {
            $key = (string) $key;
            if (in_array($key, $allowed, true)) {
                $clean[] = $key;
            }
        }
        $clean = array_values(array_unique($clean));
        if (in_array('all', $clean, true) || $clean === []) {
            return ['all'];
        }
        return $clean;
    }

    /**
     * Human-readable label for a scope list (progress panel).
     */
    public static function scopeLabel(array $scope): string {
        if (in_array('all', $scope, true)) {
            return 'Everything';
        }
        $labels = [
            'core'    => 'WordPress core',
            'plugins' => 'Plugins',
            'themes'  => 'Themes',
            'uploads' => 'Uploads',
            'content' => 'Other wp-content',
        ];
        $out = [];
        foreach ($scope as $key) {
            if (isset($labels[$key])) {
                $out[] = $labels[$key];
            }
        }
        return $out !== [] ? implode(', ', $out) : 'Everything';
    }

    /**
     * Is the path covered by the given scope list?
     */
    public static function inScope(string $path, array $scope): bool {
        $scope = self::normalizeScope($scope);
        if (in_array('all', $scope, true)) {
            return true;
        }
        foreach ($scope as $key) {
            switch ($key) {
                case 'core':
                    // Everything in the site root that is not wp-content.
                    if (self::pathUnder($path, ABSPATH) && !self::pathUnder($path, WP_CONTENT_DIR)) {
                        return true;
                    }
                    break;
                case 'plugins':
                    if (self::pathUnder($path, WP_PLUGIN_DIR)) {
                        return true;
                    }
                    break;
                case 'themes':
                    if (self::pathUnder($path, get_theme_root())) {
                        return true;
                    }
                    break;
                case 'uploads':
                    if (self::pathUnder($path, wp_upload_dir()['basedir'])) {
                        return true;
                    }
                    break;
                case 'content':
                    if (self::pathUnder($path, WP_CONTENT_DIR)) {
                        return true;
                    }
                    break;
            }
        }
        return false;
    }

    /**
     * Prefix match that tolerates mixed slash styles (WP paths on Windows
     * can use / while getRealPath() returns \).
     */
    private static function pathUnder(string $path, string $base): bool {
        $path = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path);
        $base = rtrim(str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $base), DIRECTORY_SEPARATOR);
        return $path === $base || strpos($path, $base . DIRECTORY_SEPARATOR) === 0;
    }

    /**
     * Stale index rows (deleted candidates) within the scan scope. The
     * index is walked in bounded chunks so out-of-scope rows on huge
     * sites never exhaust memory or the query limit.
     *
     * @return array<int, array{path: string, hash: string}>
     */
    private static function staleRows(string $runStart, array $scope): array {
        $scope = self::normalizeScope($scope);
        $rows = [];
        $offset = 0;
        for ($i = 0; $i < 20; $i++) {
            $chunk = FilesIndex::notSeenSince($runStart, 10000, $offset);
            if ($chunk === []) {
                break;
            }
            foreach ($chunk as $row) {
                if (self::inScope((string) $row['path'], $scope)) {
                    $rows[] = $row;
                }
            }
            $offset += count($chunk);
            if (count($chunk) < 10000) {
                break;
            }
        }
        return $rows;
    }

    /**
     * Path on the skip list, in the quarantine dir, or excluded.
     */
    public static function isSkipped(string $path): bool {
        // Never scan the watchdog plugin's own directory: it contains
        // every detection pattern as a string literal plus a vendored
        // wordfence library — self-scanning only produces noise.
        $pluginRoot = str_replace('\\', '/', dirname(__DIR__));
        $pathNorm = str_replace('\\', '/', $path);
        if ($pluginRoot !== '' && strpos($pathNorm . '/', $pluginRoot . '/') === 0) {
            return true;
        }

        $parts = explode(DIRECTORY_SEPARATOR, $path);
        foreach ($parts as $part) {
            if (in_array($part, self::SKIP_DIRS, true)) {
                return true;
            }
        }

        foreach (RedirectEngine::lines('watchdog_exclusions') as $entry) {
            if ($entry === '') {
                continue;
            }
            if (strpos($entry, '/') === 0 || strpos($entry, '\\') === 0 || preg_match('/^[A-Za-z]:[\/\\\\]/', $entry) === 1) {
                if (strpos($path, $entry) === 0) {
                    return true;
                }
            } elseif (in_array($entry, $parts, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Canonical scan report — the single source of truth for the dashboard,
     * the email reporter and the weekly cron. Combines the persisted run
     * summary with the flagged-file details held in the index.
     *
     * Guaranteed keys: time, mode, total, scanned, expected (int) and
     * malware/suspicious/info/changed/new/deleted/moved/domains (arrays).
     */
    public static function buildReport(?array $run = null): array {
        $run = is_array($run) ? $run : self::lastScan();
        $report = [
            'time'       => (int) ($run['time'] ?? 0),
            'mode'       => (string) ($run['mode'] ?? 'full'),
            'total'      => (int) ($run['total'] ?? 0),
            'scanned'    => (int) ($run['scanned'] ?? 0),
            'expected'   => (int) ($run['expected'] ?? 0),
            'changed'    => [],
            'new'        => [],
            'deleted'    => [],
            'moved'      => [],
            'domains'    => [],
            'malware'    => [],
            'suspicious' => [],
            'info'       => [],
            'checks'     => [],
        ];
        foreach (['changed', 'new', 'deleted', 'moved'] as $key) {
            if (!empty($run[$key]) && is_array($run[$key])) {
                $report[$key] = self::pathMap($run[$key]);
            }
        }
        if (!empty($run['domains']) && is_array($run['domains'])) {
            $report['domains'] = $run['domains'];
        }
        if (!empty($run['checks']) && is_array($run['checks'])) {
            $report['checks'] = $run['checks'];
        }
        // Scan findings come from the stored last-scan snapshot (never from
        // the live index), so every surface shows exactly one scan. Files
        // that no longer exist (deleted/quarantined since the scan) drop
        // out automatically.
        foreach (['malware', 'suspicious', 'info'] as $key) {
            $items = isset($run[$key]) && is_array($run[$key]) ? $run[$key] : [];
            foreach ($items as $path => $detail) {
                if ($path === '' || !is_string($path) || !@is_file($path)) {
                    continue;
                }
                $report[$key][$path] = is_array($detail) ? $detail : [];
            }
        }
        return $report;
    }

    /**
     * Flagged rows belonging to the given scan run: rows the run actually
     * touched (last_seen >= run start) and that still carry a verdict.
     * Restricting by last_seen is what keeps old runs — and old scopes —
     * out of the latest scan's result.
     *
     * @return array<string, array{severity: string, label: string,
     *                              signatures: array, redirects: array}>
     */
    private static function runFindings(string $runSince): array {
        global $wpdb;
        $rows = (array) $wpdb->get_results(
            $wpdb->prepare(
                "SELECT path, severity, label, signatures, redirects
                 FROM {$wpdb->prefix}watchdog_files
                 WHERE severity IN ('critical', 'warning', 'info') AND last_seen >= %s
                 ORDER BY severity DESC, last_seen DESC",
                $runSince
            ),
            ARRAY_A
        );
        $out = [];
        foreach ($rows ?: [] as $row) {
            $path = (string) ($row['path'] ?? '');
            if ($path === '' || !@is_file($path)) {
                continue;
            }
            $signatures = json_decode((string) ($row['signatures'] ?? '[]'), true);
            $redirects = json_decode((string) ($row['redirects'] ?? '[]'), true);
            $out[$path] = [
                'severity'   => (string) ($row['severity'] ?? ''),
                'label'      => (string) ($row['label'] ?? ''),
                'signatures' => is_array($signatures) ? $signatures : [],
                'redirects'  => is_array($redirects) ? $redirects : [],
            ];
        }
        return $out;
    }

    /**
     * Normalize a path list to a path => true map (render-friendly).
     */
    private static function pathMap(array $paths): array {
        $map = [];
        foreach ($paths as $path) {
            $map[(string) $path] = true;
        }
        return $map;
    }

    /**
     * Fast path: index row matches current size + mtime.
     */
    private static function fastPathMatches(string $path, array $row): bool {
        $stat = @stat($path);
        if ($stat === false) {
            return false;
        }
        return (int) $row['size'] === (int) $stat['size'] && (int) $row['mtime'] === (int) $stat['mtime'];
    }

    /**
     * Build a bulk-upsert row from a scan verdict.
     */
    private static function rowFor(string $path, array $verdict, ?array $prior): array {
        return [
            'path'       => $path,
            'hash'       => $verdict['hash'],
            'size'       => $verdict['size'],
            'mtime'      => $verdict['mtime'],
            'severity'   => $verdict['severity'],
            'class'      => $verdict['class'],
            'label'      => (string) $verdict['label'],
            'signatures' => $verdict['signatures'],
            'redirects'  => array_merge($verdict['redirects'], $verdict['expected']),
        ];
    }

    /**
     * Mark exactly the walked (or deleted) rows as seen for the run.
     * Un-reached rows keep their old last_seen so they surface in
     * notSeenSince() when the next segment (or the finish) runs.
     */
    private static function applySeen(array $seen, string $runStart): void {
        if (empty($seen)) {
            return;
        }
        global $wpdb;
        $chunks = array_chunk(array_keys($seen), 500);
        foreach ($chunks as $chunk) {
            $placeholders = implode(',', array_fill(0, count($chunk), '%s'));
            $wpdb->query(
                $wpdb->prepare(
                    "UPDATE {$wpdb->prefix}watchdog_files SET last_seen = %s WHERE path IN ({$placeholders})",
                    array_merge([$runStart], $chunk)
                )
            );
        }
    }

    /**
     * Compact summary array for scan run records.
     */
    private static function summary(array $counts, int $expected): array {
        $counts['expected'] = $expected;
        return $counts;
    }
}
