<?php
/**
 * Cron: weekly deep scan, debounced incremental scans (never in-request)
 * and continuation of paused scans.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * Cron
 */
final class Cron {

    public const EVENT = 'watchdog_weekly_event';
    public const DEBOUNCED_EVENT = 'watchdog_debounced_scan';
    public const CONTINUE_EVENT = 'watchdog_scan_continue';
    public const FAST_CONTINUE_EVENT = 'watchdog_scan_continue_fast';

    /**
     * Seconds between chained background segments of an active scan.
     */
    private const FAST_INTERVAL = 120;

    /**
     * Register the weekly schedule (WordPress has none built in).
     */
    public static function registerSchedule(array $schedules): array {
        $schedules['weekly'] = [
            'interval' => WEEK_IN_SECONDS,
            'display'  => __('Once Weekly', 'watchdog'),
        ];
        return $schedules;
    }

    /**
     * Make sure the events are scheduled (idempotent).
     */
    public static function ensure(): void {
        if (!wp_next_scheduled(self::EVENT)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'weekly', self::EVENT);
        }
        if (!wp_next_scheduled(self::CONTINUE_EVENT)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'hourly', self::CONTINUE_EVENT);
        }
    }

    /**
     * Debounce a background incremental scan: at most one pending debounced
     * event at a time. Never runs scans inside the request that triggered
     * the change.
     */
    public static function debounce(): void {
        if (wp_next_scheduled(self::DEBOUNCED_EVENT)) {
            return;
        }
        wp_schedule_single_event(time() + 10 * MINUTE_IN_SECONDS, self::DEBOUNCED_EVENT);
    }

    /**
     * Debounced handler: incremental scan when the lock is free.
     */
    public static function debouncedScan(): void {
        if (Scanner::scanLocked()) {
            self::debounce(); // retry later
            return;
        }
        self::scanInBackground();
    }

    /**
     * Continuation handler: resume a paused scan, run queued verifications
     * and targeted directory scans.
     */
    public static function continueScan(): void {
        $resume = get_option(Scanner::RESUME_OPTION, []);
        if (is_array($resume) && !empty($resume['run']) && !Scanner::scanLocked()) {
            Scanner::runScan('incremental');
            return;
        }
        LiveProtection::processQueue();
        if (get_option('watchdog_pending_core_verify', 0)) {
            update_option('watchdog_pending_core_verify', 0, false);
            Checksums::verifyCore();
        }
    }

    /**
     * Chain the next background segment of the active scan in ~2 minutes
     * (one pending event at a time).
     */
    public static function scheduleFastContinue(): void {
        if (!wp_next_scheduled(self::FAST_CONTINUE_EVENT)) {
            wp_schedule_single_event(time() + self::FAST_INTERVAL, self::FAST_CONTINUE_EVENT);
        }
    }

    /**
     * Fast continuation: keeps an active scan moving every couple of
     * minutes instead of waiting for the hourly safety-net event. When
     * nothing is scanning, queued verifications are processed here too,
     * and the event re-chains while verification work remains.
     */
    public static function continueScanFast(): void {
        $resume = get_option(Scanner::RESUME_OPTION, []);
        if (is_array($resume) && !empty($resume['run'])) {
            if (Scanner::scanLocked()) {
                self::scheduleFastContinue(); // a segment is still finishing; retry
                return;
            }
            $results = Scanner::runScan('incremental');
            if (($results['status'] ?? '') === 'locked') {
                self::scheduleFastContinue(); // lost the race for the lock; retry
            }
            return;
        }

        LiveProtection::processQueue();
        if (get_option('watchdog_pending_core_verify', 0)) {
            update_option('watchdog_pending_core_verify', 0, false);
            Checksums::verifyCore();
        }

        if (get_option('watchdog_pending_verify', []) !== [] || get_option('watchdog_pending_core_verify', 0)) {
            self::scheduleFastContinue(); // more work left; keep the chain going
        }
    }

    /**
     * Run the weekly deep scan, prune old log rows, verify core checksums.
     */
    public static function weekly(): void {
        if (Scanner::scanLocked()) {
            return;
        }
        Scanner::runScan('deep');
        Logger::prune(180);
        FilesIndex::purgeStale(60);
        FilesIndex::purgeRuns(90);
        Checksums::verifyCore();
        Reporter::reportScan(Scanner::buildReport());
    }

    /**
     * Remove the scheduled events (deactivation).
     */
    public static function clear(): void {
        wp_clear_scheduled_hook(self::EVENT);
        wp_clear_scheduled_hook(self::DEBOUNCED_EVENT);
        wp_clear_scheduled_hook(self::CONTINUE_EVENT);
        wp_clear_scheduled_hook(self::FAST_CONTINUE_EVENT);
    }

    /**
     * Run an incremental scan now, but only when nothing else is scanning.
     */
    private static function scanInBackground(): void {
        Scanner::runScan('incremental');
    }
}
