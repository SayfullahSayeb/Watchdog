<?php
/**
 * Plugin bootstrap and hook wiring.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * Bootstrap singleton. Wires all subsystems into WordPress hooks.
 */
final class Plugin {

    public const VERSION = '3.4.6';
    private const DB_VERSION_OPTION = 'watchdog_db_version';

    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->wireHooks();
    }

    /**
     * Register every hook used by the plugin.
     */
    private function wireHooks(): void {
        add_action('admin_menu', [Dashboard::class, 'menu']);
        add_action('admin_enqueue_scripts', [Dashboard::class, 'enqueueAssets']);
        add_action('wp_ajax_watchdog_scan_progress', [Scanner::class, 'ajaxProgress']);
        add_action('wp_ajax_watchdog_verify_status', [Checksums::class, 'ajaxVerifyStatus']);
        add_action('admin_post_watchdog_scan', [Dashboard::class, 'handleScan']);
        add_action('admin_post_watchdog_stop_scan', [Dashboard::class, 'handleStopScan']);
        add_action('admin_post_watchdog_restore_baseline', [Dashboard::class, 'handleRestoreBaseline']);
        add_action('admin_post_watchdog_quarantine', [Dashboard::class, 'handleQuarantine']);
        add_action('admin_post_watchdog_restore_quarantine', [Dashboard::class, 'handleRestoreQuarantine']);
        add_action('admin_post_watchdog_disable_plugin', [Dashboard::class, 'handleDisablePlugin']);
        add_action('admin_post_watchdog_rename_plugin', [Dashboard::class, 'handleRenamePlugin']);
        add_action('admin_post_watchdog_settings', [Dashboard::class, 'handleSettings']);
        add_action('admin_post_watchdog_export', [Dashboard::class, 'handleExport']);
        add_action('admin_post_watchdog_verify_core', [Dashboard::class, 'handleVerifyCore']);
        add_action('admin_post_watchdog_verify_packages', [Dashboard::class, 'handleVerifyPackages']);
        add_action('admin_post_watchdog_export_quarantine', [Dashboard::class, 'handleExportQuarantine']);
        add_action('admin_notices', [Dashboard::class, 'showNotice']);

        add_filter('cron_schedules', [Cron::class, 'registerSchedule']);
        add_action('watchdog_weekly_event', [Cron::class, 'weekly']);
        add_action('watchdog_debounced_scan', [Cron::class, 'debouncedScan']);
        add_action('watchdog_scan_continue', [Cron::class, 'continueScan']);
        add_action('watchdog_scan_continue_fast', [Cron::class, 'continueScanFast']);

        LiveProtection::init();
        RedirectGuard::init();
    }

    /**
     * Activation: install tables, quarantine dir, MU plugin, baseline, cron.
     */
    public static function activate(): void {
        Logger::install();
        FilesIndex::install();
        Quarantine::ensureDir();
        self::installDefaults();
        RedirectGuard::writeMuPlugin();
        Scanner::saveBaseline();
        Cron::ensure();
        self::queuePackageVerifications();
        self::markUpgraded();
    }

    /**
     * Runs after every version change: install new tables and regenerate
     * the MU plugin so the embedded code always matches this version. On
     * every regular load the MU guard is ensured (written if missing), so
     * activation always installs it automatically.
     */
    public static function upgrade(): void {
        $previous = get_option(self::DB_VERSION_OPTION, '');
        if ($previous === self::VERSION) {
            RedirectGuard::ensureMuPlugin();
            return;
        }
        FilesIndex::install();
        Quarantine::ensureDir();
        self::installDefaults();
        RedirectGuard::writeMuPlugin();
        Cron::ensure();
        self::queuePackageVerifications();
        self::markUpgraded();
    }

    /**
     * Wordfence known-files equivalent: every installed plugin and theme
     * is checksum-verified against WordPress.org in the background, so
     * trust is derived from proven provenance instead of a maintained
     * slug list. Runs at activation/upgrade and weekly (see Cron).
     */
    private static function queuePackageVerifications(): void {
        LiveProtection::queueAllVerifications();
        Cron::scheduleFastContinue();
    }

    /**
     * Deactivation: stop cron and remove the generated MU plugin (unless
     * the admin opted to keep it). Data is kept for reactivation.
     */
    public static function deactivate(): void {
        Cron::clear();
        if (get_option('watchdog_remove_mu_on_deactivate', 1)) {
            RedirectGuard::removeMuPlugin();
        }
    }

    /**
     * Uninstall: drop all Watchdog data. Runs only when the admin deletes
     * the plugin through the WordPress plugin screen (uninstall hook).
     */
    public static function uninstall(): void {
        if (!defined('WP_UNINSTALL_PLUGIN')) {
            return;
        }
        Cron::clear();
        RedirectGuard::removeMuPlugin();

        global $wpdb;
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}watchdog_files");
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}watchdog_events");
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}watchdog_scan_runs");

        foreach ([
            'watchdog_db_version', 'watchdog_baseline', 'watchdog_baseline_time',
            'watchdog_last_scan', 'watchdog_scan_resume', 'watchdog_pending_verify',
            'watchdog_pending_dirs', 'watchdog_pending_core_verify',
            'watchdog_auto_quarantine',
            'watchdog_email_alerts', 'watchdog_monitor_only',
            'watchdog_allow_subdomains',
            'watchdog_whitelist_domains', 'watchdog_whitelist_patterns',
            'watchdog_whitelist_plugins', 'watchdog_whitelist_themes',
            'watchdog_exclusions', 'watchdog_trust_plugins', 'watchdog_trust_themes',
            'watchdog_remove_mu_on_deactivate', 'watchdog_mu_version',
            'watchdog_core_verify', 'watchdog_verify_summary',
            'watchdog_logged_findings',
        ] as $option) {
            delete_option($option);
        }
        foreach (array_keys(SiteChecks::OPTIONS) as $option) {
            delete_option($option);
        }

        delete_transient('watchdog_scan_lock');
        delete_transient('watchdog_alert_cooldown');
        delete_transient('watchdog_verify_active');
        wp_clear_scheduled_hook('watchdog_weekly_event');
        wp_clear_scheduled_hook('watchdog_debounced_scan');
        wp_clear_scheduled_hook('watchdog_scan_continue');
        wp_clear_scheduled_hook('watchdog_scan_continue_fast');
    }

    /**
     * One-time option defaults (idempotent via add_option).
     */
    private static function installDefaults(): void {
        add_option('watchdog_auto_quarantine', 0);
        add_option('watchdog_email_alerts', 1);
        add_option('watchdog_monitor_only', 1);
        add_option('watchdog_allow_subdomains', 1);
        add_option('watchdog_remove_mu_on_deactivate', 1);
        add_option('watchdog_whitelist_domains', '', '', false);
        add_option('watchdog_whitelist_patterns', '', '', false);
        add_option('watchdog_whitelist_plugins', '', '', false);
        add_option('watchdog_whitelist_themes', '', '', false);
        add_option('watchdog_exclusions', '', '', false);
        add_option('watchdog_trust_plugins', [], false);
        add_option('watchdog_trust_themes', [], false);
        add_option('watchdog_pending_verify', [], false);
        add_option('watchdog_pending_dirs', [], false);
        add_option('watchdog_pending_core_verify', 0, false);

        // Scan checks — Wordfence High Sensitivity set, all ON by default.
        foreach (array_keys(SiteChecks::OPTIONS) as $option) {
            add_option($option, 1);
        }
    }

    private static function markUpgraded(): void {
        update_option(self::DB_VERSION_OPTION, self::VERSION, false);
    }
}
