<?php
/**
 * Dashboard: security score, threat level, 30-day severity chart, last
 * scan with one-click quarantine/plugin actions, trust management,
 * verification status, event timeline, JS redirect log and quarantine
 * management. Every action is nonce-protected and capability checked; all
 * output is escaped.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * Dashboard — premium presentation layer.
 *
 * Rendering only. All handlers, nonces and form contracts from earlier
 * versions are preserved verbatim so no backend behaviour changes.
 */
final class Dashboard {

    private const PAGE = 'watchdog';

    /**
     * Register the admin menu page.
     */
    public static function menu(): void {
        add_menu_page(
            'Watchdog',
            'Watchdog',
            'manage_options',
            self::PAGE,
            [self::class, 'render']
        );
    }

    /**
     * Load the design system + dashboard scripts only on the Watchdog page.
     */
    public static function enqueueAssets(): void {
        if (!isset($_GET['page']) || $_GET['page'] !== self::PAGE) {
            return;
        }

        $base   = __DIR__ . '/../';
        $url    = plugin_dir_url(dirname(__DIR__) . '/watchdog.php');

        $css = realpath($base . 'assets/css/watchdog.css');
        if ($css) {
            wp_enqueue_style(
                'watchdog-admin',
                $url . 'assets/css/watchdog.css',
                [],
                Plugin::VERSION
            );
        }

        $tabs = __DIR__ . '/../assets/js/admin-tabs.js';
        if (is_file($tabs)) {
            wp_enqueue_script(
                'watchdog-admin-tabs',
                $url . 'assets/js/admin-tabs.js',
                [],
                Plugin::VERSION,
                true
            );
        }

        $ui = __DIR__ . '/../assets/js/watchdog.js';
        if (is_file($ui)) {
            wp_enqueue_script(
                'watchdog-ui',
                $url . 'assets/js/watchdog.js',
                [],
                Plugin::VERSION,
                true
            );
            wp_localize_script('watchdog-ui', 'WatchdogUi', [
                'siteName' => wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES),
            ]);
        }

        $progress = __DIR__ . '/../assets/js/scan-progress.js';
        if (is_file($progress)) {
            wp_enqueue_script(
                'watchdog-scan-progress',
                $url . 'assets/js/scan-progress.js',
                [],
                Plugin::VERSION,
                true
            );
            wp_localize_script('watchdog-scan-progress', 'WatchdogScanProgress', [
                'endpoint' => admin_url('admin-ajax.php'),
                'nonce'    => wp_create_nonce('watchdog_scan_progress'),
            ]);
        }

        $verify = __DIR__ . '/../assets/js/verify-panel.js';
        if (is_file($verify)) {
            wp_enqueue_script(
                'watchdog-verify-panel',
                $url . 'assets/js/verify-panel.js',
                [],
                Plugin::VERSION,
                true
            );
            wp_localize_script('watchdog-verify-panel', 'WatchdogVerifyStatus', [
                'endpoint' => admin_url('admin-ajax.php'),
                'nonce'    => wp_create_nonce('watchdog_verify_status'),
            ]);
        }
    }

    /**
     * Main dashboard view (app shell).
     */
    public static function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized.', 'watchdog'), 403);
        }

        $last = Scanner::buildReport();
        $counts = Logger::severityCounts(7);
        $quarantine = Quarantine::list();

        echo '<div class="watch-shell" id="watchdog-shell" data-wd-theme="light">';

        self::renderTopbar();

        echo '<div class="wrap wd-content">';

        self::showNotice();

        echo '<section class="watchdog-tab" id="watchdog-tab-overview" aria-labelledby="wd-title-overview">';
        echo '<h2 class="wd-page-title" id="wd-title-overview">' . self::icon('grid') . ' Dashboard</h2>';
        echo '<p class="wd-page-sub">Security status at a glance.</p>';
        self::renderOverview($last, $counts, $quarantine);
        echo '</section>';

        echo '<section class="watchdog-tab" id="watchdog-tab-scan" aria-labelledby="wd-title-scan">';
        echo '<h2 class="wd-page-title" id="wd-title-scan">' . self::icon('search') . ' Security Scanner</h2>';
        echo '<p class="wd-page-sub">Scans core, plugins, themes and uploads in the background.</p>';
        $scanProgress = Scanner::progress();
        if ($scanProgress !== null) {
            self::renderScanProgress($scanProgress);
            self::renderScanInProgressNote();
        } else {
            self::renderScanActions();
            self::renderScanResults($last);
        }
        echo '</section>';

        echo '<section class="watchdog-tab" id="watchdog-tab-verification" aria-labelledby="wd-title-verification">';
        echo '<h2 class="wd-page-title" id="wd-title-verification">' . self::icon('shield') . ' Integrity &amp; Checksums</h2>';
        echo '<p class="wd-page-sub">Verifies files against official WordPress.org packages.</p>';
        self::renderVerification();
        echo '</section>';

        echo '<section class="watchdog-tab" id="watchdog-tab-quarantine" aria-labelledby="wd-title-quarantine">';
        echo '<h2 class="wd-page-title" id="wd-title-quarantine">' . self::icon('layers') . ' Quarantine</h2>';
        echo '<p class="wd-page-sub">Flagged files are isolated here. Nothing is deleted automatically.</p>';
        self::renderQuarantine($quarantine);
        echo '</section>';

        echo '<section class="watchdog-tab" id="watchdog-tab-settings" aria-labelledby="wd-title-settings">';
        echo '<h2 class="wd-page-title" id="wd-title-settings">' . self::icon('sliders') . ' Settings</h2>';
        echo '<p class="wd-page-sub">Configure how Watchdog protects your site.</p>';
        self::renderSettings();
        echo '</section>';

        echo '</div>';
        echo '</div>';

        echo '<div class="wd-toast-holder" aria-live="polite" aria-atomic="true"></div>';
    }

    /**
     * One-shot admin notice (set by handlers / live protection).
     */
    public static function showNotice(): void {
        $notice = Logger::consumeNotice();
        if ($notice === '') {
            return;
        }
        echo '<div class="wd-notice wd-notice-info" role="status">'
            . self::icon('info')
            . '<span>' . esc_html($notice) . '</span>'
            . '<button type="button" class="wd-notice-close" aria-label="Dismiss">' . esc_html('×') . '</button>'
            . '</div>';
    }

    /* ------------------------------------------------------------------
     * Rendering helpers
     * ---------------------------------------------------------------- */

    /**
     * Inline SVG icon set (Feather-style, currentColor).
     */
    private static function icon(string $name): string {
        static $paths = [
            'grid'     => '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/>',
            'search'   => '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
            'shield'   => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
            'check'    => '<path d="M20 6 9 17l-5-5"/>',
            'check-big'=> '<circle cx="12" cy="12" r="10"/><path d="m8 12 2.7 2.7L16.5 9.5"/>',
            'lock'     => '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
            'alert'    => '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
            'activity' => '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
            'sliders'  => '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3"/><path d="M1 14h6M9 8h6M17 16h6"/>',
            'menu'     => '<path d="M3 12h18M3 6h18M3 18h18"/>',
            'moon'     => '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
            'sun'      => '<circle cx="12" cy="12" r="4.5"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
            'download' => '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
            'eye'      => '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
            'copy'     => '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
            'info'     => '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
            'trash'    => '<path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/>',
            'zap'      => '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
            'layers'   => '<path d="m12 2 10 6-10 6L2 8l10-6z"/><path d="m2 17 10 5 10-5"/><path d="m2 12 10 5 10-5"/>',
            'refresh'  => '<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 3v6h-6"/>',
            'file'     => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
            'folder'   => '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
            'key'      => '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
            'external' => '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/>',
            'x'        => '<path d="M18 6 6 18M6 6l12 12"/>',
            'ban'      => '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
            'clock'    => '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
            'plays'    => '<path d="M4 4h16v16H4z"/>',
            'web'      => '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
            'hard-drive' => '<path d="M22 12H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
        ];
        $inner = isset($paths[$name]) ? $paths[$name] : '';
        if ($inner === '') {
            return '';
        }
        return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
            . 'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
            . $inner
            . '</svg>';
    }

    /**
     * Top strip: brand, classic WordPress tab bar and theme toggle.
     * Kept compatible with the admin-tabs.js contracts
     * (.nav-tab-wrapper / .nav-tab / [data-tab]).
     */
    private static function renderTopbar(): void {
        $tabs = [
            'overview'     => ['Dashboard', 'grid'],
            'scan'         => ['Scanner', 'search'],
            'verification' => ['Integrity', 'shield'],
            'quarantine'   => ['Quarantine', 'layers'],
            'settings'     => ['Settings', 'sliders'],
        ];

        echo '<header class="wd-topbar" id="wd-topbar">';

        echo '<div class="wd-brand">'
            . self::icon('shield')
            . '<span><strong>Watchdog</strong><small>Security Suite</small></span>'
            . '</div>';

        echo '<nav class="nav-tab-wrapper" aria-label="' . esc_attr__('Watchdog', 'watchdog') . '">';
        $first = true;
        foreach ($tabs as $key => $def) {
            $id = 'watchdog-tab-' . $key;
            echo '<a class="nav-tab wd-tab' . ($first ? ' nav-tab-active' : '') . '"'
                . ' href="#' . esc_attr($id) . '"'
                . ' data-tab="' . esc_attr($id) . '"'
                . ' data-wd-label="' . esc_attr($def[0]) . '">'
                . self::icon($def[1])
                . '<span>' . esc_html($def[0]) . '</span>'
                . '</a>';
            $first = false;
        }
        echo '</nav>';

        echo '<div class="wd-topbar-actions">'
            . '<button type="button" class="wd-icon-btn" id="wd-theme-toggle" aria-label="Toggle dark mode">'
            . '<span class="wd-ic-moon">' . self::icon('moon') . '</span>'
            . '<span class="wd-ic-sun">' . self::icon('sun') . '</span>'
            . '</button>'
            . '</div>';

        echo '</header>';
    }

    /**
     * Security score (0-100) computed from recent signals.
     */
    private static function securityScore(array $counts, array $quarantine): int {
        $score = 100;
        $score -= min(60, $counts['critical'] * 15);
        $score -= min(30, $counts['warning'] * 5);
        if (count($quarantine) > 0) {
            $score -= 20;
        }
        $core = Checksums::coreVerifyResult();
        if (($core['status'] ?? '') === 'modified') {
            $score -= 30;
        }
        return max(0, min(100, $score));
    }

    private static function scoreColors(int $score): array {
        if ($score >= 80) {
            return ['color' => '#10b981', 'level' => 'GOOD', 'label' => 'Strong posture — no action needed.'];
        }
        if ($score >= 50) {
            return ['color' => '#f59e0b', 'level' => 'WATCH', 'label' => 'Review flagged items below.'];
        }
        return ['color' => '#ef4444', 'level' => 'CRITICAL', 'label' => 'Review critical findings now.'];
    }

    /**
     * Overview page: hero (gauge + threat level), stat tiles, charts,
     * recent events and quick actions.
     */
    private static function renderOverview(array $last, array $counts, array $quarantine): void {
        $score = self::scoreColors(self::securityScore($counts, $quarantine));
        $r = 80;
        $c = 2 * M_PI * $r;
        $offset = $c * (1 - (self::securityScore($counts, $quarantine) / 100));

        $files = isset($last['total']) ? (int) $last['total'] : 0;
        $lastScanText = !empty($last['time'])
            ? wp_date('Y-m-d H:i:s', (int) $last['time'])
            : 'Not yet';

        $runtimeOn = (int) get_option('watchdog_monitor_only', 0) === 0 ? 'Active' : 'Monitor-only';
        $critical7  = (int) $counts['critical'];
        $warning7   = (int) $counts['warning'];
        $redirects  = Logger::countToday('redirect_blocked');

        echo '<div class="wd-card">'
            . '<div class="wd-hero">';
        // — gauge
        echo '<div class="wd-gauge" style="--wd-gauge-color:' . esc_attr($score['color']) . ';">'
            . '<svg viewBox="0 0 200 200" role="img" aria-label="Security score ' . esc_attr((string) self::securityScore($counts, $quarantine)) . ' out of 100">'
            . '<circle class="wd-gauge-track" cx="100" cy="100" r="' . (int) $r . '"></circle>'
            . '<circle class="wd-gauge-value" cx="100" cy="100" r="' . (int) $r . '"'
            . ' stroke-dasharray="' . esc_attr((string) $c) . '" stroke-dashoffset="' . esc_attr((string) $offset) . '"></circle>'
            . '</svg>'
            . '<div class="wd-gauge-caption"><strong>' . (int) self::securityScore($counts, $quarantine) . '</strong>'
            . '<span>Security score</span></div>'
            . '</div>';

        // Hero info
        echo '<div class="wd-hero-info">'
            . '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">'
            . '<span class="wd-threat" style="background:' . esc_attr(self::threatBg($score['level'])) . ';color:' . esc_attr($score['color']) . ';">'
            . self::icon('shield') . esc_html($score['level']) . '</span>'
            . '</div>'
            . '<p style="color:var(--wd-text-mid);margin:10px 0 0;font-size:13.5px;max-width:560px;">' . esc_html($score['label']) . '</p>'
            . '<div class="wd-hero-meta">'
            . '<span class="wd-chip">' . self::icon('clock') . '<span>Last scan <strong>' . esc_html($lastScanText) . '</strong></span></span>'
            . '<span class="wd-chip">' . self::icon('search') . '<span>Files scanned <strong>' . esc_html(number_format_i18n($files)) . '</strong></span></span>'
            . '<span class="wd-chip">' . self::icon('shield') . '<span>Runtime protection <strong>' . esc_html($runtimeOn) . '</strong></span></span>'
            . '<span class="wd-chip">' . self::icon('layers') . '<span>Quarantined <strong>' . esc_html(count($quarantine)) . '</strong></span></span>'
            . '</div>'
            . '<div class="wd-actions" style="margin-top:16px;">'
            . self::tabLink('scan', 'Run scan', 'wd-btn wd-btn-primary')
            . self::tabLink('verification', 'Verify checksums', 'wd-btn wd-btn-secondary')
            . self::tabLink('quarantine', 'Review quarantine', 'wd-btn wd-btn-ghost')
            . self::tabLink('timeline', 'View logs', 'wd-btn wd-btn-ghost')
            . '</div>'
            . '</div>'
            . '</div>'
            . '</div>';

        // Quick stats
        $stats = [
            ['Files scanned', (string) $files, 'search', 'primary'],
            ['Critical (7d)', (string) $critical7, 'alert', $critical7 > 0 ? 'danger' : 'primary'],
            ['Warning (7d)', (string) $warning7, 'alert', $warning7 > 0 ? 'warning' : 'primary'],
            ['Redirects today', (string) $redirects, 'ban', $redirects > 0 ? 'warning' : 'primary'],
            ['Quarantined', (string) count($quarantine), 'layers', count($quarantine) > 0 ? 'danger' : 'primary'],
            ['Untrusted plugins', (string) Trust::installedCount('plugin', Trust::UNKNOWN), 'key', 'primary'],
        ];        echo '<div class="wd-stats">';
        foreach ($stats as $s) {
            $accent = $s[3];
            $map = ['primary' => 'var(--wd-primary)', 'danger' => 'var(--wd-danger)', 'warning' => 'var(--wd-warning)'];
            echo '<div class="wd-stat" style="--wd-stat-accent:' . esc_attr($map[$accent]) . ';--wd-stat-bg:' . esc_attr(self::statBg($accent)) . ';">'
                . '<span class="wd-stat-icon">' . self::icon($s[2]) . '</span>'
                . '<strong>' . esc_html($s[1]) . '</strong>'
                . '<small>' . esc_html($s[0]) . '</small>'
                . '</div>';
        }
        echo '</div>';

        // Threat history + recent activity
        echo '<div class="wd-grid">';
        self::renderChart();
        self::renderRecentActivity();
        echo '</div>';
    }

    private static function threatBg(string $level): string {
        if ($level === 'GOOD') {
            return 'var(--wd-success-weak)';
        }
        if ($level === 'CRITICAL') {
            return 'var(--wd-danger-weak)';
        }
        return 'var(--wd-warning-weak)';
    }

    private static function statBg(string $key): string {
        return [
            'primary' => 'var(--wd-primary-weak)',
            'danger'  => 'var(--wd-danger-weak)',
            'warning' => 'var(--wd-warning-weak)',
        ][$key];
    }

    /**
     * Tab-switch link used for quick actions (no server round-trip).
     */
    private static function tabLink(string $key, string $label, string $class): string {
        $id = 'watchdog-tab-' . $key;
        return '<a class="wd-btn ' . esc_attr($class) . '" href="#' . esc_attr($id) . '" data-tab="' . esc_attr($id) . '">'
            . esc_html($label) . '</a>';
    }

    /**
     * 30-day severity chart (inline SVG, no external requests).
     */
    private static function renderChart(): void {
        $series = Logger::severitySeries(30);
        $max = 1;
        foreach ($series as $day) {
            $max = max($max, $day['critical'] + $day['warning'] + $day['info']);
        }

        $width = 620;
        $height = 150;
        $colWidth = $width / max(1, count($series));
        $colors = ['critical' => 'var(--wd-danger)', 'warning' => 'var(--wd-warning)', 'info' => 'var(--wd-info)'];
        $bars = '';

        foreach ($series as $i => $day) {
            $x = (int) round($i * $colWidth);
            $offset = 0;
            foreach (['critical', 'warning', 'info'] as $sev) {
                $count = (int) $day[$sev];
                if ($count === 0) {
                    continue;
                }
                $h = (int) max(2, round($count / $max * ($height - 26)));
                $y = $height - 16 - $offset - $h;
                $offset += $h;
                $bars .= '<rect x="' . $x . '" y="' . $y . '" width="' . (int) max(2, round($colWidth - 4)) . '" height="' . $h . '" rx="1.5" fill="' . $colors[$sev] . '">'
                    . '<title>' . esc_html($day['date'] . ' — ' . $sev . ': ' . $count) . '</title></rect>';
            }
        }

        echo '<div class="wd-card">'
            . '<div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('activity') . ' Threat history (30 days)</h3></div>'
            . '<svg viewBox="0 0 ' . (int) $width . ' ' . (int) $height . '" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto;" role="img" aria-label="Daily threat counts by severity">'
            . $bars
            . '</svg>'
            . '<div class="wd-card-foot" style="display:flex;gap:14px;">'
            . '<span class="wd-badge"><span class="wd-sev wd-sev-critical">Crit</span>&nbsp;Critical</span>'
            . '<span class="wd-badge"><span class="wd-sev wd-sev-warning">W</span>&nbsp;Warning</span>'
            . '<span class="wd-badge"><span class="wd-sev wd-sev-info">I</span>&nbsp;Informational</span>'
            . '</div>'
            . '</div>';
    }

    /**
     * Latest 8 security events.
     */
    private static function renderRecentActivity(): void {
        $events = Logger::query(8);
        $sevColor = ['critical' => 'var(--wd-danger)', 'warning' => 'var(--wd-warning)', 'info' => 'var(--wd-info)', 'safe' => 'var(--wd-success)'];

        echo '<div class="wd-card">'
            . '<div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('clock') . ' Recent activity</h3>'
            . '<a class="wd-btn wd-btn-ghost" href="#watchdog-tab-timeline" data-tab="watchdog-tab-timeline">View all</a></div>';

        if (empty($events)) {
            echo '<div class="wd-empty" style="padding:24px 12px;">' . self::icon('check-big')
                . '<strong>All quiet</strong><p>No events yet.</p></div>';
        } else {
            echo '<ul class="wd-timeline">';
            foreach ($events as $event) {
                $color = isset($sevColor[$event['severity']]) ? $sevColor[$event['severity']] : 'var(--wd-text-mute)';
                echo '<li class="wd-tl-' . esc_attr($event['severity']) . '">'
                    . '<div class="wd-tl-head">'
                    . '<strong>' . esc_html($event['type']) . '</strong>'
                    . '<span class="wd-sev wd-sev-' . esc_attr($event['severity']) . '">' . esc_html($event['severity']) . '</span>'
                    . '<span class="wd-tl-time">' . esc_html(wp_date('M j, H:i', strtotime((string) $event['event_time']))) . '</span>'
                    . '</div>'
                    . '<div class="wd-tl-src"><code>' . esc_html((string) $event['source']) . '</code></div>'
                    . '<div class="wd-tl-detail">' . esc_html((string) $event['ip']) . (($event['username'] ?? '') !== '' ? ' · ' . esc_html((string) $event['username']) : '') . '</div>'
                    . '</li>';
            }
            echo '</ul>';
        }
        echo '</div>';
    }

    /**
     * Scan progress panel: shown while a scan run is active (or between
     * background segments). Modeled on the Wordfence scan "workflow":
     * a large percentage, a progress bar and a stage checklist that
     * ticks off as the scan advances. Server-rendered on load and
     * refreshed live by scan-progress.js (class names are its DOM
     * contract — do not rename).
     */
    private static function renderScanProgress(?array $progress): void {
        if ($progress === null) {
            return;
        }
        $total = max(0, (int) ($progress['total'] ?? 0));
        $scanned = max(0, min((int) ($progress['scanned'] ?? 0), $total));
        $percent = $total > 0 ? (int) round($scanned / $total * 100) : 0;
        $running = !empty($progress['running']);
        $scopeLabel = isset($progress['scope_label']) ? (string) $progress['scope_label'] : 'Everything';
        $segments = max(1, (int) ($progress['segments'] ?? 1));
        $currentPath = (string) ($progress['current_path'] ?? '');
        $currentUpdated = (int) ($progress['current_updated'] ?? 0);
        $currentFresh = $currentUpdated > 0 && (time() - $currentUpdated) < 75;
        $recentFiles = isset($progress['current_files']) && is_array($progress['current_files'])
            ? $progress['current_files']
            : [];

        $stages = [
            1 => 'Indexing files',
            2 => 'Scanning for malware',
            3 => 'Checking redirects',
            4 => 'Verifying core',
            5 => 'Building report',
        ];
        $thresholds = [0, 20, 45, 75, 95];
        $stageHtml = '<ul class="wd-stages">';
        $activeNum = 6;
        $i = 0;
        foreach ($stages as $num => $label) {
            $i++;
            $done = $percent >= (int) $thresholds[$i - 1];
            if (!$done && $activeNum > $num) {
                $activeNum = $num;
            }
            $state = $done ? 'wd-stage-done' : (($running && $num === $activeNum) ? 'wd-stage-active' : 'wd-stage-pending');
            $stageHtml .= '<li class="wd-stage ' . $state . '"><span class="wd-stage-ic"></span>'
                . '<span class="wd-stage-label">' . $label . '</span></li>';
        }
        $stageHtml .= '</ul>';

        $currentLine = '';
        if ($currentPath !== '') {
            $currentLine = '<div class="watchdog-progress-current wd-scan-file">'
                . esc_html($currentFresh ? 'Scanning: ' : 'Last file: ')
                . '<code>' . esc_html($currentPath) . '</code></div>';
        }

        $log = '';
        if ($recentFiles !== []) {
            $log = '<ul class="watchdog-progress-log wd-file-list" style="margin-top:8px;max-height:170px;">';
            foreach ($recentFiles as $file) {
                $stamp = '';
                if (is_array($file) && !empty($file['ts'])) {
                    $stamp = wp_date('H:i:s', (int) $file['ts']);
                }
                $path = is_array($file) ? (string) ($file['path'] ?? '') : (string) $file;
                $log .= '<li><span class="wd-file-stamp">' . esc_html($stamp) . '</span><span>' . esc_html($path) . '</span></li>';
            }
            $log .= '</ul>';
        }

        echo '<div id="watchdog-scan-progress" class="wd-card wd-scan-live">'
            . '<div class="wd-card-head">'
            . '<span class="wd-status"><span class="wd-dot wd-dot-live"></span>'
            . '<strong class="watchdog-progress-status">' . esc_html($running ? 'Scanning' : 'Scan queued') . '</strong></span>'
            . '<div class="wd-actions">'
            . '<span class="watchdog-progress-scope wd-badge">' . esc_html($scopeLabel) . '</span>'
            . self::postForm('watchdog_stop_scan', 'Stop Scan', 'button-link-delete', 'watchdog_stop_scan_action', 'watchdog_stop_scan_nonce')
            . '</div></div>'
            . '<div class="wd-scan-meter">'
            . '<span class="watchdog-progress-pct wd-scan-pct">' . (int) $percent . '%</span>'
            . '<div class="wd-progress wd-progress-lg"><div class="watchdog-progress-fill wd-progress-fill" style="width:' . (int) $percent . '%;"></div></div>'
            . '<div class="watchdog-progress-meta wd-scan-count">'
            . '<strong>' . esc_html(number_format_i18n($scanned)) . '</strong> of '
            . esc_html(number_format_i18n($total)) . ' files processed</div>'
            . '</div>'
            . $stageHtml
            . $currentLine
            . '<details class="wd-scan-details"><summary>Live details</summary>'
            . '<div class="wd-scan-meta">'
            . '<span>Segment <span class="watchdog-progress-segment">' . (int) $segments . '</span></span>'
            . '<span class="watchdog-progress-eta">' . esc_html($running ? 'Running' : 'Queued — next segment') . '</span>'
            . '</div>'
            . $log
            . '</details>'
            . '</div>';
    }

    /**
     * Scan start UI with scope picker.
     */
    private static function renderScanActions(): void {
        $order = ['all', 'core', 'plugins', 'themes', 'uploads', 'content'];
        $scopes = Scanner::scopes();
        $help = [
            'all'     => 'Full site scan.',
            'core'    => 'WordPress core.',
            'plugins' => 'All plugins.',
            'themes'  => 'All themes.',
            'uploads' => 'Media uploads.',
            'content' => 'Other wp-content files.',
        ];
        $icons = [
            'all' => 'layers', 'core' => 'shield', 'plugins' => 'key',
            'themes' => 'layout', 'uploads' => 'folder', 'content' => 'folder',
        ];

        echo '<div class="wd-card wd-scan-start">'
            . '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">'
            . '<input type="hidden" name="action" value="watchdog_scan">'
            . wp_nonce_field('watchdog_scan_action', 'watchdog_scan_nonce', true, false)
            . '<div class="wd-actions wd-scan-start-head" style="align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:0;">'
            . '<div class="wd-scan-start-title">'
            . '<h3 class="wd-card-title" style="margin:0;">' . self::icon('search') . ' Run a scan</h3>'
            . '<p class="wd-scan-start-sub">Runs in the background — no need to stay on this page.</p>'
            . '</div>'
            . get_submit_button('Start Scan', 'primary', '', false)
            . '</div>'
            . '<div class="wd-scopes wd-scopes-chips">';
        foreach ($order as $key) {
            $label = isset($scopes[$key]) ? $scopes[$key] : $key;
            $desc = isset($help[$key]) ? $help[$key] : '';
            $ic = isset($icons[$key]) ? $icons[$key] : 'folder';
            echo '<label class="wd-scope" title="' . esc_attr($desc) . '">'
                . '<input type="checkbox" name="watchdog_scope[]" value="' . esc_attr($key) . '"' . checked($key, 'all', false) . '>'
                . '<span class="wd-scope-box" tabindex="-1">'
                . '<span class="wd-scope-name">' . self::icon($ic) . esc_html($label) . '</span>'
                . '</span>'
                . '</label>';
        }
        echo '</div></form>'
            . '<div class="wd-scan-baseline">'
            . '<span>Baseline: snapshot the site as clean.</span>'
            . self::postForm('watchdog_restore_baseline', 'Restore baseline', 'secondary', 'watchdog_restore_baseline_action', 'watchdog_restore_baseline_nonce')
            . '</div>'
            . '</div>';
    }

    /**
     * Replaces the (old) results card while a scan run is active, so a
     * fresh scan never shows the previous run's findings next to it.
     */
    private static function renderScanInProgressNote(): void {
        echo '<div class="wd-card wd-scan-results">'
            . '<div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('search') . ' Scan results</h3></div>'
            . '<div class="wd-empty">' . self::icon('clock')
            . '<strong>Scan in progress</strong>'
            . '<p>Results appear here when the scan finishes.</p>'
            . '</div></div>';
    }

    private static function renderScanResults(array $last): void {
        $total = (int) ($last['total'] ?? 0);
        $scanned = (int) ($last['scanned'] ?? 0);
        echo '<div class="wd-card wd-scan-results">'
            . '<div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('search') . ' Scan results</h3>'
            . '<span class="wd-badge">' . esc_html(number_format_i18n($total)) . ' files checked'
            . ($scanned > 0 ? ' · ' . esc_html(number_format_i18n($scanned)) . ' re-scanned' : '')
            . (!empty($last['time']) ? ' · ' . esc_html(wp_date('M j Y H:i', (int) $last['time'])) : '')
            . '</span></div>';

        if (empty($last['time'])) {
            echo '<div class="wd-empty">' . self::icon('search')
                . '<strong>No scan yet</strong><p>Run a scan to see findings.</p></div>'
                . '</div>';
            return;
        }

        $groupDef = [
            'malware'    => ['Malware', 'critical', 'alert'],
            'suspicious' => ['Suspicious code', 'warning', 'ban'],
        ];
        $advisoryDef = [
            'info' => ['Quiet code patterns', 'info', 'info'],
        ];
        $notesDef = [
            'changed' => ['Changed files', 'refresh'],
            'new'     => ['New files', 'zap'],
            'deleted' => ['Deleted files', 'trash'],
        ];

        $counts = ['critical' => 0, 'warning' => 0, 'info' => 0, 'notes' => 0];
        foreach ($groupDef as $key => $def) {
            $items = isset($last[$key]) && is_array($last[$key]) ? $last[$key] : [];
            if ($items) {
                $counts[$def[1]] += count($items);
            }
        }
        $siteChecks = isset($last['checks']) && is_array($last['checks']) ? $last['checks'] : [];
        foreach ($siteChecks as $check) {
            $sev = isset($check['sev']) ? (string) $check['sev'] : 'info';
            if (isset($counts[$sev])) {
                $counts[$sev]++;
            }
        }
        $infoRows = 0;
        foreach ($advisoryDef as $key => $def) {
            $items = isset($last[$key]) && is_array($last[$key]) ? $last[$key] : [];
            $infoRows += count($items);
        }
        $counts['info'] = $infoRows;
        foreach ($notesDef as $key => $d) {
            $counts['notes'] += count(isset($last[$key]) && is_array($last[$key]) ? $last[$key] : []);
        }
        $domains = isset($last['domains']) && is_array($last['domains']) ? $last['domains'] : [];
        $alerts = $counts['critical'] + $counts['warning'];

        $expected = (int) ($last['expected'] ?? 0);
        if ($expected > 0) {
            echo '<p class="wd-scan-expect">' . self::icon('check')
                . esc_html((string) $expected) . ' expected redirect(s) allowed by the behavior engine.</p>';
        }

        echo '<div class="wd-tabs" data-wd-tabgroup="results" data-wd-default="critical">'
            . '<button type="button" class="wd-tab wd-tab-critical" data-wd-tab="critical">'
            . (int) $counts['critical'] . ' Critical</button>'
            . '<button type="button" class="wd-tab wd-tab-warning" data-wd-tab="warning">'
            . (int) $counts['warning'] . ' Warnings</button>'
            . '<button type="button" class="wd-tab wd-tab-info" data-wd-tab="info">'
            . (int) $counts['info'] . ' Informational</button>'
            . '<button type="button" class="wd-tab wd-tab-notes" data-wd-tab="notes">'
            . (int) $counts['notes'] . ' Notes</button>'
            . '</div>';

        if ($alerts === 0) {
            echo '<div class="wd-find-clear">' . self::icon('check-big')
                . '<div><strong>No malware or suspicious code detected</strong>'
                . '<p>Nothing suspicious found — informational patterns are expected.'
                . ($scanned === 0 ? ' All ' . esc_html(number_format_i18n($total)) . ' files are unchanged since the last scan — nothing to re-analyze.' : '')
                . '</p></div></div>';
        }

        $tab = ['critical' => '', 'warning' => '', 'info' => '', 'notes' => ''];

        foreach ($groupDef as $key => $def) {
            $items = isset($last[$key]) && is_array($last[$key]) ? $last[$key] : [];
            if (empty($items)) {
                continue;
            }
            $actionable = ($key === 'malware' || $key === 'suspicious');
            $tab[$def[1]] .= self::findingAccordion($def[0], count($items), $def[2], $def[1], $items, $actionable);
        }

        // Site checks (config exposure, users, passwords, posts/comments,
        // versions, disk space, suspected files, image/outside scans).
        if ($siteChecks !== []) {
            $warn = 0;
            $crit = 0;
            foreach ($siteChecks as $check) {
                $sev = isset($check['sev']) ? (string) $check['sev'] : 'info';
                if ($sev === 'warning') {
                    $warn++;
                } elseif ($sev === 'critical') {
                    $crit++;
                }
            }
            $tab['warning'] .= '<div class="wd-finding wd-fac-' . ($crit > 0 ? 'critical' : ($warn > 0 ? 'warning' : 'info')) . '">'
                . '<div class="wd-finding-head">'
                . '<span class="wd-finding-ic">' . self::icon('shield') . '</span>'
                . '<span class="wd-finding-title">Site checks (High Sensitivity)</span>'
                . '<span class="wd-finding-count">' . (int) count($siteChecks) . '</span>'
                . '</div>'
                . '<div class="wd-finding-body wd-open"><ul class="wd-file-list" data-wd-paginate="20">';
            foreach ($siteChecks as $check) {
                $sev = isset($check['sev']) ? (string) $check['sev'] : 'info';
                $badge = ['critical' => 'wd-badge-critical', 'warning' => 'wd-badge-warning', 'info' => 'wd-badge-info'];
                $tab['warning'] .= '<li><span class="wd-badge ' . (isset($badge[$sev]) ? $badge[$sev] : 'wd-badge-info') . '">' . esc_html(strtoupper($sev)) . '</span>'
                    . '<strong style="color:var(--wd-head);">' . esc_html((string) ($check['label'] ?? '')) . '</strong>'
                    . '<span class="wd-file-meta">' . esc_html((string) ($check['details'] ?? '')) . '</span></li>';
            }
            $tab['warning'] .= '</ul></div></div>';
        }

        if ($counts['info'] > 0) {
            $items = isset($last['info']) && is_array($last['info']) ? $last['info'] : [];
            $tab['info'] .= self::findingAccordion('Quiet code patterns', $counts['info'], 'info', 'info', $items, false)
                . '<p class="wd-finding-note">Common informational patterns — no action needed.</p>';
        }

        if ($domains !== []) {
            $tab['info'] .= '<div class="wd-finding wd-fac-notes">'
                . '<div class="wd-finding-head">'
                . '<span class="wd-finding-ic">' . self::icon('web') . '</span>'
                . '<span class="wd-finding-title">External domains seen in code</span>'
                . '<span class="wd-finding-count">' . (int) count($domains) . '</span>'
                . '</div>'
                . '<div class="wd-finding-body wd-open"><ul class="wd-file-list" data-wd-paginate="20">';
            foreach ($domains as $host => $dest) {
                $tab['info'] .= '<li><span style="color:var(--wd-text-mid);">' . esc_html((string) $host) . '</span>'
                    . '<span class="wd-file-meta">' . esc_html((string) $dest) . '</span></li>';
            }
            $tab['info'] .= '</ul></div></div>';
        }

        if ($counts['notes'] > 0) {
            $tab['notes'] .= '<div class="wd-finding wd-fac-notes">'
                . '<div class="wd-finding-head">'
                . '<span class="wd-finding-ic">' . self::icon('layers') . '</span>'
                . '<span class="wd-finding-title">Notes &amp; file changes</span>'
                . '<span class="wd-finding-count">' . (int) $counts['notes'] . '</span>'
                . '</div>'
                . '<div class="wd-finding-body wd-open">';
            foreach ($notesDef as $key => $def) {
                $items = isset($last[$key]) && is_array($last[$key]) ? $last[$key] : [];
                if (empty($items)) {
                    continue;
                }
                $tab['notes'] .= '<h4 class="wd-file-group">' . self::icon($def[1]) . esc_html($def[0]) . ' (' . (int) count($items) . ')</h4>'
                    . '<ul class="wd-file-list" data-wd-paginate="20">';
                $i = 0;
                foreach ($items as $path => $detail) {
                    if ($i++ >= 500) {
                        $tab['notes'] .= '<li><span class="wd-file-meta">… and ' . esc_html((string) count($items)) . ' more</span></li>';
                        break;
                    }
                    $tab['notes'] .= '<li><span>' . esc_html($path) . '</span></li>';
                }
                $tab['notes'] .= '</ul>';
            }
            $tab['notes'] .= '</div></div>';
        }

        foreach ($tab as $key => $body) {
            echo '<div class="wd-panel wd-panel-result" data-wd-panel-group="results" data-wd-panel="' . esc_attr((string) $key) . '">'
                . ($body !== '' ? $body : '<div class="wd-empty">' . self::icon('check-big')
                    . '<strong>No ' . esc_html(ucfirst((string) $key)) . ' entries</strong>'
                    . '<p>Nothing recorded for this severity.</p></div>')
                . '</div>';
        }

        echo '</div>';
    }

    /**
     * One finding group (severity, icon, paginated file rows).
     */
    private static function findingAccordion(string $title, int $total, string $icon, string $sev, array $items, bool $actionable): string {
        $html = '<div class="wd-finding wd-fac-' . esc_attr($sev) . '">'
            . '<div class="wd-finding-head">'
            . '<span class="wd-finding-ic">' . self::icon($icon) . '</span>'
            . '<span class="wd-finding-title">' . esc_html($title) . '</span>'
            . '<span class="wd-finding-count">' . (int) $total . '</span>'
            . '<span class="wd-sev wd-sev-' . esc_attr($sev) . '">' . esc_html($sev) . '</span>'
            . '</div>'
            . '<div class="wd-finding-body wd-open"><ul class="wd-file-list" data-wd-paginate="20">';
        $i = 0;
        foreach ($items as $path => $detail) {
            if ($i++ >= 500) {
                $html .= '<li><span class="wd-file-meta">… and ' . esc_html((string) count($items)) . ' more</span></li>';
                break;
            }
            $html .= '<li class="wd-file-detailed">'
                . '<span class="wd-file-row"><span class="wd-file-path">' . esc_html($path) . '</span>';
            if (is_array($detail) && !empty($detail['signatures'])) {
                $html .= '<span class="wd-file-sigs">';
                foreach ($detail['signatures'] as $sig) {
                    $html .= '<span class="wd-badge">' . esc_html($sig) . '</span>';
                }
                $html .= '</span>';
            }
            if ($actionable) {
                $html .= '<span class="wd-file-meta">' . self::itemActions($path) . '</span>';
            }
            $html .= '</span>';
            if (is_array($detail)) {
                $html .= self::fileDetailHtml($detail);
            } elseif (is_string($detail)) {
                $html .= '<div class="wd-file-note">— ' . esc_html($detail) . '</div>';
            }
            $html .= '</li>';
        }
        $html .= '</ul></div></div>';
        return $html;
    }

    /**
     * Nested details (signatures, redirect findings) for one file.
     */
    private static function fileDetailHtml(array $detail): string {
        $html = '';
        if (!empty($detail['label'])) {
            $html .= '<div style="color:var(--wd-text-mid);font-size:12.5px;">' . esc_html($detail['label']) . '</div>';
        }
        if (!empty($detail['redirects'])) {
            $html .= '<details style="margin:4px 0 0 6px;"><summary>redirect analysis</summary><ul class="wd-file-list">';
            foreach ($detail['redirects'] as $finding) {
                $dest = !empty($finding['dest']) ? $finding['dest'] : ($finding['note'] ?? '');
                $class = !empty($finding['class']) ? strtoupper((string) $finding['class']) : '';
                $reason = !empty($finding['reason']) ? $finding['reason'] : ($finding['note'] ?? '');
                $confidence = !empty($finding['confidence']) ? $finding['confidence'] : '';
                $html .= sprintf(
                    '<li><span class="wd-file-follow"><strong>%s</strong> %s → %s (line %d, %s) — %s</span></li>',
                    esc_html($class),
                    esc_html((string) $finding['call']),
                    esc_html((string) $dest),
                    (int) ($finding['line'] ?? 0),
                    esc_html((string) $confidence),
                    esc_html((string) $reason)
                );
            }
            $html .= '</ul></details>';
        }
        return $html;
    }

    /**
     * Quarantine / disable / rename buttons for a flagged file.
     */
    private static function itemActions(string $path): string {
        $html = '<span class="wd-action-inline" style="display:inline-flex;gap:6px;">'
            . '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline-block;">'
            . '<input type="hidden" name="action" value="watchdog_quarantine">'
            . '<input type="hidden" name="file" value="' . esc_attr($path) . '">'
            . wp_nonce_field('watchdog_quarantine_action', 'watchdog_quarantine_nonce', true, false)
            . '<button type="submit" class="button button-small" onclick="return confirm(\'Quarantine this file?\');">Quarantine</button>'
            . '</form>';

        $plugin = Quarantine::pluginMainFile($path);
        if ($plugin) {
            $html .= self::pluginActionForm('watchdog_disable_plugin', $plugin, 'watchdog_disable_plugin_action', 'watchdog_disable_plugin_nonce', 'Disable plugin', 'Deactivate this plugin?');
            $html .= self::pluginActionForm('watchdog_rename_plugin', $plugin, 'watchdog_rename_plugin_action', 'watchdog_rename_plugin_nonce', 'Rename folder', 'Rename the plugin folder to .disabled?', true);
        }
        return $html . '</span>';
    }

    private static function pluginActionForm(string $action, string $plugin, string $nonceAction, string $nonceField, string $label, string $confirm, bool $danger = false): string {
        return '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline-block;">'
            . '<input type="hidden" name="action" value="' . esc_attr($action) . '">'
            . '<input type="hidden" name="plugin" value="' . esc_attr($plugin) . '">'
            . wp_nonce_field($nonceAction, $nonceField, true, false)
            . '<button type="submit" class="button button-small' . ($danger ? ' button-link-delete' : '') . '" onclick="return confirm(\'' . esc_js($confirm) . '\');">' . esc_html($label) . '</button>'
            . '</form>';
    }

    /**
     * Verification status (two live cards).
     */
    private static function renderVerification(): void {
        $status = Checksums::verifyStatus();

        echo '<div class="wd-card">'
            . '<div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('shield') . ' Checksum verification</h3>'
            . '<div class="wd-actions">'
            . self::postForm('watchdog_verify_core', 'Verify Core', 'secondary', 'watchdog_verify_core_action', 'watchdog_verify_core_nonce')
            . self::postForm('watchdog_verify_packages', 'Verify Plugins &amp; Themes', 'primary', 'watchdog_verify_packages_action', 'watchdog_verify_packages_nonce')
            . '</div></div>'
            . '<p style="color:var(--wd-text-mid);font-size:13px;margin:0;">Runs in the background — results appear here automatically.</p>'
            . '</div>';

        echo '<div id="watchdog-verify-status" class="wd-grid">';

        $core = (array) ($status['core']['result'] ?? []);
        $mismatches = (array) (($core['mismatches'] ?? []) ?: []);

        echo '<div class="wd-card">'
            . '<div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('lock') . ' WordPress core</h3>'
            . '<span class="wd-badge">' . esc_html(count($mismatches) > 0 ? 'Modified' : (($core['status'] ?? '') === 'clean' ? 'Clean' : '—')) . '</span></div>'
            . '<div class="watchdog-core-state">' . self::coreStatusLine($status) . '</div>'
            . '<div class="watchdog-core-list">' . ($mismatches
                ? '<ul class="wd-file-list">' . self::ulItems($mismatches, 50) . '</ul>'
                : '') . '</div>'
            . '</div>';

        $by = isset($status['packages']['byStatus']) && is_array($status['packages']['byStatus'])
            ? $status['packages']['byStatus'] : [];
        $totalVerified = (int) array_sum($by);
        $modified = isset($status['packages']['modified']) && is_array($status['packages']['modified'])
            ? $status['packages']['modified'] : [];

        echo '<div class="wd-card">'
            . '<div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('key') . ' Plugins &amp; themes</h3>'
            . '<span class="wd-badge">' . (int) $totalVerified . ' verified</span></div>'
            . '<div class="watchdog-pkg-state">' . self::packageStatusLine($status) . '</div>'
            . '<div class="watchdog-pkg-summary">' . self::packageSummary($status) . '</div>'
            . '<div class="watchdog-pkg-list">' . ($modified
                ? '<h4 style="color:var(--wd-danger);margin:10px 0 6px;">Modified packages</h4>'
                    . '<ul class="wd-file-list">' . self::ulItems($modified, 30) . '</ul>'
                : '') . '</div>'
            . '</div>';

        echo '</div>';
    }

    private static function ulItems(array $items, int $max): string {
        $out = '';
        $i = 0;
        foreach ($items as $item) {
            if ($i++ >= $max) {
                break;
            }
            $out .= '<li><code>' . esc_html((string) $item) . '</code></li>';
        }
        return $out;
    }

    /**
     * Server-rendered state line for the core verification card.
     */
    private static function coreStatusLine(array $status): string {
        $active = (string) ($status['active'] ?? '');
        if ($active === 'core') {
            return '<span class="wd-status"><span class="wd-dot wd-dot-live"></span><strong style="color:var(--wd-success);">Verifying core files now…</strong></span>';
        }
        $core = (array) ($status['core']['result'] ?? []);
        if (!empty($status['core']['pending'])) {
            return '<span class="wd-status"><span class="wd-dot wd-dot-warn"></span><strong style="color:var(--wd-warning);">Queued</strong>&nbsp;starts shortly.</span>';
        }
        if (empty($core['time'])) {
            return '<span style="color:var(--wd-text-mid);">Not verified yet.</span>';
        }
        $s = (string) ($core['status'] ?? 'error');
        $time = esc_html(wp_date('Y-m-d H:i:s', (int) ($core['time'] ?? 0)));
        $verified = (int) ($core['verified'] ?? 0);
        $mis = count((array) ($core['mismatches'] ?? []));
        $missing = count((array) ($core['missing'] ?? []));
        switch ($s) {
            case 'clean':
                return '<span class="wd-status"><span class="wd-dot" style="background:var(--wd-success);"></span><strong style="color:var(--wd-success);">Clean</strong> — ' . $verified . ' file(s) match (checked ' . $time . ').</span>';
            case 'modified':
                return '<span class="wd-status"><span class="wd-dot wd-dot-crit"></span><strong style="color:var(--wd-danger);">Modified</strong> — ' . $mis . ' file(s) differ (' . $time . ', ' . $missing . ' missing).</span>';
            case 'unavailable':
                return '<span class="wd-status"><span class="wd-dot wd-dot-warn"></span><strong style="color:var(--wd-warning);">Unavailable</strong> — no official checksums for this version/locale (' . $time . ').</span>';
            default:
                return '<span class="wd-status"><span class="wd-dot wd-dot-warn"></span><strong style="color:var(--wd-warning);">Error</strong> — could not reach checksum API (' . $time . ').</span>';
        }
    }

    private static function packageStatusLine(array $status): string {
        if ($status['active'] !== '' && $status['active'] !== 'core') {
            return '<span class="wd-status"><span class="wd-dot wd-dot-live"></span><strong style="color:var(--wd-success);">Working on: <code>' . esc_html((string) $status['active']) . '</code></strong></span>';
        }
        if ((int) ($status['packages']['queued'] ?? 0) > 0) {
            return '<span class="wd-status"><span class="wd-dot wd-dot-warn"></span><strong style="color:var(--wd-warning);">' . (int) $status['packages']['queued'] . ' queued — starting shortly.</strong></span>';
        }
        return '<span style="color:var(--wd-text-mute);">No verification running.</span>';
    }

    private static function packageSummary(array $status): string {
        $by = isset($status['packages']['byStatus']) && is_array($status['packages']['byStatus']) ? $status['packages']['byStatus'] : [];
        $total = (int) array_sum($by);
        $installed = (int) ($status['packages']['installed'] ?? 0);
        $last = (int) ($status['packages']['last'] ?? 0);
        if ($total === 0) {
            return 'Not verified yet.';
        }
        $labels = [
            'clean' => 'Clean', 'modified' => 'Modified', 'not-on-wordpress' => 'Not on WP.org',
            'version-mismatch' => 'Version differs', 'download-error' => 'Download failed',
            'error' => 'Error', 'other' => 'Other',
        ];
        $parts = [];
        foreach ($by as $key => $count) {
            $parts[] = (isset($labels[$key]) ? $labels[$key] : 'Other') . ' ' . (int) $count;
        }
        $out = '<strong>' . (int) $total . '</strong> verified' . ($installed > 0 ? ' of ' . (int) $installed : '') . ' — ' . esc_html(implode(' · ', $parts)) . '.';
        if ($last > 0) {
            $out .= '<br><span style="color:var(--wd-text-mute);font-size:12px;">Last activity: ' . esc_html(wp_date('Y-m-d H:i:s', $last)) . '.</span>';
        }
        return $out;
    }

    private static function renderQuarantine(array $items): void {
        echo '<div class="wd-card">'
            . '<div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('layers') . ' Quarantined files</h3>'
            . self::postForm('watchdog_export_quarantine', 'Download Zip', 'secondary', 'watchdog_export_quarantine_action', 'watchdog_export_quarantine_nonce')
            . '</div>';

        if (empty($items)) {
            echo '<div class="wd-empty">' . self::icon('check-big')
                . '<strong>Nothing quarantined</strong>'
                . '<p>Flagged files land here; nothing is deleted automatically.</p></div>'
                . '</div>';
            return;
        }

        echo '<div class="wd-table-controls">'
            . '<label class="wd-search">' . self::icon('search')
            . '<input type="search" placeholder="Filter files…" data-wd-search="#wd-quarantine-table" aria-label="Filter quarantined files"></label>'
            . '</div>';

        echo '<div class="wd-table-wrap"><table class="wd-table" id="wd-quarantine-table">'
            . '<thead><tr><th style="width:100%;">File</th><th class="wd-sort">Quarantined</th><th>Size</th><th>Actions</th></tr></thead>'
            . '<tbody>';
        foreach ($items as $item) {
            $name = (string) $item['name'];
            $preview = '';
            $path = Quarantine::dir() . DIRECTORY_SEPARATOR . $name;
            $content = @file_get_contents($path);
            if ($content !== false) {
                $text = mb_substr($content, 0, 4000);
                $id  = 'wd-qp-' . sanitize_key($name);
                $preview = '<details style="margin-top:6px;"><summary>Preview</summary>'
                    . '<pre class="wd-log-pre" id="' . esc_attr($id) . '">' . esc_html($text) . '</pre>'
                    . '<div class="wd-actions" style="margin-top:8px;">'
                    . '<button type="button" class="button button-small" data-wd-copy="#' . esc_attr($id) . '"><span class="wd-copy-label">Copy</span></button>'
                    . '</div></details>';
            } elseif (is_file($path)) {
                $preview = '<p style="color:var(--wd-text-mute);font-size:12px;">Binary — no preview.</p>';
            }

            echo '<tr>'
                . '<td><code>' . esc_html($name) . '</code>'
                . '<div style="color:var(--wd-text-mute);font-size:11.5px;">' . esc_html($item['original'] !== '' ? $item['original'] : 'original path unknown') . '</div>'
                . $preview . '</td>'
                . '<td style="white-space:nowrap;">' . esc_html(wp_date('Y-m-d H:i', $item['mtime'])) . '</td>'
                . '<td>' . esc_html(size_format($item['size'])) . '</td>'
                . '<td><div class="wd-actions">'
                . '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">'
                . '<input type="hidden" name="action" value="watchdog_restore_quarantine">'
                . '<input type="hidden" name="file" value="' . esc_attr($name) . '">'
                . wp_nonce_field('watchdog_restore_quarantine_action', 'watchdog_restore_quarantine_nonce', true, false)
                . '<button type="submit" class="button button-small">Restore</button></form>'
                . '</div></td>'
                . '</tr>';
        }
        echo '</tbody></table><div class="wd-table-empty" style="display:none;">No quarantined files match the filter.</div></div>';

        echo '</div>';
    }

    /**
     * Event timeline.
     */
    private static function renderTimeline(): void {
        $events = Logger::query(200);

        $last = (array) get_option('watchdog_last_scan', []);
        $destinations = [];
        foreach ($events as $event) {
            if (($event['type'] ?? '') === 'redirect_blocked') {
                $det = json_decode((string) ($event['details'] ?? ''), true);
                $dest = is_array($det) && !empty($det['destination']) ? trim((string) $det['destination']) : '';
                if ($dest !== '') {
                    $destinations[$dest] = ($destinations[$dest] ?? 0) + 1;
                }
            }
        }
        $domains = isset($last['domains']) && is_array($last['domains']) ? $last['domains'] : [];
        foreach ($domains as $host => $detail) {
            if (!is_string($detail) || trim($detail) === '') {
                continue;
            }
            $destinations[$detail] = ($destinations[$detail] ?? 0) + 1;
        }
        arsort($destinations);

        if (empty($events) && $destinations === []) {
            echo '<div class="wd-empty">' . self::icon('check-big')
                . '<strong>Nothing recorded</strong><p>Detections and blocks will appear here.</p></div>';
            return;
        }

        echo '<div class="wd-table-controls">'
            . '<label class="wd-search">' . self::icon('search')
            . '<input type="search" placeholder="Filter events…" data-wd-search="#wd-events-table" aria-label="Filter security events"></label>'
            . '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">'
            . '<input type="hidden" name="action" value="watchdog_export">'
            . wp_nonce_field('watchdog_export_action', 'watchdog_export_nonce', true, false)
            . '<button type="submit" class="button button-secondary">' . self::icon('download') . ' Export CSV</button>'
            . '</form></div>';

        echo '<div class="wd-tabs wd-tabs-events" data-wd-tabgroup="events" data-wd-table="#wd-events-table" data-wd-default="critical">'
            . '<button type="button" class="wd-tab" data-wd-tab="critical">Critical</button>'
            . '<button type="button" class="wd-tab" data-wd-tab="warning">Warnings</button>'
            . '<button type="button" class="wd-tab" data-wd-tab="info">Informational</button>'
            . '<button type="button" class="wd-tab" data-wd-tab="notes">Notes</button>'
            . '<button type="button" class="wd-tab" data-wd-tab="redirect">Redirect' . (count($destinations) > 0 ? ' (' . (int) count($destinations) . ')' : '') . '</button>'
            . '</div>';

        echo '<div class="wd-table-wrap">'
            . '<table class="wd-table" id="wd-events-table"><thead><tr>'
            . '<th class="wd-sort">Time</th><th>Type</th><th>Source</th><th class="wd-col-details">Details</th>'
            . '</tr></thead><tbody>';
        $sevTab = ['critical' => 'critical', 'warning' => 'warning', 'info' => 'info', 'safe' => 'notes'];
        $noiseSignatures = [
            'JS: window/document.location',
            'JS: window.open()',
            'JS: history.pushState()',
            'JS: history.replaceState()',
            'JS: mobile detection (userAgent)',
            'JS: mobile keywords',
            'JS: String.fromCharCode()',
            'JS: new Function()',
        ];
        foreach ($events as $event) {
            $sevKey = (string) ($event['severity'] ?? 'safe');
            $tabKey = isset($sevTab[$sevKey]) ? $sevTab[$sevKey] : 'notes';
            if (($event['type'] ?? '') === 'scan_finding') {
                $det = json_decode((string) ($event['details'] ?? ''), true);
                $sigs = isset($det['signatures']) && is_array($det['signatures']) ? $det['signatures'] : [];
                if ($sigs !== [] && array_reduce($sigs, static function (bool $carry, string $s) use ($noiseSignatures): bool {
                    return $carry && in_array($s, $noiseSignatures, true);
                }, true)) {
                    continue;
                }
            }
            echo '<tr data-sev="' . esc_attr((string) $tabKey) . '">'
                . '<td style="white-space:nowrap;">' . esc_html(wp_date('Y-m-d H:i', strtotime((string) $event['event_time']))) . '</td>'
                . '<td><code>' . esc_html((string) $event['type']) . '</code></td>'
                . '<td><code>' . esc_html((string) $event['source']) . '</code></td>'
                . '<td class="wd-col-details">' . self::renderDetailsCell($event['details'], (string) $event['source']) . '</td>'
                . '</tr>';
        }
        echo '</tbody></table><div class="wd-table-empty" style="display:none;">No events match your filter.</div></div>';

        echo '<div class="wd-panel" data-wd-panel-group="events" data-wd-panel="redirect" style="display:none;">';
        if ($destinations === []) {
            echo '<div class="wd-empty">' . self::icon('check-big')
                . '<strong>No redirects found</strong><p>External redirect destinations seen in scanned code appear here.</p></div>';
        } else {
            echo '<div class="wd-finding wd-fac-warning">'
                . '<div class="wd-finding-head">'
                . '<span class="wd-finding-ic">' . self::icon('ban') . '</span>'
                . '<span class="wd-finding-title">Redirect destinations</span>'
                . '<span class="wd-finding-count">' . (int) count($destinations) . '</span>'
                . '</div>'
                . '<div class="wd-finding-body wd-open"><ul class="wd-file-list" data-wd-paginate="20">';
            foreach ($destinations as $dest => $count) {
                $host = (string) wp_parse_url($dest, PHP_URL_HOST);
                $label = $host !== '' ? $host : $dest;
                echo '<li><span style="color:var(--wd-text-mid);">' . esc_html($label) . '</span>'
                    . '<span class="wd-file-meta">' . (int) $count . '×</span>'
                    . '<div class="wd-file-note">' . esc_html($dest) . '</div></li>';
            }
            echo '</ul></div></div>';
        }
        echo '</div>';
    }

    /**
     * Pretty-print the details JSON column inside a details element.
     * Scan findings (details carry 'lines') get a Wordfence-style code
     * viewer: file name, signatures and the exact flagged lines.
     */
    private static function renderDetailsCell(?string $json, string $source = ''): string {
        if (!$json) {
            return '—';
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            return esc_html($json);
        }
        $lines = isset($data['lines']) && is_array($data['lines']) ? $data['lines'] : [];
        if ($lines !== []) {
            $signatures = isset($data['signatures']) && is_array($data['signatures']) ? $data['signatures'] : [];
            $label = (string) ($data['label'] ?? '');
            $out = '';
            if ($label !== '') {
                $out .= '<div class="wd-code-title">' . esc_html($label) . '</div>';
            }
            if ($signatures !== []) {
                $out .= '<div class="wd-file-sigs">';
                foreach ($signatures as $sig) {
                    $out .= '<span class="wd-badge">' . esc_html($sig) . '</span>';
                }
                $out .= '</div>';
            }
            $out .= '<pre class="wd-code-pre">';
            foreach ($lines as $hit) {
                $out .= '<span class="wd-code-line"><span class="wd-code-no">' . esc_html((string) ($hit['line'] ?? '')) . '</span>'
                    . '<span class="wd-code-text">' . esc_html((string) ($hit['code'] ?? '')) . '</span></span>' . "\n";
            }
            $out .= '</pre>';
            return $out;
        }
        $out = '<pre class="wd-log-pre">';
        $out .= esc_html(wp_json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        $out .= '</pre>';
        return $out;
    }

    /* ------------------------------------------------------------------
     * Settings
     * ---------------------------------------------------------------- */

    private static function renderSettings(): void {
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">'
            . '<input type="hidden" name="action" value="watchdog_settings">'
            . wp_nonce_field('watchdog_settings_action', 'watchdog_settings_nonce', true, false);

        $settings = [
            'protection' => [
                'name'    => 'Protection',
                'blurb'    => 'How Watchdog responds to detections.',
                'fields'   => [
                    ['watchdog_monitor_only', 'Monitor-only mode', 'Log only — never block or quarantine. Recommended when starting out.', 0],
                    ['watchdog_auto_quarantine', 'Auto-quarantine critical findings', 'Move critical files to quarantine automatically (core is never touched).', 0],
                ],
            ],
            'notifications' => [
                'name'    => 'Notifications',
                'blurb'    => 'Alerts for critical events.',
                'fields'   => [
                    ['watchdog_email_alerts', 'Email alerts', 'Send alerts for critical and warning events.', 1],
                ],
            ],
        ];

        foreach ($settings as $group) {
            echo '<div class="wd-card">'
                . '<div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('sliders') . ' ' . esc_html($group['name']) . '</h3></div>'
                . '<p style="color:var(--wd-text-mid);font-size:12.5px;margin:0 0 14px;">' . esc_html($group['blurb']) . '</p>';
            foreach ($group['fields'] as [$option, $label, $help, $default]) {
                $on = (int) get_option($option, $default) === 1;
                echo '<div class="wd-field">'
                    . '<label>'
                    . '<span class="wd-toggle"><input type="checkbox" name="' . esc_attr($option) . '" value="1"' . checked($on, true, false) . '>'
                    . '<span class="wd-track"></span></span>'
                    . '<span>' . esc_html($label) . '</span>'
                    . '</label>'
                    . '<div class="wd-field-help">' . esc_html($help) . '</div>'
                    . '</div>';
            }
            echo '</div>';
        }

        // Scan checks — the Wordfence "High Sensitivity" option set.
        echo '<div class="wd-card"><div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('shield') . ' Scan checks (Wordfence High Sensitivity set)</h3></div>'
            . '<p style="color:var(--wd-text-mid);font-size:12.5px;margin:0 0 14px;">All checks are enabled by default.</p>';
        foreach (SiteChecks::OPTIONS as $option => $label) {
            $on = (int) get_option($option, 1) === 1;
            echo '<div class="wd-field">'
                . '<label>'
                . '<span class="wd-toggle"><input type="checkbox" name="' . esc_attr($option) . '" value="1"' . checked($on, true, false) . '>'
                . '<span class="wd-track"></span></span>'
                . '<span>' . esc_html($label) . '</span>'
                . '</label>'
                . '</div>';
        }
        echo '</div>';

        // Whitelists & scanning
        echo '<div class="wd-card"><div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('sliders') . ' Redirect allow-lists &amp; scan exclusions</h3></div>'
            . '<p style="color:var(--wd-text-mid);font-size:12.5px;margin:0 0 4px;">One entry per line. Regex lines are validated on save.</p>';

        $areas = [
            'watchdog_whitelist_domains'  => ['Whitelisted destination hosts', 'One host per line. Redirects to these hosts are allowed.'],
            'watchdog_denied_domains'     => ['Denied destination hosts', 'One host per line. Redirects to these hosts (or subdomains) are always blocked. Empty = defaults: google.com, t.co, ushort.company.'],
            'watchdog_whitelist_patterns' => ['Whitelisted redirect patterns', 'One regex per line, e.g. /checkout/ or ^https://pay\\.'],
            'watchdog_allow_subdomains'   => ['Allow same-site subdomains', 'Allow cdn., shop., staging. subdomains of this site.'],
            'watchdog_whitelist_plugins'  => ['Legacy whitelisted plugins', 'Plugin folder names, one per line.'],
            'watchdog_whitelist_themes'   => ['Legacy whitelisted themes', 'Theme folder names, one per line.'],
            'watchdog_exclusions'         => ['Scan exclusions', 'Paths to skip, one per line.'],
        ];
        $isBool = ['watchdog_allow_subdomains' => true];

        foreach ($areas as $option => $def) {
            echo '<div class="wd-field" style="margin-top:16px;">'
                . '<span class="wd-field-label">' . esc_html($def[0]) . '</span>';
            if (isset($isBool[$option])) {
                $on = (int) get_option($option, 1) === 1;
                echo '<label style="display:flex;align-items:center;gap:9px;margin-top:8px;">'
                    . '<span class="wd-toggle"><input type="checkbox" name="' . esc_attr($option) . '" value="1"' . checked($on, true, false) . '><span class="wd-track"></span></span>'
                    . '<span>Enabled</span></label>';
            } else {
                echo '<textarea name="' . esc_attr($option) . '" rows="4" class="wd-textarea" aria-label="' . esc_attr($def[0]) . '">'
                    . esc_textarea(implode("\n", RedirectEngine::lines($option)))
                    . '</textarea>';
            }
            echo '<div class="wd-field-help">' . esc_html($def[1]) . '</div></div>';
        }
        echo '</div>';

        // Debug/danger
        echo '<div class="wd-card" style="border-left:4px solid var(--wd-danger);">'
            . '<div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('alert') . ' Dangerous actions</h3></div>'
            . '<p style="color:var(--wd-text-mid);font-size:12.5px;margin:0 0 14px;">Irreversible — use with care.</p>'
            . '<div class="wd-field"><div class="wd-danger-zone">'
            . '<strong>Reset the file baseline</strong> after a clean install.'
            . self::postForm('watchdog_restore_baseline', 'Restore Baseline', 'button-link-delete', 'watchdog_restore_baseline_action', 'watchdog_restore_baseline_nonce')
            . '</div></div>'
            . '</div>';

        self::renderTrustTable();

        echo '<div class="wd-card"><div class="wd-actions" style="justify-content:flex-end;">'
            . get_submit_button('Save Settings', 'primary', '', false)
            . '</div></div>'
            . '</form>';
    }

    /**
     * Per-installed-plugin/theme trust level selectors.
     */
    private static function renderTrustTable(): void {
        $labels = [
            Trust::OFFICIAL => 'Official (WP.org)',
            Trust::TRUSTED  => 'Trusted (commercial)',
            Trust::UNKNOWN  => 'Unknown — monitor closely',
        ];

        echo '<div class="wd-card">'
            . '<div class="wd-card-head"><h3 class="wd-card-title">' . self::icon('key') . ' Trust model</h3></div>'
            . '<p style="color:var(--wd-text-mid);font-size:12.5px;margin:0 0 10px;">Official WP.org packages are trusted by default. Mark trusted commercial plugins so their redirects are never blocked.</p>'
            . '<details style="margin-bottom:12px;"><summary>How trust works</summary><p class="wd-field-help">Every package is Official (from WordPress.org), Trusted (you certify it), or Unknown. Trust only affects redirect analysis.</p></details>';

        echo '<div class="wd-table-wrap"><table class="wd-table" id="wd-trust-plugins">'
            . '<thead><tr><th style="width:45%;">Plugin</th><th style="width:35%;">Trust level</th><th>Last verification</th></tr></thead><tbody>';
        foreach (array_keys(get_plugins()) as $pluginFile) {
            $slug = dirname($pluginFile);
            $data = get_plugin_data(WP_PLUGIN_DIR . '/' . $pluginFile, false, false);
            $level = Trust::level($slug, 'plugin');
            $verify = Checksums::packageResult('plugin', $slug);
            $status = isset($verify['status']) ? (string) $verify['status'] : 'not verified';
            echo '<tr><td><strong style="color:var(--wd-head);">' . esc_html($data['Name'] !== '' ? $data['Name'] : $slug) . '</strong><br><code style="font-size:11px;">' . esc_html($slug) . '</code></td>'
                . '<td><select name="watchdog_trust_plugins[' . esc_attr($slug) . ']" class="wd-select">'
                . self::trustOptions($labels, $level)
                . '</select></td>'
                . '<td><span style="color:var(--wd-text-mute);">' . esc_html($status) . '</span></td></tr>';
        }
        echo '</tbody></table></div>';

        echo '<div class="wd-table-wrap" style="margin-top:14px;"><table class="wd-table" id="wdTrustThemes">'
            . '<thead><tr><th style="width:45%;">Theme</th><th style="width:35%;">Trust level</th><th>Last verification</th></tr></thead><tbody>';
        foreach (wp_get_themes() as $slug => $theme) {
            $level = Trust::level((string) $slug, 'theme');
            $verify = Checksums::packageResult('theme', (string) $slug);
            $status = isset($verify['status']) ? (string) $verify['status'] : 'not verified';
            echo '<tr><td><strong style="color:var(--wd-head);">' . esc_html((string) $theme->get('Name')) . '</strong><br><code style="font-size:11px;">' . esc_html((string) $slug) . '</code></td>'
                . '<td><select name="watchdog_trust_themes[' . esc_attr((string) $slug) . ']" class="wd-select">'
                . self::trustOptions($labels, $level)
                . '</select></td>'
                . '<td><span style="color:var(--wd-text-mute);">' . esc_html($status) . '</span></td></tr>';
        }
        echo '</tbody></table></div>';
        echo '</div>';
    }

    private static function trustOptions(array $labels, string $current): string {
        $html = '';
        foreach ($labels as $value => $label) {
            $html .= '<option value="' . esc_attr($value) . '" ' . selected($current, $value, false) . '>' . esc_html($label) . '</option>';
        }
        return $html;
    }

    /* ------------------------------------------------------------------
     * Admin-post handlers (all nonce + capability protected)
     * ---------------------------------------------------------------- */

    public static function handleScan(): void {
        self::requirePermission('watchdog_scan_action', 'watchdog_scan_nonce');

        $scope = isset($_POST['watchdog_scope']) && is_array($_POST['watchdog_scope'])
            ? array_map('sanitize_key', wp_unslash($_POST['watchdog_scope']))
            : [];
        if ($scope === []) {
            Logger::notice('Select at least one scan scope.');
            self::redirect();
            return;
        }

        // The scan starts in the background: the first segment is picked
        // up within seconds by the progress poller (or the cron fast
        // continue). Never block this request for a whole segment — a
        // refresh mid-segment would leave the run stalled.
        if (Scanner::progress() !== null) {
            Logger::notice('A scan is already running — stop it to change scope.');
            self::redirect();
            return;
        }
        Scanner::ensureRun($scope);
        Cron::scheduleFastContinue();
        Logger::notice('Scan started — runs in the background.');
        self::redirect();
    }

    public static function handleStopScan(): void {
        self::requirePermission('watchdog_stop_scan_action', 'watchdog_stop_scan_nonce');
        Scanner::cancelScan();
        Logger::notice('Scan stopped.');
        self::redirect();
    }

    public static function handleRestoreBaseline(): void {
        self::requirePermission('watchdog_restore_baseline_action', 'watchdog_restore_baseline_nonce');
        $count = Scanner::saveBaseline();
        Logger::notice(sprintf('Baseline restored (%d files).', $count));
        self::redirect();
    }

    public static function handleVerifyCore(): void {
        self::requirePermission('watchdog_verify_core_action', 'watchdog_verify_core_nonce');
        update_option('watchdog_pending_core_verify', time(), false);
        Cron::ensure();
        Cron::scheduleFastContinue();
        Logger::notice('Core verification queued — starts shortly.');
        self::redirect();
    }

    public static function handleVerifyPackages(): void {
        self::requirePermission('watchdog_verify_packages_action', 'watchdog_verify_packages_nonce');
        $count = LiveProtection::queueAllVerifications();
        Cron::ensure();
        Cron::scheduleFastContinue();
        Logger::notice(sprintf('Verification queued for %d package(s) — starts shortly.', $count));
        self::redirect();
    }

    public static function handleExportQuarantine(): void {
        self::requirePermission('watchdog_export_quarantine_action', 'watchdog_export_quarantine_nonce');
        Quarantine::exportZip();
    }

    public static function handleQuarantine(): void {
        self::requirePermission('watchdog_quarantine_action', 'watchdog_quarantine_nonce');

        $path = isset($_POST['file']) ? sanitize_text_field(wp_unslash($_POST['file'])) : '';
        $quarantined = Quarantine::quarantineFile($path);
        if ($quarantined !== null) {
            Logger::log('quarantined', 'critical', $path, ['quarantine_file' => $quarantined['name']]);
            Logger::notice('Quarantined: ' . basename($path));
        } else {
            Logger::notice('Quarantine failed for: ' . basename($path));
        }
        self::redirect();
    }

    public static function handleRestoreQuarantine(): void {
        self::requirePermission('watchdog_restore_quarantine_action', 'watchdog_restore_quarantine_nonce');

        $name = isset($_POST['file']) ? sanitize_file_name(wp_unslash($_POST['file'])) : '';
        if (Quarantine::restore($name)) {
            Logger::notice('Restored: ' . $name);
        } else {
            Logger::notice('Restore failed: ' . $name);
        }
        self::redirect();
    }

    public static function handleDisablePlugin(): void {
        self::requirePermission('watchdog_disable_plugin_action', 'watchdog_disable_plugin_nonce');

        $plugin = isset($_POST['plugin']) ? sanitize_text_field(wp_unslash($_POST['plugin'])) : '';
        if (Quarantine::disablePlugin($plugin)) {
            Logger::log('plugin_disabled', 'critical', $plugin);
            Logger::notice('Plugin deactivated: ' . $plugin);
        } else {
            Logger::notice('Could not deactivate: ' . $plugin);
        }
        self::redirect();
    }

    public static function handleRenamePlugin(): void {
        self::requirePermission('watchdog_rename_plugin_action', 'watchdog_rename_plugin_nonce');

        $plugin = isset($_POST['plugin']) ? sanitize_text_field(wp_unslash($_POST['plugin'])) : '';
        if (Quarantine::renamePluginFolder($plugin)) {
            Logger::notice('Plugin folder renamed to .disabled');
        } else {
            Logger::notice('Could not rename plugin folder: ' . $plugin);
        }
        self::redirect();
    }

    public static function handleSettings(): void {
        self::requirePermission('watchdog_settings_action', 'watchdog_settings_nonce');

        update_option('watchdog_auto_quarantine', isset($_POST['watchdog_auto_quarantine']) ? 1 : 0);
        update_option('watchdog_email_alerts', isset($_POST['watchdog_email_alerts']) ? 1 : 0);
        update_option('watchdog_monitor_only', isset($_POST['watchdog_monitor_only']) ? 1 : 0);
        update_option('watchdog_allow_subdomains', isset($_POST['watchdog_allow_subdomains']) ? 1 : 0);

        // Scan checks (Wordfence High Sensitivity set) — all default ON.
        foreach (array_keys(SiteChecks::OPTIONS) as $option) {
            update_option($option, isset($_POST[$option]) ? 1 : 0);
        }

        foreach (['watchdog_whitelist_domains', 'watchdog_denied_domains', 'watchdog_whitelist_plugins', 'watchdog_whitelist_themes', 'watchdog_exclusions'] as $option) {
            $raw = isset($_POST[$option]) ? sanitize_textarea_field(wp_unslash($_POST[$option])) : '';
            update_option($option, $raw, false);
        }

        // Regex whitelist lines are validated before saving — an invalid
        // pattern would silently disable that line (preg_match returns
        // false) and leak user attention away from real findings.
        $patternLines = [];
        $skipped = 0;
        $rawPatterns = isset($_POST['watchdog_whitelist_patterns']) ? sanitize_textarea_field(wp_unslash($_POST['watchdog_whitelist_patterns'])) : '';
        foreach (preg_split('/\R/', $rawPatterns) as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            if (@preg_match('~' . $line . '~i', 'probe') === false) {
                $skipped++;
                continue;
            }
            $patternLines[] = $line;
        }
        update_option('watchdog_whitelist_patterns', implode("\n", $patternLines), false);

        Trust::saveFromRequest(
            isset($_POST['watchdog_trust_plugins']) && is_array($_POST['watchdog_trust_plugins']) ? wp_unslash($_POST['watchdog_trust_plugins']) : [],
            isset($_POST['watchdog_trust_themes']) && is_array($_POST['watchdog_trust_themes']) ? wp_unslash($_POST['watchdog_trust_themes']) : []
        );

        $notice = 'Settings saved.';
        if ($skipped > 0) {
            $notice .= sprintf(' %d invalid regex line(s) skipped.', $skipped);
        }
        Logger::notice($notice);
        self::redirect();
    }

    /**
     * Download all events as CSV (nonce + capability protected).
     * Cell values starting with = + - @ are escaped to prevent spreadsheet
     * formula injection.
     */
    public static function handleExport(): void {
        self::requirePermission('watchdog_export_action', 'watchdog_export_nonce');

        $rows = Logger::export(5000);
        $filename = 'watchdog-events-' . gmdate('Ymd-His') . '.csv';

        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        echo "\xEF\xBB\xBF"; // BOM for Excel

        $out = fopen('php://output', 'w');
        fputcsv($out, ['time', 'type', 'severity', 'source', 'ip', 'user', 'details']);
        foreach ($rows as $row) {
            fputcsv($out, [
                self::csvSafe(isset($row['event_time']) ? $row['event_time'] : ''),
                self::csvSafe(isset($row['type']) ? $row['type'] : ''),
                self::csvSafe(isset($row['severity']) ? $row['severity'] : ''),
                self::csvSafe(isset($row['source']) ? $row['source'] : ''),
                self::csvSafe(isset($row['ip']) ? $row['ip'] : ''),
                self::csvSafe(isset($row['username']) ? $row['username'] : ''),
                self::csvSafe(isset($row['details']) ? $row['details'] : ''),
            ]);
        }
        fclose($out);
        exit;
    }

    /* ------------------------------------------------------------------
     * Shared helpers
     * ---------------------------------------------------------------- */

    /**
     * Neutralize spreadsheet formula injection in exported cells.
     */
    private static function csvSafe(string $value): string {
        if ($value !== '' && strpos('=+-@', $value[0]) !== false) {
            return "'" . $value;
        }
        return $value;
    }

    private static function postForm(string $action, string $label, string $class, string $nonceAction, string $nonceField): string {
        return '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline-block;">'
            . '<input type="hidden" name="action" value="' . esc_attr($action) . '">'
            . wp_nonce_field($nonceAction, $nonceField, true, false)
            . get_submit_button($label, $class, '', false)
            . '</form>';
    }

    private static function requirePermission(string $action, string $nonceField): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized.', 'watchdog'), 403);
        }
        check_admin_referer($action, $nonceField);
    }

    /**
     * Redirect back to the dashboard, keeping the active tab (posted as a
     * hidden field by admin-tabs.js) so the user lands where they were.
     */
    private static function redirect(): void {
        $tab = isset($_POST['watchdog_tab']) ? self::sanitizeTabKey((string) wp_unslash($_POST['watchdog_tab'])) : '';
        wp_safe_redirect(admin_url('admin.php?page=' . self::PAGE . ($tab !== '' ? '#' . $tab : '')));
        exit;
    }

    /**
     * Restrict the tab fragment to the known tab ids.
     */
    private static function sanitizeTabKey(string $tab): string {
        $allowed = [
            'watchdog-tab-overview',
            'watchdog-tab-scan',
            'watchdog-tab-verification',
            'watchdog-tab-quarantine',
            'watchdog-tab-timeline',
            'watchdog-tab-settings',
        ];
        return in_array($tab, $allowed, true) ? $tab : '';
    }
}