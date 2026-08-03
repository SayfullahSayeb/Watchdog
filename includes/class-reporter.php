<?php
/**
 * Reporter: sends email alerts to the admin with rate limiting and a
 * structured HTML report of scan results.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * Reporter
 */
final class Reporter {

    private const COOLDOWN_TRANSIENT = 'watchdog_alert_cooldown';
    private const COOLDOWN_SECONDS = 900; // 15 minutes

    /**
     * True when email alerts are enabled.
     */
    public static function enabled(): bool {
        return (bool) get_option('watchdog_email_alerts', 1);
    }

    /**
     * Send a scan report if there is anything critical or warning.
     */
    public static function reportScan(array $results): void {
        if (!self::enabled()) {
            return;
        }
        $critical = count((array) ($results['malware'] ?? []));
        $warning = count((array) ($results['suspicious'] ?? []));
        if ($critical === 0 && $warning === 0) {
            return;
        }
        if (!self::cooldownPassed()) {
            return;
        }

        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        $subject = sprintf(
            'Watchdog ALERT: %d critical, %d suspicious finding(s) on %s',
            $critical,
            $warning,
            $host
        );

        $body = '<h2>Watchdog scan report</h2>';
        $body .= '<p>Scanned ' . (int) ($results['total'] ?? 0) . ' files at ' . esc_html(wp_date('Y-m-d H:i:s', (int) ($results['time'] ?? 0))) . '.</p>';

        $expected = (int) ($results['expected'] ?? 0);
        if ($expected > 0) {
            $body .= '<p><strong>' . $expected . '</strong> expected redirect(s) were allowed by the behavior engine.</p>';
        }

        $sections = [
            'malware'    => ['MALWARE (critical)', '#dc3232'],
            'suspicious' => ['Suspicious code', '#f56e28'],
            'info'       => ['Informational matches', '#00a0d2'],
            'domains'    => ['External domains observed', '#dc3232'],
            'changed'    => ['Changed files (likely legit updates)', '#666'],
            'new'        => ['New files', '#666'],
            'deleted'    => ['Deleted files', '#666'],
        ];

        // Site checks (Wordfence High Sensitivity set) with severity.
        $checks = isset($results['checks']) && is_array($results['checks']) ? $results['checks'] : [];
        if ($checks !== []) {
            $body .= '<h3 style="color:#00a0d2">Site checks (High Sensitivity — ' . count($checks) . ')</h3><ul>';
            foreach (array_slice($checks, 0, 100) as $check) {
                $sev = isset($check['sev']) ? (string) $check['sev'] : 'info';
                $color = $sev === 'critical' ? '#dc3232' : ($sev === 'warning' ? '#f56e28' : '#666');
                $body .= '<li><span style="color:' . $color . ';font-weight:600;">[' . esc_html(strtoupper($sev)) . ']</span> '
                    . esc_html((string) ($check['label'] ?? ''))
                    . (isset($check['details']) && $check['details'] !== '' ? ' — ' . esc_html((string) $check['details']) : '')
                    . '</li>';
            }
            $body .= '</ul>';
        }

        foreach ($sections as $key => $def) {
            $items = isset($results[$key]) && is_array($results[$key]) ? $results[$key] : [];
            if (empty($items)) {
                continue;
            }
            $body .= '<h3 style="color:' . $def[1] . '">' . $def[0] . ' (' . count($items) . ')</h3><ul>';
            $i = 0;
            foreach ($items as $path => $detail) {
                if ($i++ >= 100) {
                    $body .= '<li>… and ' . (count($items) - $i + 1) . ' more</li>';
                    break;
                }
                $extra = '';
                if (is_array($detail) && !empty($detail['redirects'])) {
                    $first = $detail['redirects'][0];
                    $extra = ' — ' . esc_html($first['call'] . ' -> ' . ($first['dest'] ? $first['dest'] : $first['note']));
                } elseif (is_array($detail) && !empty($detail['signatures'])) {
                    $extra = ' — ' . esc_html(implode(', ', array_slice($detail['signatures'], 0, 3)));
                } elseif (is_array($detail) && !empty($detail['destination'])) {
                    $extra = ' — ' . esc_html($detail['destination']);
                }
                $body .= '<li>' . esc_html($path) . $extra . '</li>';
            }
            $body .= '</ul>';
        }

        $body .= '<p>Quarantine flagged files from the Watchdog dashboard. Check wp-config.php, .htaccess and .user.ini manually.</p>';

        self::send($subject, $body);
    }

    /**
     * Immediate alert for a single high-confidence event (e.g. blocked
     * redirect or blocked plugin activation).
     */
    public static function alert(string $subject, string $bodyHtml): void {
        if (!self::enabled() || !self::cooldownPassed()) {
            return;
        }
        self::send($subject, $bodyHtml);
    }

    /**
     * Structured incident report for one Execution Context finding
     * (confidence, risk, context, file, plugin/theme, line, destination,
     * trigger, reason, recommended action).
     */
    public static function incident(array $finding): void {
        if (!self::enabled() || !self::cooldownPassed()) {
            return;
        }
        $report = ExecutionContext::incidentReport($finding);
        $rows = [
            'Confidence'        => strtoupper((string) $report['confidence']),
            'Risk score'        => (string) $report['risk_score'],
            'Filename'          => (string) $report['filename'],
            'Plugin / theme'    => (string) $report['plugin_theme'],
            'Line'              => (string) $report['line'],
            'Destination'       => (string) $report['destination'],
            'Trigger'           => (string) $report['trigger'],
            'Reason'            => (string) $report['reason'],
            'Recommended action' => (string) $report['action'],
        ];
        $body = '<h2>Watchdog incident report</h2><table style="border-collapse:collapse;width:100%;">';
        foreach ($rows as $label => $value) {
            $body .= '<tr style="border-bottom:1px solid #eee;">'
                . '<td style="padding:6px 10px;font-weight:600;width:220px;">' . esc_html($label) . '</td>'
                . '<td style="padding:6px 10px;">' . esc_html($value) . '</td></tr>';
        }
        $body .= '</table>';
        if (!empty($report['execution_context']) && is_array($report['execution_context'])) {
            $body .= '<p><strong>Execution context</strong>: '
                . esc_html(wp_json_encode($report['execution_context'], JSON_UNESCAPED_SLASHES))
                . '</p>';
        }
        self::send(
            'Watchdog incident report: ' . strtoupper((string) $report['confidence'])
                . ' — ' . (string) $report['filename'] . ':' . (string) $report['line'],
            $body
        );
    }

    /**
     * Send a HTML email to the admin address.
     */
    private static function send(string $subject, string $bodyHtml): void {
        wp_mail(
            get_option('admin_email'),
            $subject,
            $bodyHtml,
            ['Content-Type: text/html; charset=UTF-8']
        );
    }

    /**
     * Rate limiting: at most one alert per cooldown window.
     */
    private static function cooldownPassed(): bool {
        $last = get_transient(self::COOLDOWN_TRANSIENT);
        if ($last !== false && time() - (int) $last < self::COOLDOWN_SECONDS) {
            return false;
        }
        set_transient(self::COOLDOWN_TRANSIENT, time(), self::COOLDOWN_SECONDS);
        return true;
    }
}
