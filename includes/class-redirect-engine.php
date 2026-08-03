<?php
/**
 * RedirectEngine: behavior-based redirect classification.
 *
 * Every redirect is classified by behavior, context and the source's trust
 * level into four tiers with a confidence rating:
 *
 *   SAFE        - relative URLs, internal paths, no host involved.
 *   EXPECTED    - same-host, subdomains, WordPress system paths,
 *                 whitelisted domains/plugins/themes/patterns.
 *   SUSPICIOUS  - flagged, never blocked (LOW confidence).
 *   MALICIOUS   - external host with aggravating factors (HIGH) or from
 *                 an unlisted source (MEDIUM), or a destination host on
 *                 the denied list (google.com, t.co, ushort.company by
 *                 default).
 *
 * Confidence drives runtime actions:
 *   HIGH   -> block the redirect, quarantine the source, notify.
 *   MEDIUM -> log, notify, allow.
 *   LOW    -> log only.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * RedirectEngine
 */
final class RedirectEngine {

    public const SAFE = 'safe';
    public const EXPECTED = 'expected';
    public const SUSPICIOUS = 'suspicious';
    public const MALICIOUS = 'malicious';

    public const CONFIDENCE_HIGH = 'high';
    public const CONFIDENCE_MEDIUM = 'medium';
    public const CONFIDENCE_LOW = 'low';

    /** Option holding the comma/newline separated deny list. */
    public const DENY_OPTION = 'watchdog_denied_domains';

    /** Default deny list: destination hosts that are always blocked. */
    public const DEFAULT_DENIED = ['google.com', 't.co', 'ushort.company'];

    /**
     * Classify a redirect found inside a scanned file.
     *
     * @param array  $finding    From RedirectAnalyzer: dest, method, arg,
     *                           obfuscated, mobile, line, function.
     * @param string $sourceFile Absolute path of the file containing it.
     * @param array  $signatures Heuristics signature names for the file.
     *
     * @return array{class: string, reason: string, severity: string, confidence: string}
     */
    public static function classify(array $finding, string $sourceFile, array $signatures = []): array {
        $dest = isset($finding['dest']) && $finding['dest'] !== '' ? (string) $finding['dest'] : null;
        $method = isset($finding['method']) ? (string) $finding['method'] : 'unknown';
        $arg = isset($finding['arg']) ? (string) $finding['arg'] : '';
        $obfuscated = !empty($finding['obfuscated']) || self::decodeHint($arg);
        $mobile = !empty($finding['mobile']);
        $signature = self::hasCriticalSignature($signatures);
        $origin = self::originOf($sourceFile);

        // --- No resolvable destination: judge by source and hints ---
        if ($dest === null) {
            if (!empty($finding['severity']) && $finding['severity'] === 'safe') {
                return self::result(self::EXPECTED, 'WordPress function destination', self::CONFIDENCE_LOW);
            }
            if ($obfuscated) {
                return self::result(self::MALICIOUS, 'encoded or opaque destination (decoder hints present)', self::CONFIDENCE_HIGH);
            }
            if (self::sourceTrusted($origin)) {
                return self::result(self::EXPECTED, 'dynamic redirect from trusted source', self::CONFIDENCE_LOW);
            }
            if ($origin['core']) {
                return self::result(self::EXPECTED, 'core-managed dynamic redirect', self::CONFIDENCE_LOW);
            }
            return self::result(self::SUSPICIOUS, 'dynamic or unknown destination could not be resolved', self::CONFIDENCE_LOW);
        }

        // --- Deny list: google.com / t.co (or any subdomain) are always
        // blocked, regardless of source trust, obfuscation or whitelists.
        $denied = self::deniedHost($dest);
        if ($denied !== '') {
            return self::result(self::MALICIOUS, 'destination host is denied: ' . $denied, self::CONFIDENCE_HIGH);
        }

        // --- Non-web schemes (javascript:, data:, vbscript:, file:) are
        // never SAFE — they are not relative URLs and have no host. ---
        if (self::hasNonWebScheme($dest)) {
            if ($obfuscated || $signature) {
                return self::result(self::MALICIOUS, 'non-web scheme destination combined with ' . ($obfuscated ? 'obfuscation' : 'malware signature'), self::CONFIDENCE_HIGH);
            }
            if (self::isPayloadScheme($dest)) {
                return self::sourceTrusted($origin) || $origin['core']
                    ? self::result(self::MALICIOUS, 'javascript:/data: destination', self::CONFIDENCE_MEDIUM)
                    : self::result(self::MALICIOUS, 'javascript:/data: destination from unlisted source', self::CONFIDENCE_HIGH);
            }
            return self::result(self::SUSPICIOUS, 'non-web destination scheme', self::CONFIDENCE_LOW);
        }

        // --- Allowlist-first rules ---
        if (self::isRelative($dest)) {
            return self::result(self::SAFE, 'relative URL (no host)', self::CONFIDENCE_LOW);
        }
        if (self::isSystemPath($dest)) {
            return self::result(self::EXPECTED, 'WordPress system path: ' . self::systemPath($dest), self::CONFIDENCE_LOW);
        }
        if (self::isSameHost($dest)) {
            return self::result(self::EXPECTED, 'same-host redirect (including subdomains)', self::CONFIDENCE_LOW);
        }
        if (self::isWhitelistedDomain($dest)) {
            return self::result(self::EXPECTED, 'destination host is whitelisted', self::CONFIDENCE_LOW);
        }
        if (self::matchesWhitelistPattern($dest)) {
            return self::result(self::EXPECTED, 'matches a whitelisted redirect pattern', self::CONFIDENCE_LOW);
        }
        if (self::isWordPressOrgHost($dest)) {
            return self::result(self::EXPECTED, 'WordPress.org destination', self::CONFIDENCE_LOW);
        }

        // --- External host from here on ---
        // Aggravating factors escalate regardless of trust, but mobile
        // gating alone only escalates from non-trusted sources (many
        // legitimate plugins detect mobile devices).
        if ($obfuscated || $signature) {
            return self::result(
                self::MALICIOUS,
                'external redirect combined with ' . ($obfuscated ? 'obfuscated/encoded code' : '')
                . ($signature ? (($obfuscated ? ', ' : '') . 'malware signature') : ''),
                self::CONFIDENCE_HIGH
            );
        }
        if ($mobile) {
            if (self::sourceTrusted($origin)) {
                return self::result(self::SUSPICIOUS, 'mobile-gated redirect from trusted source', self::CONFIDENCE_LOW);
            }
            return self::result(self::MALICIOUS, 'external redirect combined with mobile gating', self::CONFIDENCE_HIGH);
        }
        if (self::sourceTrusted($origin)) {
            return self::result(self::EXPECTED, 'redirect from trusted source', self::CONFIDENCE_LOW);
        }
        if ($origin['core']) {
            return self::result(self::SUSPICIOUS, 'external redirect from WordPress core file', self::CONFIDENCE_LOW);
        }
        if ($origin['uploads']) {
            return self::result(self::SUSPICIOUS, 'external redirect from uploads', self::CONFIDENCE_LOW);
        }
        if ($origin['plugin'] !== '' || $origin['theme'] !== '') {
            if (stripos($method, 'window.open') !== false) {
                return self::result(
                    self::SUSPICIOUS,
                    'popup to external host from unlisted source (' . ($origin['plugin'] !== '' ? 'plugin: ' . $origin['plugin'] : 'theme: ' . $origin['theme']) . ')',
                    self::CONFIDENCE_LOW
                );
            }
            if (Trust::originUnknown($origin)) {
                return self::result(
                    self::MALICIOUS,
                    'external redirect from unknown ' . ($origin['plugin'] !== '' ? 'plugin: ' . $origin['plugin'] : 'theme: ' . $origin['theme']),
                    self::CONFIDENCE_HIGH
                );
            }
            return self::result(
                self::MALICIOUS,
                'external redirect from untrusted source (' . ($origin['plugin'] !== '' ? 'plugin: ' . $origin['plugin'] : 'theme: ' . $origin['theme']) . ')',
                self::CONFIDENCE_MEDIUM
            );
        }
        return self::result(self::SUSPICIOUS, 'external redirect from unknown source', self::CONFIDENCE_LOW);
    }

    /**
     * Classify a server-side redirect (wp_redirect / wp_safe_redirect) at
     * runtime. Aggravating factors come from the source's trust level.
     *
     * @param string $location Destination being redirected to.
     * @param array  $origin   From originOf(): plugin, theme, core, uploads.
     */
    public static function classifyServerRedirect(string $location, array $origin): array {
        $dest = trim($location);
        if ($dest === '') {
            return self::result(self::SAFE, 'empty destination', self::CONFIDENCE_LOW);
        }
        $denied = self::deniedHost($dest);
        if ($denied !== '') {
            return self::result(self::MALICIOUS, 'destination host is denied: ' . $denied, self::CONFIDENCE_HIGH);
        }
        if (self::isRelative($dest)) {
            return self::result(self::SAFE, 'relative URL', self::CONFIDENCE_LOW);
        }
        if (self::hasNonWebScheme($dest)) {
            if (self::isPayloadScheme($dest)) {
                return self::result(self::MALICIOUS, 'javascript:/data: destination', self::CONFIDENCE_MEDIUM);
            }
            return self::result(self::SUSPICIOUS, 'non-web destination scheme', self::CONFIDENCE_LOW);
        }
        if (self::isSameHost($dest)) {
            return self::result(self::EXPECTED, 'same-host redirect', self::CONFIDENCE_LOW);
        }
        if (self::isWhitelistedDomain($dest)) {
            return self::result(self::EXPECTED, 'destination host is whitelisted', self::CONFIDENCE_LOW);
        }
        if (self::matchesWhitelistPattern($dest)) {
            return self::result(self::EXPECTED, 'matches a whitelisted redirect pattern', self::CONFIDENCE_LOW);
        }
        if (self::isWordPressOrgHost($dest)) {
            return self::result(self::EXPECTED, 'WordPress.org destination', self::CONFIDENCE_LOW);
        }
        if (self::sourceTrusted($origin)) {
            return self::result(self::EXPECTED, 'redirect from trusted source', self::CONFIDENCE_LOW);
        }
        if (!empty($origin['core'])) {
            return self::result(self::SUSPICIOUS, 'external redirect from core code', self::CONFIDENCE_LOW);
        }
        if (!empty($origin['plugin']) || !empty($origin['theme'])) {
            if (Trust::originUnknown($origin)) {
                return self::result(
                    self::MALICIOUS,
                    'external redirect from unknown ' . (!empty($origin['plugin']) ? 'plugin: ' . $origin['plugin'] : 'theme: ' . $origin['theme']),
                    self::CONFIDENCE_HIGH
                );
            }
            return self::result(
                self::MALICIOUS,
                'external redirect from untrusted source (' . (!empty($origin['plugin']) ? 'plugin: ' . $origin['plugin'] : 'theme: ' . $origin['theme']) . ')',
                self::CONFIDENCE_MEDIUM
            );
        }
        return self::result(self::MALICIOUS, 'external redirect from unknown source', self::CONFIDENCE_MEDIUM);
    }

    /**
     * Identify what owns a file: plugin slug, theme slug, core or uploads.
     */
    public static function originOf(string $path): array {
        $path = str_replace('\\', '/', (string) $path);
        $result = ['plugin' => '', 'theme' => '', 'core' => false, 'uploads' => false];

        $content = str_replace('\\', '/', WP_CONTENT_DIR);
        if ($content && strpos($path, $content) === 0) {
            $parts = explode('/', ltrim(substr($path, strlen($content)), '/'));
            if (isset($parts[0])) {
                if ($parts[0] === 'plugins' && isset($parts[1])) {
                    $result['plugin'] = $parts[1];
                } elseif ($parts[0] === 'themes' && isset($parts[1])) {
                    $result['theme'] = $parts[1];
                } elseif ($parts[0] === 'uploads') {
                    $result['uploads'] = true;
                }
            }
            return $result;
        }

        $abspath = str_replace('\\', '/', ABSPATH);
        if ($abspath && strpos($path, $abspath) === 0) {
            $rel = ltrim(substr($path, strlen($abspath)), '/');
            if ($rel === ''
                || strpos($rel, 'wp-admin/') === 0
                || strpos($rel, 'wp-includes/') === 0
                || preg_match('/^(?:index\.php|wp-config\.php|wp-config-sample\.php|wp-settings\.php|wp-load\.php|wp-login\.php|wp-cron\.php|wp-activate\.php|wp-comments-post\.php|wp-blog-header\.php|wp-mail\.php|wp-signup\.php|wp-trackback\.php|wp-links-opml\.php|xmlrpc\.php)$/i', $rel) === 1) {
                $result['core'] = true;
            }
        }
        return $result;
    }

    /**
     * True when monitor-only mode is enabled (never block, only log).
     */
    public static function monitorOnly(): bool {
        return (bool) get_option('watchdog_monitor_only', 0);
    }

    /**
     * Relative URL / anchor / query — no host involved. Any scheme'd URL
     * (http/https/ftp and non-web alike) has a host component and is
     * judged by the host analysis rules, never by this check.
     */
    public static function isRelative(string $dest): bool {
        if (preg_match('/^\/\//', $dest) === 1) {
            return false; // protocol-relative URL has a host
        }
        if (preg_match('/^[a-z][a-z0-9+.-]*:/i', $dest) === 1) {
            return false; // scheme'd URL — has a host
        }
        return strpos($dest, '://') === false || preg_match('/^[\/#?]/', $dest) === 1;
    }

    /**
     * Destination uses a scheme other than http/https/ftp.
     */
    public static function hasNonWebScheme(string $dest): bool {
        return preg_match('/^[a-z][a-z0-9+.-]*:/i', $dest) === 1
            && preg_match('#^(?:https?|ftp):#i', $dest) !== 1;
    }

    /**
     * Schemes that execute code or inline content when navigated to.
     */
    public static function isPayloadScheme(string $dest): bool {
        return preg_match('/^(?:javascript|data|vbscript|file|jar):/i', $dest) === 1;
    }

    /**
     * Well-known WordPress/system paths.
     */
    public static function isSystemPath(string $dest): bool {
        return self::systemPath($dest) !== '';
    }

    public static function systemPath(string $dest): string {
        $path = (string) wp_parse_url($dest, PHP_URL_PATH);
        if (preg_match(
            '/^(?:\/wp-admin(?:\/.*)?|\/wp-login\.php(?:\?.*)?|\/wp-json(?:\/.*)?|\/feed(?:\/.*)?|\/wp-cron\.php|\/xmlrpc\.php|\/wp-includes\/.*|\/wp-content\/.*|\/admin-post\.php|\/admin-ajax\.php|\/index\.php)/i',
            $path
        ) === 1) {
            return $path;
        }
        return '';
    }

    /**
     * Same host as the site (subdomains included when enabled).
     */
    public static function isSameHost(string $dest): bool {
        $host = strtolower((string) wp_parse_url($dest, PHP_URL_HOST));
        $site = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        if ($host === '' || $site === '') {
            return false;
        }
        if ($host === $site) {
            return true;
        }
        if (get_option('watchdog_allow_subdomains', 1) && substr($host, -strlen($site) - 1) === '.' . $site) {
            return true;
        }
        return false;
    }

    /**
     * Non-empty lines of the deny-list option. When the option is empty
     * the built-in defaults apply (google.com, t.co, ushort.company).
     */
    public static function deniedDomains(): array {
        $raw = (string) get_option(self::DENY_OPTION, '');
        if (trim($raw) === '') {
            return self::DEFAULT_DENIED;
        }
        $out = [];
        foreach (preg_split('/[\s,]+/', $raw) as $entry) {
            $entry = strtolower(trim($entry, " \t\n\r\0\x0B."));
            if ($entry !== '') {
                $out[] = $entry;
            }
        }
        return array_values(array_unique($out));
    }

    /**
     * Deny-list domain matching a destination (exact host or any
     * subdomain), or '' when the destination is not denied.
     */
    public static function deniedHost(string $dest): string {
        $dest = trim($dest);
        if ($dest === '') {
            return '';
        }
        $host = (strpos($dest, '://') !== false || strpos($dest, '//') === 0)
            ? (string) wp_parse_url($dest, PHP_URL_HOST)
            : $dest;
        $host = strtolower(rtrim(trim($host), '.'));
        if ($host === '') {
            return '';
        }
        foreach (self::deniedDomains() as $denied) {
            if ($host === $denied || substr($host, -strlen($denied) - 1) === '.' . $denied) {
                return $denied;
            }
        }
        return '';
    }

    /**
     * True when the destination host is on the deny list (or is a
     * subdomain of one).
     */
    public static function isDeniedHost(string $value): bool {
        return self::deniedHost($value) !== '';
    }

    /**
     * Host (or subdomain of a host) present in the whitelist setting.
     */
    public static function isWhitelistedDomain(string $dest): bool {
        $host = strtolower((string) wp_parse_url($dest, PHP_URL_HOST));
        if ($host === '') {
            return false;
        }
        foreach (self::lines('watchdog_whitelist_domains') as $entry) {
            $entry = strtolower(trim($entry));
            if ($entry === '') {
                continue;
            }
            if ($host === $entry || substr($host, -strlen($entry) - 1) === '.' . $entry) {
                return true;
            }
        }
        return false;
    }

    /**
     * Regex patterns from settings (admin-defined redirect rules).
     */
    public static function matchesWhitelistPattern(string $dest): bool {
        foreach (self::lines('watchdog_whitelist_patterns') as $pattern) {
            if (@preg_match('~' . $pattern . '~i', $dest) === 1) {
                return true;
            }
        }
        return false;
    }

    /**
     * The WordPress.org host family is always expected: core files open
     * the plugin handbook (api.wordpress.org/core/handbook/...), and
     * plugin update/help links target *.wordpress.org.
     */
    public static function isWordPressOrgHost(string $dest): bool {
        $host = strtolower((string) wp_parse_url($dest, PHP_URL_HOST));
        if ($host === '') {
            return false;
        }
        return $host === 'wordpress.org'
            || substr($host, -strlen('.wordpress.org')) === '.wordpress.org';
    }

    /**
     * Plugin/theme whitelist checks for a file origin (legacy list) or
     * trust level official/trusted.
     */
    private static function sourceTrusted(array $origin): bool {
        if (!empty($origin['plugin'])) {
            if (Trust::level($origin['plugin'], 'plugin') !== Trust::UNKNOWN) {
                return true;
            }
            foreach (self::lines('watchdog_whitelist_plugins') as $entry) {
                if (strtolower(trim($entry)) === strtolower($origin['plugin'])) {
                    return true;
                }
            }
        }
        if (!empty($origin['theme'])) {
            if (Trust::level($origin['theme'], 'theme') !== Trust::UNKNOWN) {
                return true;
            }
            foreach (self::lines('watchdog_whitelist_themes') as $entry) {
                if (strtolower(trim($entry)) === strtolower($origin['theme'])) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Argument hints that a destination is decoded (decoded_url, b64var...).
     * Word-bounded identifiers or decoder function calls only — never bare
     * substrings, so identifiers like encodeURIComponent are not flagged.
     */
    private static function decodeHint(string $arg): bool {
        return preg_match(
            '/\b(?:atob|base64_decode|str_rot13|gzinflate|gzuncompress|gzdecode|fromCharCode|hex2bin|chr)\s*\(|\\\\x[0-9a-f]{2}|\b(?:payload|decoded|encoded|obfuscated|b64|rot13|base64)\b/i',
            $arg
        ) === 1;
    }

    /**
     * Any CRITICAL signature present in the file?
     */
    private static function hasCriticalSignature(array $signatures): bool {
        if (empty($signatures)) {
            return false;
        }
        foreach (Heuristics::patterns() as $pattern) {
            if ($pattern['sev'] === 'critical' && in_array($pattern['name'], $signatures, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Non-empty lines of a list option.
     */
    public static function lines(string $option): array {
        $raw = (string) get_option($option, '');
        $out = [];
        foreach (explode("\n", $raw) as $line) {
            $line = trim($line);
            if ($line !== '') {
                $out[] = $line;
            }
        }
        return $out;
    }

    /**
     * Build a classification payload.
     */
    private static function result(string $class, string $reason, string $confidence): array {
        $severity = [
            self::SAFE       => 'safe',
            self::EXPECTED   => 'info',
            self::SUSPICIOUS => 'warning',
            self::MALICIOUS  => 'critical',
        ];
        return [
            'class'      => $class,
            'reason'     => $reason,
            'severity'   => $severity[$class],
            'confidence' => $confidence,
        ];
    }
}

