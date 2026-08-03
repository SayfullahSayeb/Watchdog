<?php
/**
 * Malware signature patterns and the weighted risk scoring engine.
 *
 * Scoring principles (false-positive reduction):
 *  - Redirect primitives are INFORMATIONAL only. Their destinations are
 *    judged by RedirectAnalyzer + RedirectEngine (which apply whitelists,
 *    trust and confidence) — never by whole-file regex escalation.
 *  - Escalation to CRITICAL requires an execution/backdoor/obfuscation
 *    signal, not mere combinations of informational markers.
 *  - Patterns with high legitimate use (call_user_func_array etc.) are
 *    not flagged at all.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * Heuristics
 */
final class Heuristics {

    private static $patterns = null;

    public const WEIGHT_INFO = 10;
    public const WEIGHT_WARNING = 35;
    public const WEIGHT_CRITICAL = 75;

    /**
     * Extensions that are executable PHP. Command-execution, eval,
     * backdoor and gzip-obfuscation signatures only ever apply to
     * these — `exec()` in JS is RegExp.exec(), `system` is common in
     * minified frontend code, and compressed payload patterns appear
     * legitimately inside WordPres core libraries.
     */
    public const PHP_EXTS = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'inc', 'htaccess', 'ini'];

    /**
     * All signature patterns.
     *
     * Each: name, cat, sev (safe|info|warning|critical), w (weight),
     * re, optional exts.
     */
    public static function patterns(): array {
        if (self::$patterns !== null) {
            return self::$patterns;
        }

        self::$patterns = [
            // --- JavaScript redirect primitives (informational alone) ---
            ['name' => 'JS: location.replace()',           'cat' => 'redirect', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/location\s*\.\s*replace\s*\(/i'],
            ['name' => 'JS: location.assign()',            'cat' => 'redirect', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/location\s*\.\s*assign\s*\(/i'],
            ['name' => 'JS: window/document.location',     'cat' => 'redirect', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/(?:window|document)\s*\.\s*location\b/i'],
            ['name' => 'JS: location.href=',               'cat' => 'redirect', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/location\s*\.\s*href\s*=/i'],
            ['name' => 'JS: window.open()',                'cat' => 'redirect', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/window\s*\.\s*open\s*\(/i'],
            ['name' => 'JS: setTimeout(...location...)',   'cat' => 'redirect', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/setTimeout\s*\([^)]*location[^)]*\)/i'],
            ['name' => 'JS: setInterval(...location...)',  'cat' => 'redirect', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/setInterval\s*\([^)]*location[^)]*\)/i'],
            ['name' => 'JS: history.pushState()',          'cat' => 'redirect', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/history\s*\.\s*pushState\s*\(/i'],
            ['name' => 'JS: history.replaceState()',       'cat' => 'redirect', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/history\s*\.\s*replaceState\s*\(/i'],
            ['name' => 'JS: meta refresh',                 'cat' => 'redirect', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/<meta\b[^>]*http-equiv\s*=\s*["\']?\s*refresh/i'],
            ['name' => 'JS: dynamic import()',             'cat' => 'redirect', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/\bimport\s*\(\s*["\']/i', 'exts' => ['js', 'mjs', 'cjs']],

            // --- Mobile detection markers (informational, no escalation) ---
            ['name' => 'JS: mobile detection (userAgent)', 'cat' => 'mobile', 'sev' => 'info', 'w' => self::WEIGHT_INFO, 're' => '/navigator\s*\.\s*userAgent/i'],
            ['name' => 'JS: mobile detection (matchMedia)', 'cat' => 'mobile', 'sev' => 'info', 'w' => self::WEIGHT_INFO, 're' => '/matchMedia\s*\(/i'],
            ['name' => 'JS: mobile keywords',              'cat' => 'mobile', 'sev' => 'info', 'w' => self::WEIGHT_INFO, 're' => '/\b(?:android|iphone|ipad)\b/i', 'exts' => ['js', 'mjs', 'cjs']],

            // --- Encoding / decoding primitives ---
            ['name' => 'JS: atob()',                       'cat' => 'decoder', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/\batob\s*\(/i', 'exts' => ['js', 'mjs', 'cjs']],
            ['name' => 'JS: String.fromCharCode()',        'cat' => 'decoder', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/String\s*\.\s*fromCharCode\s*\(/i', 'exts' => ['js', 'mjs', 'cjs']],
            // new Function() is standard webpack runtime boilerplate
            // ("return this" globals, lazy chunk loading). Judgement is
            // left to the line-level ExecutionContext, which checks
            // trust and payload decoding; whole-file mention is a note.
            ['name' => 'JS: new Function()',               'cat' => 'decoder', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/new\s+Function\s*\(/i', 'exts' => ['js', 'mjs', 'cjs']],
            ['name' => 'Obfuscation: hex escapes',         'cat' => 'decoder', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/(?:\\\\x[0-9a-f]{2}){3,}/i'],
            ['name' => 'Obfuscation: chr() chains',        'cat' => 'decoder', 'sev' => 'info',   'w' => self::WEIGHT_INFO,   're' => '/\bchr\s*\(/i', 'exts' => self::PHP_EXTS],

            // --- PHP redirect primitives ---
            ['name' => 'PHP: header("Location:")',         'cat' => 'redirect', 'sev' => 'info', 'w' => self::WEIGHT_INFO, 're' => '/header\s*\(\s*["\']\s*location\s*:/i'],
            ['name' => 'PHP: header("Refresh:")',          'cat' => 'redirect', 'sev' => 'info', 'w' => self::WEIGHT_INFO, 're' => '/header\s*\(\s*["\']\s*refresh\s*:/i'],
            ['name' => 'PHP: wp_redirect()',               'cat' => 'redirect', 'sev' => 'info', 'w' => self::WEIGHT_INFO, 're' => '/wp_redirect\s*\(/i'],
            ['name' => 'PHP: wp_safe_redirect()',          'cat' => 'redirect', 'sev' => 'info', 'w' => self::WEIGHT_INFO, 're' => '/wp_safe_redirect\s*\(/i'],
            ['name' => 'PHP: exit/die after header()',     'cat' => 'redirect', 'sev' => 'info', 'w' => self::WEIGHT_INFO, 're' => '/header\s*\(\s*["\']\s*(?:location|refresh)\s*:[^)]*\)\s*;\s*(?:exit|die)\b/i'],

            // --- Obfuscation / payload execution (PHP only) ---
            ['name' => 'Obfuscation: eval(base64_decode())', 'cat' => 'obfuscation', 'sev' => 'critical', 'w' => self::WEIGHT_CRITICAL, 're' => '/eval\s*\(\s*base64_decode\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Obfuscation: eval(gzinflate(base64_decode()))', 'cat' => 'obfuscation', 'sev' => 'critical', 'w' => self::WEIGHT_CRITICAL, 're' => '/eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Obfuscation: gzinflate()',         'cat' => 'obfuscation', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/gzinflate\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Obfuscation: gzuncompress()',      'cat' => 'obfuscation', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/gzuncompress\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Obfuscation: gzdecode()',          'cat' => 'obfuscation', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/gzdecode\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Obfuscation: str_rot13()',         'cat' => 'obfuscation', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/str_rot13\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Obfuscation: create_function()',   'cat' => 'obfuscation', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/create_function\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Legacy: preg_replace /e',          'cat' => 'obfuscation', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/preg_replace\s*\(\s*["\'][^"\']*\/e["\']/i', 'exts' => self::PHP_EXTS],
            ['name' => 'PHP: eval()',                      'cat' => 'obfuscation', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/\beval\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'PHP: auto_prepend_file()',         'cat' => 'exec', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/auto_prepend_file\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'PHP: include() remote URL',        'cat' => 'exec', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/\binclude(?:_once)?\s*\(\s*["\']https?:\/\//i', 'exts' => self::PHP_EXTS],
            ['name' => 'PHP: require() remote URL',        'cat' => 'exec', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/\brequire(?:_once)?\s*\(\s*["\']https?:\/\//i', 'exts' => self::PHP_EXTS],

            // --- Command execution (PHP only; `exec` in JS is RegExp) ---
            // Whole-file command primitives are warnings, never critical:
            // getID3, PHPMailer and Snoopy in WP core legitimately call
            // shell_exec/passthru/popen for external tools. A true
            // webshell couples the primitive with request data — see
            // 'Backdoor: command execution(request)' below.
            ['name' => 'Execution: shell_exec()',          'cat' => 'exec', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/shell_exec\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Execution: exec()',                'cat' => 'exec', 'sev' => 'warning',  'w' => self::WEIGHT_WARNING,  're' => '/\bexec\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Execution: system()',              'cat' => 'exec', 'sev' => 'warning',  'w' => self::WEIGHT_WARNING,  're' => '/\bsystem\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Execution: passthru()',            'cat' => 'exec', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/passthru\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Execution: proc_open()',           'cat' => 'exec', 'sev' => 'warning',  'w' => self::WEIGHT_WARNING,  're' => '/proc_open\s*\(/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Execution: popen()',               'cat' => 'exec', 'sev' => 'warning',  'w' => self::WEIGHT_WARNING,  're' => '/popen\s*\(/i', 'exts' => self::PHP_EXTS],

            // --- Backdoors ---
            // Command execution fed by request data is a webshell —
            // critical regardless of the file's origin.
            ['name' => 'Backdoor: command execution(request)', 'cat' => 'backdoor', 'sev' => 'critical', 'w' => self::WEIGHT_CRITICAL, 're' => '/\b(?:system|shell_exec|passthru|proc_open|popen|exec)\s*\(\s*["\']?\s*\$_(?:GET|POST|REQUEST|COOKIE)/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Backdoor: assert() with payload',  'cat' => 'backdoor', 'sev' => 'critical', 'w' => self::WEIGHT_CRITICAL, 're' => '/\bassert\s*\(\s*(?:base64_decode|gzuncompress|gzdecode|\$_(?:GET|POST|REQUEST|COOKIE))/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Backdoor: base64_decode(request)', 'cat' => 'backdoor', 'sev' => 'critical', 'w' => self::WEIGHT_CRITICAL, 're' => '/base64_decode\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Backdoor: eval(request)',          'cat' => 'backdoor', 'sev' => 'critical', 'w' => self::WEIGHT_CRITICAL, 're' => '/\beval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i', 'exts' => self::PHP_EXTS],
            ['name' => 'Backdoor: create_function(request)', 'cat' => 'backdoor', 'sev' => 'critical', 'w' => self::WEIGHT_CRITICAL, 're' => '/create_function\s*\(\s*["\'][^"\']*\$_(?:GET|POST|REQUEST|COOKIE)/i', 'exts' => self::PHP_EXTS],
            ['name' => 'SQLi: query with request data',    'cat' => 'backdoor', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/\b(?:mysql_query|mysqli_query|wpdb->query|$wpdb->query)\s*\(\s*["\']?[^"\']*\$_(?:GET|POST|REQUEST)/i', 'exts' => self::PHP_EXTS],


            ['name' => 'Malware domain: ushort.company',   'cat' => 'domain', 'sev' => 'critical', 'w' => self::WEIGHT_CRITICAL, 're' => '/ushort\s*\.\s*company/i'],
            ['name' => 'URL shortener: bit.ly',            'cat' => 'domain', 'sev' => 'info',     'w' => self::WEIGHT_INFO,     're' => '/bit\s*\.\s*ly\b/i'],
            ['name' => 'URL shortener: tinyurl.com',       'cat' => 'domain', 'sev' => 'info',     'w' => self::WEIGHT_INFO,     're' => '/tinyurl\s*\.\s*com/i'],
            ['name' => 'Telegram link: t.me',              'cat' => 'domain', 'sev' => 'info',     'w' => self::WEIGHT_INFO,     're' => '/t\s*\.\s*me\b/i'],
            ['name' => 'Paste site: pastebin.com',         'cat' => 'domain', 'sev' => 'info',     'w' => self::WEIGHT_INFO,     're' => '/pastebin\s*\.\s*com/i'],
            ['name' => 'Tunnel: ngrok.io',                 'cat' => 'domain', 'sev' => 'info',     'w' => self::WEIGHT_INFO,     're' => '/ngrok\s*\.\s*(?:io|com|app)/i'],
            ['name' => 'Dynamic DNS: duckdns.org',         'cat' => 'domain', 'sev' => 'info',     'w' => self::WEIGHT_INFO,     're' => '/duckdns\s*\.\s*org/i'],

            // --- Crypto miners ---
            ['name' => 'Crypto miner script',              'cat' => 'miner', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/(?:coinhive|coin-hive|authedmine|webminepool|cryptoloot|minr\s*\.\s*cr|mineralt|reese84)/i'],

            // --- Hidden content / SEO spam ---
            ['name' => 'Hidden iframe',                    'cat' => 'spam', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/<iframe[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0)/i', 'exts' => ['htm', 'html', 'php', 'phtml']],
            ['name' => 'Hidden script element',            'cat' => 'spam', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/<script[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden)/i', 'exts' => ['htm', 'html', 'php', 'phtml']],
            ['name' => 'Hidden SEO link',                  'cat' => 'spam', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/<a[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|position\s*:\s*absolute|font-size\s*:\s*0)/i', 'exts' => ['htm', 'html', 'php', 'phtml']],
            // Whole words only — 'cialis' must not match inside
            // 'specialised' (lodash doc comments) or 'official'.
            ['name' => 'SEO spam keywords',                'cat' => 'spam', 'sev' => 'warning', 'w' => self::WEIGHT_WARNING, 're' => '/(?:viagra|cialis|casino|nike|louis\s+vuitton|gucci|replica\s+watches)\b/i'],

            // --- High-entropy blob (encoded payload). Only flagged when the
            // file also decodes something — a bare base64 blob (inline
            // images, license keys) is too common to flag on its own.
            ['name' => 'High-entropy blob',                'cat' => 'entropy', 'sev' => 'info', 'w' => self::WEIGHT_INFO, 're' => '/[A-Za-z0-9+\/]{80,}/', 'exts' => ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'inc', 'htaccess', 'ini']],
        ];

        return self::$patterns;
    }

    /**
     * Decoder markers that make a high-entropy blob worth flagging.
     */
    private static function hasDecoderContext(string $content): bool {
        return preg_match('/\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|eval|assert|atob|fromCharCode|hex2bin|pack|unpack)\s*\(/i', $content) === 1;
    }

    /**
     * Run all signatures against file content. Returns matched pattern names.
     */
    public static function scan(string $content, string $ext): array {
        $found = [];
        foreach (self::patterns() as $pattern) {
            if (isset($pattern['exts']) && !in_array($ext, $pattern['exts'], true)) {
                continue;
            }
            if ($pattern['name'] === 'High-entropy blob' && !self::hasDecoderContext($content)) {
                continue;
            }
            if (preg_match($pattern['re'], $content) === 1) {
                $found[] = $pattern['name'];
            }
        }
        return $found;
    }

    /**
     * Locate the lines matching the given signature names inside a file.
     * Used by the timeline "view" so an event shows the exact code that
     * triggered the detection (Wordfence-style).
     *
     * @return array<int, array{line: int, code: string}>
     */
    public static function locateLines(string $path, array $names, int $limit = 8): array {
        if ($names === []) {
            return [];
        }
        $content = @file_get_contents($path);
        if ($content === false || $content === '') {
            return [];
        }
        $regexes = [];
        foreach (self::patterns() as $pattern) {
            if (in_array($pattern['name'], $names, true)) {
                $regexes[] = $pattern['re'];
            }
        }
        if ($regexes === []) {
            return [];
        }
        $lines = preg_split('/\R/', $content);
        if ($lines === false) {
            return [];
        }
        $found = [];
        foreach ($lines as $i => $line) {
            $lineText = (string) $line;
            foreach ($regexes as $re) {
                if (@preg_match($re, $lineText) === 1) {
                    $found[] = ['line' => $i + 1, 'code' => trim($lineText)];
                    break;
                }
            }
            if (count($found) >= $limit) {
                break;
            }
        }
        return $found;
    }

    /**
     * Weighted risk scoring for a set of matched pattern names.
     *
     * Returns ['sev', 'label', 'score'].
     *
     * Rules:
     *  - score = sum of pattern weights.
     *  - severity starts at the worst matched pattern severity.
     *  - Informational markers (location, mobile detection, atob,
     *    hex escapes …) NEVER escalate on their own or by count —
     *    every modern JavaScript file contains them legitimately.
     *  - warning -> critical escalation requires two or more
     *    distinct warning-or-critical categories (exec + obfuscation,
     *    spam + domain, …), i.e. an actual execution-capable signal.
     */
    public static function classify(array $found): array {
        if (empty($found)) {
            return ['sev' => '', 'label' => null, 'score' => 0];
        }

        $order = ['safe' => 0, 'info' => 1, 'warning' => 2, 'critical' => 3];
        $cats = [];
        $score = 0;
        $worst = 0;
        $warningCats = [];

        foreach (self::patterns() as $pattern) {
            if (!in_array($pattern['name'], $found, true)) {
                continue;
            }
            $cats[$pattern['cat']] = true;
            $score += $pattern['w'];
            if ($order[$pattern['sev']] > $worst) {
                $worst = $order[$pattern['sev']];
            }
            if ($order[$pattern['sev']] >= 2) {
                $warningCats[$pattern['cat']] = true;
            }
        }

        $severity = 'info';
        foreach ($order as $level => $weight) {
            if ($weight === $worst) {
                $severity = $level;
            }
        }

        $label = null;
        if ($severity === 'warning' && count($warningCats) >= 2) {
            $severity = 'critical';
            $label = 'multiple suspicious indicators';
        }

        return ['sev' => $severity, 'label' => $label, 'score' => $score];
    }

    /**
     * True when any matched pattern is a hard critical signature
     * (eval(request), backdoor, shell_exec, malicious domain, …).
     */
    public static function hasCriticalSignature(array $found): bool {
        if (empty($found)) {
            return false;
        }
        foreach (self::patterns() as $pattern) {
            if ($pattern['sev'] === 'critical' && in_array($pattern['name'], $found, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Numeric ordering helper used when merging severities.
     */
    public static function rank(string $severity): int {
        $order = ['safe' => 0, 'info' => 1, 'warning' => 2, 'critical' => 3];
        return isset($order[$severity]) ? $order[$severity] : 0;
    }
}
