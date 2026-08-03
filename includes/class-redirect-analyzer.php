<?php
/**
 * Redirect analyzer. Instead of blind regex matching, it locates redirect
 * primitives in JS/PHP code, extracts the argument expression, attempts to
 * decode obfuscated destinations (base64, hex, chr(), String.fromCharCode,
 * atob, str_rot13, gzinflate, concatenation) and classifies each call as
 * SAFE / INFO / WARNING / CRITICAL with line, function and destination.
 *
 * No eval() is ever executed: decoding is done with pure string functions.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * RedirectAnalyzer
 */
final class RedirectAnalyzer {

    /**
     * JavaScript redirect primitives.
     * kind = call  -> argument is the balanced parens content
     * kind = assign-> argument is the statement until ';' or newline
     */
    private static function jsPatterns(): array {
        return [
            ['name' => 'location.replace',   'kind' => 'call',   're' => '/location\s*\.\s*replace\s*\(/i'],
            ['name' => 'location.assign',    'kind' => 'call',   're' => '/location\s*\.\s*assign\s*\(/i'],
            ['name' => 'window.location',    'kind' => 'assign', 're' => '/(?:window|document)\s*\.\s*location(?:\s*\.\s*href)?\s*=/i'],
            ['name' => 'location.href',      'kind' => 'assign', 're' => '/location\s*\.\s*href\s*=/i'],
            ['name' => 'window.open',        'kind' => 'call',   're' => '/window\s*\.\s*open\s*\(/i'],
            ['name' => 'setTimeout',         'kind' => 'call',   're' => '/setTimeout\s*\(/i'],
            ['name' => 'setInterval',        'kind' => 'call',   're' => '/setInterval\s*\(/i'],
            ['name' => 'history.pushState',  'kind' => 'call',   're' => '/history\s*\.\s*pushState\s*\(/i'],
            ['name' => 'history.replaceState', 'kind' => 'call', 're' => '/history\s*\.\s*replaceState\s*\(/i'],
        ];
    }

    /**
     * HTML meta-refresh redirects.
     * kind = meta -> argument is the url= value of the content attribute.
     */
    private static function metaPatterns(): array {
        return [
            ['name' => 'meta-refresh', 'kind' => 'meta', 're' => '/<meta\b[^>]*http-equiv\s*=\s*["\']?\s*refresh\s*["\']?[^>]*>/i'],
        ];
    }

    /**
     * PHP redirect primitives.
     */
    private static function phpPatterns(): array {
        return [
            ['name' => 'header("Location:")', 'kind' => 'header', 're' => '/header\s*\(\s*["\']\s*location\s*:/i'],
            ['name' => 'header("Refresh:")',  'kind' => 'header', 're' => '/header\s*\(\s*["\']\s*refresh\s*:/i'],
            ['name' => 'wp_redirect',         'kind' => 'call',   're' => '/wp_redirect\s*\(/i'],
            ['name' => 'wp_safe_redirect',    'kind' => 'call',   're' => '/wp_safe_redirect\s*\(/i'],
        ];
    }

    /**
     * Analyze file content. Returns an array of findings, each:
     * call, line, function, arg, dest (decoded or null), severity, note.
     */
    public static function analyzeContent(string $content, string $filename): array {
        $findings = [];
        $hasMobile = preg_match('/navigator\s*\.\s*userAgent|matchMedia\s*\(|\b(?:android|iphone|ipad)\b/i', $content) === 1;

        foreach (self::jsPatterns() as $pattern) {
            self::scanPattern($content, $pattern, $findings, $hasMobile);
        }
        foreach (self::metaPatterns() as $pattern) {
            self::scanPattern($content, $pattern, $findings, $hasMobile);
        }
        foreach (self::phpPatterns() as $pattern) {
            self::scanPattern($content, $pattern, $findings, $hasMobile);
        }
        return $findings;
    }

    /**
     * Find every occurrence of one pattern and evaluate it.
     */
    private static function scanPattern(string $content, array $pattern, array &$findings, bool $hasMobile): void {
        $matched = preg_match_all($pattern['re'], $content, $matches, PREG_OFFSET_CAPTURE);
        if ($matched === false || $matched === 0 || empty($matches[0])) {
            return;
        }

        foreach ($matches[0] as $match) {
            $offset = (int) $match[1];
            $line = substr_count(substr($content, 0, $offset), "\n") + 1;
            $raw = self::extractArgument($content, $pattern, $offset);

            if ($raw === '') {
                continue;
            }

            $findings[] = self::evaluate($pattern['name'], $raw, $line, self::detectFunction($content, $offset), $hasMobile);
        }
    }

    /**
     * Pull the argument expression depending on pattern kind.
     */
    private static function extractArgument(string $content, array $pattern, int $offset): string {
        $kind = $pattern['kind'];

        if ($kind === 'assign') {
            $statement = substr($content, $offset, 300);
            $semi = strpos($statement, ';');
            $newline = strpos($statement, "\n");
            $end = PHP_INT_MAX;
            if ($semi !== false) {
                $end = $semi;
            }
            if ($newline !== false && $newline < $end) {
                $end = $newline;
            }
            $statement = substr($statement, 0, $end);
            return trim(preg_replace('/^(?:window|document)\s*\.\s*location(?:\s*\.\s*href)?\s*=|^location\s*\.\s*href\s*=/i', '', $statement));
        }

        if ($kind === 'header') {
            $snippet = substr($content, $offset, 400);
            if (preg_match('/header\s*\(\s*["\']\s*location\s*:\s*([^"\']+)["\']/i', $snippet, $hm)) {
                return trim($hm[1]);
            }
            if (preg_match('/header\s*\(\s*["\']\s*refresh\s*:\s*[^"\']*url\s*=\s*([^"\']+)["\']/i', $snippet, $hm)) {
                return trim($hm[1]);
            }
            return '';
        }

        if ($kind === 'meta') {
            $tag = substr($content, $offset, 500);
            if (preg_match('/content\s*=\s*["\']([^"\']*)["\']/i', $tag, $cm)) {
                $contentValue = trim($cm[1]);
                if (preg_match('/url\s*=\s*(["\']?)([^"\']*)\1/i', $contentValue, $um)) {
                    return trim($um[2]);
                }
                if (preg_match('/^\s*\d*\s*;\s*(.+?)\s*$/', $contentValue, $em)) {
                    return trim($em[1]);
                }
            }
            return '';
        }

        return self::readBalanced($content, $offset + strlen($pattern['re'] === '' ? '' : ''));
    }

    /**
     * Read the balanced-parens argument of a call, respecting quotes.
     */
    private static function readBalanced(string $content, int $pos): string {
        $length = strlen($content);
        $depth = 0;
        $quote = null;
        $started = false;
        $out = '';

        for ($i = $pos; $i < $length; $i++) {
            $char = $content[$i];

            if ($quote !== null) {
                if ($char === '\\' && isset($content[$i + 1])) {
                    $out .= $char . $content[$i + 1]; // preserve escapes (\xNN)
                    $i++;
                } elseif ($char === $quote) {
                    $out .= $char; // closing quote
                    $quote = null;
                } else {
                    $out .= $char;
                }
                continue;
            }

            if ($char === '"' || $char === "'") {
                $quote = $char;
                if ($started) {
                    $out .= $char;
                }
                continue;
            }

            if ($char === '(') {
                $depth++;
                $started = true;
                if ($depth > 1) {
                    $out .= $char; // preserve nested parens (function calls)
                }
                continue;
            }

            if ($char === ')') {
                if ($depth === 1) {
                    break;
                }
                $depth--;
                $out .= $char;
                continue;
            }

            if ($started) {
                $out .= $char;
                if (strlen($out) > 400) {
                    break;
                }
            }
        }

        return trim($out);
    }

    /**
     * Decode chains and classify a single redirect call.
     */
    private static function evaluate(string $call, string $raw, int $line, string $function, bool $hasMobile): array {
        $raw = trim(substr($raw, 0, 300));
        $dest = self::decodeDestination($raw);
        // Decoder calls and hex escapes only. String concatenation is
        // resolved by decodeDestination() and is NOT treated as
        // obfuscation, otherwise every 'https://' + var expression in
        // legitimate code would be flagged.
        $hasObfuscation = preg_match(
            '/\b(?:atob|base64_decode|str_rot13|gzinflate|gzuncompress|gzdecode|fromCharCode|hex2bin|chr)\s*\(|\\\\x[0-9a-f]{2}|\beval\s*\(|new\s+Function\s*\(/i',
            $raw
        ) === 1;
        $hint = preg_match('/\b(?:payload|decoded|encoded|obfuscated|base64|b64|rot13)\b/i', $raw) === 1;

        if ($dest !== null && $dest !== '') {
            if (self::isInternal($dest)) {
                $severity = 'safe';
                $note = 'internal destination';
            } else {
                $severity = ($hasObfuscation || $hasMobile) ? 'critical' : 'warning';
                $note = $hasObfuscation
                    ? 'external destination built from decoded or concatenated input'
                    : 'external destination';
            }
        } elseif (self::isWpFunction($raw)) {
            $severity = 'safe';
            $note = 'WordPress function destination';
        } else {
            $severity = ($hasObfuscation || $hint) ? 'critical' : 'warning';
            $note = ($hasObfuscation || $hint)
                ? 'encoded, decoded or opaque destination'
                : 'dynamic or unknown destination';
        }

        return [
            'call'       => $call,
            'method'     => $call,
            'line'       => $line,
            'function'   => $function,
            'arg'        => $raw,
            'dest'       => $dest,
            'obfuscated' => $hasObfuscation,
            'mobile'     => $hasMobile,
            'hint'       => $hint,
            'severity'   => $severity,
            'note'       => $note,
        ];
    }

    /**
     * Iteratively apply decode steps (max 5) and return a URL-like result.
     */
    private static function decodeDestination(string $raw): ?string {
        $current = trim($raw);

        for ($i = 0; $i < 5; $i++) {
            $next = self::decodeStep($current);
            if ($next === $current) {
                break;
            }
            $current = $next;
        }

        if (self::looksLikeUrl($current)) {
            return $current;
        }
        return null;
    }

    /**
     * One decode pass: base64, rot13, inflate, hex, char codes, unquoting.
     */
    private static function decodeStep(string $input): string {
        $t = trim($input);
        $changed = false;

        // Strip one pair of surrounding quotes.
        if (strlen($t) >= 2 && ($t[0] === '"' || $t[0] === "'") && substr($t, -1) === $t[0]) {
            $t = substr($t, 1, -1);
            $changed = true;
        }

        // Bare base64 literal that decodes to a URL.
        if (preg_match('/^[A-Za-z0-9+\/]{16,}={0,2}$/', $t) === 1) {
            $decoded = @base64_decode($t, true);
            if ($decoded !== false && self::looksLikeUrl($decoded)) {
                return $decoded;
            }
        }

        // atob("...") / base64_decode("...")
        $t = preg_replace_callback(
            '/\b(?:atob|base64_decode)\s*\(\s*["\']?([A-Za-z0-9+\/]+={0,2})["\']?\s*\)/',
            static function ($m) use (&$changed) {
                $decoded = @base64_decode($m[1], true);
                if ($decoded === false) {
                    return $m[0];
                }
                $changed = true;
                return $decoded;
            },
            $t
        );

        // Unwrap URL-decoding wrappers (decodeURIComponent, unescape,
        // urldecode, rawurldecode) around already-decoded strings.
        $t = preg_replace_callback(
            '/\b(?:decodeURIComponent|unescape|urldecode|rawurldecode)\s*\(([^()]*)\)/i',
            static function ($m) use (&$changed) {
                $changed = true;
                return $m[1];
            },
            $t
        );

        // str_rot13("...")
        $t = preg_replace_callback(
            '/\bstr_rot13\s*\(\s*["\']?([^"\'()]*)["\']?\s*\)/',
            static function ($m) use (&$changed) {
                $changed = true;
                return str_rot13($m[1]);
            },
            $t
        );

        // gzinflate(base64_decode("..."))
        $t = preg_replace_callback(
            '/\bgzinflate\s*\(\s*base64_decode\s*\(\s*["\']?([A-Za-z0-9+\/]+={0,2})["\']?\s*\)\s*\)/',
            static function ($m) use (&$changed) {
                $raw = @base64_decode($m[1], true);
                if ($raw === false) {
                    return $m[0];
                }
                $inflated = @gzinflate($raw);
                if ($inflated === false || strlen($inflated) > 4096) {
                    return $m[0];
                }
                $changed = true;
                return $inflated;
            },
            $t
        );

        // Hex escapes \xNN
        if (preg_match('/\\\\x[0-9a-f]{2}/i', $t) === 1) {
            $t = preg_replace_callback(
                '/\\\\x([0-9a-f]{2})/i',
                static function ($m) use (&$changed) {
                    $changed = true;
                    return chr(hexdec($m[1]));
                },
                $t
            );
        }

        // Full char-code chains: chr(104).chr(116) / chr(104)+chr(116) /
        // String.fromCharCode(104,116). Only used when the whole argument
        // is such a chain, so ordinary identifiers are never touched.
        if (preg_match('/^\s*(?:String\s*\.\s*fromCharCode|chr)\s*\([^)]+\)(?:\s*[.+]?\s*(?:String\s*\.\s*fromCharCode|chr)\s*\([^)]+\))*\s*$/i', $t) === 1) {
            $out = '';
            if (preg_match_all('/\b(?:String\s*\.\s*fromCharCode|chr)\s*\(([^)]+)\)/i', $t, $calls)) {
                foreach ($calls[1] as $args) {
                    if (preg_match_all('/0x[0-9a-f]+|\d+/i', $args, $nums)) {
                        foreach ($nums[0] as $num) {
                            $value = preg_match('/^0x/i', $num) ? hexdec($num) : (int) $num;
                            if ($value > 0 && $value < 256) {
                                $out .= chr($value);
                            }
                        }
                    }
                }
            }
            if ($out !== '') {
                $changed = true;
                return $out;
            }
        }

        // Unquote all quoted strings and collapse concatenation: 'a'+'b' => ab
        $unquoted = preg_replace_callback(
            '/["\']([^"\']*)["\']/',
            static function ($m) use (&$changed) {
                $changed = true;
                return $m[1];
            },
            $t
        );
        if ($unquoted !== $t) {
            $t = preg_replace('/\s*\+\s*/', '', $unquoted);
        }

        return $changed ? trim($t) : trim($input);
    }

    /**
     * True when the string looks like a URL or a relative path.
     */
    private static function looksLikeUrl(string $value): bool {
        $value = trim($value);
        return preg_match('/^(?:https?:\/\/|\/\/|ftp:\/\/)/i', $value) === 1
            || (strlen($value) > 1 && preg_match('/^[\/#?]/', $value) === 1)
            || (strpos($value, '.') !== false && preg_match('/^[a-z0-9][a-z0-9.\/-]*$/i', $value) === 1);
    }

    /**
     * Internal destinations: relative paths, anchors, queries, same host.
     */
    private static function isInternal(string $dest): bool {
        $dest = trim($dest);
        if ($dest === '') {
            return true;
        }
        if (preg_match('/^[\/#?]/', $dest) === 1 || strpos($dest, '://') === false) {
            return true;
        }
        if (preg_match('/^\/\//', $dest) === 1) {
            $dest = 'https:' . $dest;
        }
        $destHost = strtolower((string) wp_parse_url($dest, PHP_URL_HOST));
        if ($destHost === '') {
            return true;
        }
        $siteHost = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        return $destHost === $siteHost;
    }

    /**
     * Known WordPress navigation functions => safe.
     */
    private static function isWpFunction(string $raw): bool {
        return preg_match(
            '/^(?:home_url|admin_url|site_url|network_home_url|network_admin_url|wp_login_url|wp_logout_url|wp_registration_url|get_permalink|wp_get_referer|wp_safe_redirect|redirect_canonical)\s*\(/i',
            $raw
        ) === 1;
    }

    /**
     * Find the enclosing function name before a given offset.
     */
    private static function detectFunction(string $content, int $offset): string {
        $prefix = substr($content, 0, $offset);
        if (preg_match_all('/function\s+([a-zA-Z_$][\w$]*)\s*\(/i', $prefix, $matches, PREG_OFFSET_CAPTURE) === 1 && !empty($matches[1])) {
            $last = $matches[1][count($matches[1]) - 1];
            return (string) $last[0];
        }
        return 'global scope';
    }
}
