<?php
/**
 * ExecutionContext: understands HOW, WHEN, WHERE and WHY code executes
 * before judging it.
 *
 * Suspicious primitives (redirects, eval/Function constructors) are not
 * classified by keyword presence but by execution behavior:
 *
 *   - execution mode: immediate top-level, IIFE, deferred (timer, ready,
 *     rAF, observer, promise), user-interaction handler, never-called,
 *     or WordPress hook context (frontend / admin / AJAX / REST / cron).
 *   - conditions: wrapped in if/while/for/ternary/&&/|| chains, and
 *     whether the condition is mobile gating (matchMedia pointer:coarse,
 *     userAgent, screen.width, wp_is_mobile ...).
 *   - destination: resolved statically when possible (concatenation,
 *     atob(), String.fromCharCode(), chr(), base64_decode(), hex/unicode
 *     escapes, template literals, array joins, WordPress URL functions).
 *     Nothing is ever executed or evaluated dynamically.
 *   - confidence: LOW / MEDIUM / HIGH / CRITICAL from the five scores,
 *     with fixed rules for the known malware patterns (immediate
 *     external redirect, mobile-gated automatic redirect, timer
 *     redirect) and trust-model downgrades to keep legitimate
 *     WooCommerce/Elementor/login/checkout flows safe.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * ExecutionContext
 */
final class ExecutionContext {

    public const CONFIDENCE_LOW = 'low';
    public const CONFIDENCE_MEDIUM = 'medium';
    public const CONFIDENCE_HIGH = 'high';
    public const CONFIDENCE_CRITICAL = 'critical';

    public const MAX_ANALYZE_BYTES = 524288; // 512 KB
    private const MAX_TOKENS = 200000;

    private const REDIRECT_METHODS = [
        'location.replace()',
        'location.assign()',
        'window.open()',
        'location=',
        'window.location=',
        'document.location=',
        'location.href=',
        'wp_redirect()',
        'wp_safe_redirect()',
        'header(Location)',
        'header(Refresh)',
    ];

    /**
     * Analyze file content. Returns findings for every redirect / eval
     * primitive with execution context, scores, confidence and action.
     *
     * @return array<int, array>
     */
    public static function analyzeFile(string $content, string $path): array {
        $content = (string) $content;
        if ($content === '' || strlen($content) > self::MAX_ANALYZE_BYTES) {
            return [];
        }

        $lang = in_array(strtolower(pathinfo($path, PATHINFO_EXTENSION)), ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'inc'], true) ? 'php' : 'js';
        if (preg_match('~/\*\s*@watchdog-skip-exec\b~i', $content) === 1) {
            return [];
        }

        return self::analyzeCode($content, $path, $lang, null, 0);
    }

    /**
     * Core analysis pipeline; recurses into timer string bodies.
     *
     * @return array<int, array>
     */
    private static function analyzeCode(string $code, string $path, string $lang, ?array $forcedExec, int $depth): array {
        if ($depth > 2 || $code === '' || strlen($code) > self::MAX_ANALYZE_BYTES) {
            return [];
        }

        $tokens = self::tokenize($code);
        if (empty($tokens)) {
            return [];
        }

        $pairs = self::matchPairs($tokens);
        $struct = self::structure($tokens, $pairs);
        $primitives = self::detectPrimitives($tokens, $pairs, $lang);

        $results = [];
        foreach ($primitives as $primitive) {
            $result = self::classifyPrimitive($primitive, $tokens, $pairs, $struct, $path, $lang, $forcedExec);
            if ($result !== null) {
                $results[] = $result;
            }
        }

        // timer/interval string bodies (`setTimeout("location.href=...", 1000)`):
        // the code inside the string never appears in the token stream, so it
        // is analyzed recursively under the timer's execution context.
        foreach ($struct['regs'] as $reg) {
            if (empty($reg['stringBody'])) {
                continue;
            }
            $inner = self::analyzeCode((string) $reg['stringBody'], $path, 'js', self::modeFromReg($reg, 'js'), $depth + 1);
            foreach ($inner as $finding) {
                $results[] = $finding;
            }
        }

        return $results;
    }

    /**
     * Full report payload for one finding (incident reporting).
     */
    public static function incidentReport(array $finding): array {
        $origin = RedirectEngine::originOf(isset($finding['path']) ? $finding['path'] : '');
        $source = $origin['plugin'] !== ''
            ? 'plugin: ' . $origin['plugin']
            : ($origin['theme'] !== '' ? 'theme: ' . $origin['theme'] : ($origin['core'] ? 'wordpress core' : ($origin['uploads'] ? 'uploads' : 'unknown')));
        $context = isset($finding['context']) && is_array($finding['context']) ? $finding['context'] : [];
        return [
            'confidence'        => (string) ($finding['confidence'] ?? ''),
            'risk_score'        => (int) (($finding['scores']['risk'] ?? 0)),
            'execution_context' => $context,
            'filename'          => isset($finding['path']) ? basename($finding['path']) : '',
            'plugin_theme'      => $source,
            'line'              => (int) ($finding['line'] ?? 0),
            'destination'       => (string) ($finding['dest'] ?? ''),
            'trigger'           => (string) ($finding['trigger'] ?? ''),
            'reason'            => (string) ($finding['reason'] ?? ''),
            'action'            => (string) ($finding['action'] ?? ''),
        ];
    }

    /**
     * Recommended automated action for a confidence level.
     */
    public static function actionFor(string $confidence): string {
        switch ($confidence) {
            case self::CONFIDENCE_CRITICAL:
                return 'Block redirect immediately; disable plugin if possible; quarantine modified file; backup original; generate incident report';
            case self::CONFIDENCE_HIGH:
                return 'Block runtime redirect; log stack trace; notify administrator';
            case self::CONFIDENCE_MEDIUM:
                return 'Alert administrator';
            default:
                return 'Log only';
        }
    }

    /* ------------------------------------------------------------------
     * Tokenizer
     * ---------------------------------------------------------------- */

    /**
     * Tokenize JS/PHP into a flat list: t = str|tmpl|regex|num|id|p,
     * v = raw text, l = 1-based line.
     *
     * @return array<int, array{t: string, v: string, l: int, interp?: bool}>
     */
    private static function tokenize(string $code): array {
        $tokens = [];
        $len = strlen($code);
        $i = 0;
        $line = 1;
        $regexAllowed = true;

        while ($i < $len && count($tokens) < self::MAX_TOKENS) {
            $c = $code[$i];

            if ($c === "\n") {
                $line++;
                $i++;
                $regexAllowed = true;
                continue;
            }
            if (ctype_space($c)) {
                $i++;
                continue;
            }
            if ($c === '/' && ($code[$i + 1] ?? '') === '/') {
                while ($i < $len && $code[$i] !== "\n") {
                    $i++;
                }
                continue;
            }
            if ($c === '/' && ($code[$i + 1] ?? '') === '*') {
                $i += 2;
                while ($i + 1 < $len && !($code[$i] === '*' && $code[$i + 1] === '/')) {
                    if ($code[$i] === "\n") {
                        $line++;
                    }
                    $i++;
                }
                $i = min($i + 2, $len);
                continue;
            }
            if ($c === '"' || $c === "'") {
                $quote = $c;
                $start = $i;
                $i++;
                while ($i < $len) {
                    if ($code[$i] === '\\') {
                        $i += 2;
                        continue;
                    }
                    if ($code[$i] === $quote) {
                        $i++;
                        break;
                    }
                    if ($code[$i] === "\n") {
                        $line++;
                    }
                    $i++;
                }
                $tokens[] = ['t' => 'str', 'v' => substr($code, $start, $i - $start), 'l' => $line];
                $regexAllowed = false;
                continue;
            }
            if ($c === '`') {
                $start = $i;
                $i++;
                $interp = false;
                while ($i < $len) {
                    if ($code[$i] === '\\') {
                        $i += 2;
                        continue;
                    }
                    if ($code[$i] === '$' && ($code[$i + 1] ?? '') === '{') {
                        $interp = true;
                    }
                    if ($code[$i] === '`') {
                        $i++;
                        break;
                    }
                    if ($code[$i] === "\n") {
                        $line++;
                    }
                    $i++;
                }
                $tokens[] = ['t' => 'tmpl', 'v' => substr($code, $start, $i - $start), 'l' => $line, 'interp' => $interp];
                $regexAllowed = false;
                continue;
            }
            if ($c === '/' && $regexAllowed) {
                $start = $i;
                $i++;
                $inClass = false;
                while ($i < $len) {
                    if ($code[$i] === '\\') {
                        $i += 2;
                        continue;
                    }
                    if ($code[$i] === '[') {
                        $inClass = true;
                    } elseif ($code[$i] === ']') {
                        $inClass = false;
                    } elseif ($code[$i] === '/' && !$inClass) {
                        $i++;
                        break;
                    }
                    if ($code[$i] === "\n") {
                        $line++;
                    }
                    $i++;
                }
                while ($i < $len && preg_match('/[a-z]/i', $code[$i])) {
                    $i++;
                }
                $tokens[] = ['t' => 'regex', 'v' => substr($code, $start, $i - $start), 'l' => $line];
                $regexAllowed = false;
                continue;
            }
            if (ctype_digit($c) || ($c === '.' && isset($code[$i + 1]) && ctype_digit($code[$i + 1]))) {
                $start = $i;
                while ($i < $len && preg_match('/[0-9a-fA-FxXeEoObB_.+-]/', $code[$i]) && $code[$i] !== "\n") {
                    $i++;
                }
                $tokens[] = ['t' => 'num', 'v' => substr($code, $start, $i - $start), 'l' => $line];
                $regexAllowed = false;
                continue;
            }
            if (preg_match('/[A-Za-z_$]/', $c)) {
                $start = $i;
                while ($i < $len && preg_match('/[A-Za-z0-9_$]/', $code[$i])) {
                    $i++;
                }
                $tokens[] = ['t' => 'id', 'v' => substr($code, $start, $i - $start), 'l' => $line];
                $regexAllowed = false;
                continue;
            }
            if ($c === '=' && ($code[$i + 1] ?? '') === '>') {
                $tokens[] = ['t' => 'id', 'v' => '=>', 'l' => $line];
                $i += 2;
                $regexAllowed = false;
                continue;
            }
            if ($c === '&' && ($code[$i + 1] ?? '') === '&') {
                $tokens[] = ['t' => 'id', 'v' => '&&', 'l' => $line];
                $i += 2;
                $regexAllowed = false;
                continue;
            }
            if ($c === '|' && ($code[$i + 1] ?? '') === '|') {
                $tokens[] = ['t' => 'id', 'v' => '||', 'l' => $line];
                $i += 2;
                $regexAllowed = false;
                continue;
            }
            if ($c === '?' && ($code[$i + 1] ?? '') === '?') {
                $tokens[] = ['t' => 'id', 'v' => '??', 'l' => $line];
                $i += 2;
                $regexAllowed = false;
                continue;
            }
            if ($c === '?' && ($code[$i + 1] ?? '') === '.') {
                $tokens[] = ['t' => 'id', 'v' => '?.', 'l' => $line];
                $i += 2;
                $regexAllowed = false;
                continue;
            }
            $tokens[] = ['t' => 'p', 'v' => $c, 'l' => $line];
            $regexAllowed = in_array($c, ['(', '[', '{', ',', ';', '=', ':', '!', '&', '|', '?', '+', '-', '*', '%', '<', '>', '~', '^', '?', '/'], true);
            $i++;
        }
        return $tokens;
    }

    /* ------------------------------------------------------------------
     * Structure
     * ---------------------------------------------------------------- */

    /**
     * Match open/close brackets into pairs: pairIdx[open] = close and
     * pairIdx[close] = open.
     *
     * @return array<int, int>
     */
    private static function matchPairs(array $tokens): array {
        $stack = [];
        $pairs = [];
        foreach ($tokens as $i => $tk) {
            if ($tk['t'] === 'p' && in_array($tk['v'], ['(', '[', '{'], true)) {
                $stack[] = [$tk['v'], $i];
            } elseif ($tk['t'] === 'p' && in_array($tk['v'], [')', ']', '}'], true)) {
                $closers = [')' => '(', ']' => '[', '}' => '{'];
                $opener = $closers[$tk['v']];
                $found = null;
                while ($stack) {
                    [$op, $oi] = array_pop($stack);
                    if ($op === $opener) {
                        $found = $oi;
                        break;
                    }
                }
                if ($found !== null) {
                    $pairs[$found] = $i;
                    $pairs[$i] = $found;
                }
            }
        }
        return $pairs;
    }

    /**
     * Build functions, callback registrations, conditional markers and
     * logical chains from the token stream.
     *
     * @return array{
     *   funcs: array<int, array>,
     *   regs: array<int, array>,
     *   conds: array<int, array>,
     *   chains: array<int, array>,
     * }
     */
    private static function structure(array $tokens, array $pairs): array {
        $n = count($tokens);
        $funcs = [];
        $regs = [];
        $conds = [];
        $chains = [];

        for ($i = 0; $i < $n; $i++) {
            $tk = $tokens[$i];
            if ($tk['t'] !== 'id') {
                continue;
            }
            $v = $tk['v'];

            if ($v === 'function') {
                $j = $i + 1;
                $name = '';
                if (($tokens[$j]['t'] ?? '') === 'id') {
                    $name = $tokens[$j]['v'];
                    $j++;
                }
                $bodyOpen = self::skipToBrace($tokens, $j);
                if ($bodyOpen === null) {
                    continue;
                }
                $bodyClose = $pairs[$bodyOpen] ?? null;
                if ($bodyClose === null) {
                    continue;
                }
                $ownReg = self::eventAssignmentReg($tokens, $i);
                $funcs[] = [
                    'idx'       => $i,
                    'name'      => $name,
                    'kind'      => 'decl',
                    'bodyOpen'  => $bodyOpen,
                    'bodyClose' => $bodyClose,
                ];
                if ($ownReg !== null) {
                    $funcs[count($funcs) - 1]['reg'] = $ownReg;
                }
                $i = $bodyOpen; // continue scanning the body (callbacks, nested functions)
                continue;
            }

            if ($v === '=>') {
                $bodyOpen = null;
                $bodyClose = null;
                $j = $i + 1;
                if (($tokens[$j]['t'] ?? '') === 'p' && $tokens[$j]['v'] === '{') {
                    $bodyOpen = $j;
                    $bodyClose = $pairs[$j] ?? null;
                } else {
                    $bodyOpen = $j;
                    $bodyClose = self::expressionEnd($tokens, $j);
                }
                $funcs[] = [
                    'idx'      => $i,
                    'name'     => '',
                    'kind'     => 'arrow',
                    'bodyOpen' => $bodyOpen,
                    'bodyClose' => $bodyClose !== null ? $bodyClose : $j,
                ];
                $ownReg = self::eventAssignmentReg($tokens, $i);
                if ($ownReg !== null) {
                    $funcs[count($funcs) - 1]['reg'] = $ownReg;
                }
                continue;
            }

            // --- callback registrations ---
            $next = ($tokens[$i + 1] ?? null);
            if ($next !== null && $next['t'] === 'p' && $next['v'] === '(') {
                $close = $pairs[$i + 1] ?? null;
                if ($close !== null) {
                    $prev = ($tokens[$i - 1] ?? null);
                    $reg = self::registrationFor($v, $prev, $tokens, $i + 1, $close);
                    if ($reg !== null) {
                        $reg['idx'] = $i;
                        $reg['open'] = $i + 1;
                        $reg['close'] = $close;
                        $regs[] = $reg;
                    }
                }
            }

            // --- conditionals ---
            if (in_array($v, ['if', 'while', 'for', 'else', 'catch', 'case', 'switch', 'try'], true)) {
                $condStart = null;
                $condEnd = null;
                if (in_array($v, ['if', 'while', 'for', 'switch'], true)) {
                    $j = $i + 1;
                    if (($tokens[$j]['t'] ?? '') === 'p' && $tokens[$j]['v'] === '(') {
                        $condStart = $j + 1;
                        $condEnd = $pairs[$j] ?? null;
                    }
                }
                $conds[] = [
                    'idx'       => $i,
                    'type'      => $v,
                    'condStart' => $condStart,
                    'condEnd'   => $condEnd,
                ];
            }

            // --- logical chains (&& / ||) ---
            if ($v === '&&' || $v === '||') {
                $left = self::operandStart($tokens, $i);
                $right = self::operandEnd($tokens, $i, $pairs);
                if ($left !== null && $right !== null) {
                    $chains[] = ['op' => $v, 'left' => $left, 'right' => $right, 'opIdx' => $i];
                }
            }

            // --- ternaries ---
            if ($v === '?') {
                $left = self::operandStart($tokens, $i);
                $colon = self::ternaryColon($tokens, $i, $pairs);
                if ($left !== null && $colon !== null) {
                    $chains[] = ['op' => '?', 'left' => $left, 'right' => $colon, 'opIdx' => $i];
                }
            }
        }

        // attach callback contexts to functions (innermost registration)
        foreach ($funcs as $fi => $func) {
            $best = null;
            foreach ($regs as $reg) {
                if ($reg['open'] < $func['idx'] && $func['idx'] < $reg['close']) {
                    if ($best === null || $reg['open'] > $best['open']) {
                        $best = $reg;
                    }
                }
            }
            if ($best !== null) {
                $funcs[$fi]['reg'] = $best;
            }
        }

        return ['funcs' => $funcs, 'regs' => $regs, 'conds' => $conds, 'chains' => $chains];
    }

    /**
     * What a call-site registration is: setTimeout, addEventListener,
     * jQuery .ready, observers, .then, PHP hooks, .onclick assignment.
     */
    private static function registrationFor(string $name, ?array $prev, array $tokens, int $open, int $close): ?array {
        $inner = self::argTexts($tokens, $open, $close);
        $first = isset($inner[0]) ? trim($inner[0]) : '';
        $second = isset($inner[1]) ? trim($inner[1]) : '';
        $prevT = $prev !== null ? $prev['t'] : '';
        $prevV = $prev !== null ? $prev['v'] : '';

        if (($name === 'setTimeout' || $name === 'setInterval') && ($prevT !== 'p' || $prevV !== '.')) {
            $mode = $name === 'setTimeout' ? 'timer' : 'interval';
            $delay = self::resolveStatic($second, 'js');
            $delayNum = 0;
            if ($delay['resolved'] && is_numeric($delay['value'])) {
                $delayNum = (int) $delay['value'];
            }
            if (($tokens[$open + 1]['t'] ?? '') === 'str') {
                return ['type' => $mode, 'event' => '', 'delay' => $delayNum, 'stringBody' => self::stringContent($tokens[$open + 1]['v']), 'ref' => ''];
            }
            return ['type' => $mode, 'event' => '', 'delay' => $delayNum, 'stringBody' => '', 'ref' => preg_match('/^[A-Za-z_$][A-Za-z0-9_$]*$/', $first) ? $first : ''];
        }
        if ($name === 'requestAnimationFrame') {
            return ['type' => 'raf', 'event' => '', 'delay' => 0, 'stringBody' => '', 'ref' => ''];
        }
        if ($name === 'addEventListener' && $prevT === 'p' && $prevV === '.') {
            $event = self::resolveStatic($first, 'js');
            return ['type' => 'listener', 'event' => $event['resolved'] ? (string) $event['value'] : '', 'delay' => 0, 'stringBody' => '', 'ref' => ''];
        }
        if ($name === 'then' && $prevT === 'p' && $prevV === '.') {
            return ['type' => 'promise', 'event' => '', 'delay' => 0, 'stringBody' => '', 'ref' => ''];
        }
        if ($name === 'ready' && $prevT === 'p' && $prevV === '.') {
            return ['type' => 'ready', 'event' => '', 'delay' => 0, 'stringBody' => '', 'ref' => ''];
        }
        if ($name === 'on' && $prevT === 'p' && $prevV === '.') {
            $event = self::resolveStatic($first, 'js');
            return ['type' => 'listener', 'event' => $event['resolved'] ? (string) $event['value'] : '', 'delay' => 0, 'stringBody' => '', 'ref' => ''];
        }
        if (in_array($name, ['click', 'submit', 'change', 'keyup', 'keydown', 'keypress', 'mouseover', 'mouseout', 'mousedown', 'mouseup', 'scroll', 'resize', 'focus', 'blur', 'input', 'load', 'dblclick', 'touchstart', 'touchend', 'hover'], true) && $prevT === 'p' && $prevV === '.') {
            return ['type' => 'listener', 'event' => $name, 'delay' => 0, 'stringBody' => '', 'ref' => ''];
        }
        if ($name === '$' || $name === 'jQuery') {
            $firstTok = ($tokens[$open + 1] ?? null);
            if ($firstTok !== null && $firstTok['t'] === 'id' && $firstTok['v'] === 'function') {
                return ['type' => 'ready', 'event' => '', 'delay' => 0, 'stringBody' => '', 'ref' => ''];
            }
        }
        if ($name === 'MutationObserver' || $name === 'IntersectionObserver') {
            return ['type' => 'observer', 'event' => '', 'delay' => 0, 'stringBody' => '', 'ref' => ''];
        }
        if ($name === 'add_action' || $name === 'add_filter') {
            $hook = self::resolveStatic($first, 'php');
            return ['type' => 'hook', 'event' => $hook['resolved'] ? (string) $hook['value'] : '', 'delay' => 0, 'stringBody' => '', 'ref' => ''];
        }
        if ($name === 'register_rest_route') {
            return ['type' => 'rest', 'event' => '', 'delay' => 0, 'stringBody' => '', 'ref' => ''];
        }
        if ($name === 'observe') {
            return ['type' => 'observer', 'event' => '', 'delay' => 0, 'stringBody' => '', 'ref' => ''];
        }
        return null;
    }

    /**
     * `btn.onclick = function/arrow` => user-interaction listener reg.
     */
    private static function eventAssignmentReg(array $tokens, int $fnIdx): ?array {
        $p1 = ($tokens[$fnIdx - 1] ?? null);
        $p2 = ($tokens[$fnIdx - 2] ?? null);
        $p3 = ($tokens[$fnIdx - 3] ?? null);
        if ($p1 !== null && $p1['t'] === 'p' && $p1['v'] === '=' &&
            $p2 !== null && $p2['t'] === 'id' && strpos($p2['v'], 'on') === 0 &&
            $p3 !== null && $p3['t'] === 'p' && $p3['v'] === '.') {
            return ['type' => 'listener', 'event' => substr($p2['v'], 2), 'delay' => 0, 'stringBody' => '', 'ref' => ''];
        }
        return null;
    }

    /**
     * Split call arguments on top-level commas.
     */
    private static function argTexts(array $tokens, int $open, int $close): array {
        $out = [];
        $depth = 0;
        $cur = [];
        for ($i = $open + 1; $i < $close; $i++) {
            $tk = $tokens[$i];
            if ($tk['t'] === 'p' && in_array($tk['v'], ['(', '[', '{'], true)) {
                $depth++;
            } elseif ($tk['t'] === 'p' && in_array($tk['v'], [')', ']', '}'], true)) {
                $depth--;
            }
            if ($depth === 0 && $tk['t'] === 'p' && $tk['v'] === ',') {
                $out[] = self::tokensToText($tokens, $cur);
                $cur = [];
                continue;
            }
            $cur[] = $i;
        }
        if ($cur) {
            $out[] = self::tokensToText($tokens, $cur);
        }
        return $out;
    }

    /* ------------------------------------------------------------------
     * Primitives
     * ---------------------------------------------------------------- */

    /**
     * Locate every redirect / eval primitive with statement bounds.
     *
     * @return array<int, array{method: string, idx: int, line: int, argStart: int, argEnd: int, stmtStart: int, stmtEnd: int}>
     */
    private static function detectPrimitives(array $tokens, array $pairs, string $lang): array {
        $out = [];
        $n = count($tokens);
        for ($i = 0; $i < $n; $i++) {
            $tk = $tokens[$i];
            if ($tk['t'] !== 'id') {
                continue;
            }
            $v = $tk['v'];
            $prev = ($tokens[$i - 1] ?? null);
            $prevDot = $prev !== null && $prev['t'] === 'p' && $prev['v'] === '.';
            $next = ($tokens[$i + 1] ?? null);
            $isCall = $next !== null && $next['t'] === 'p' && $next['v'] === '(';
            $callClose = $isCall ? ($pairs[$i + 1] ?? null) : null;

            $method = '';
            $argStart = null;
            $argEnd = null;

            if ($lang === 'js') {
                if ($v === 'location' && !$prevDot) {
                    if (($tokens[$i + 1]['t'] ?? '') === 'p' && $tokens[$i + 1]['v'] === '=') {
                        $method = 'location=';
                        $argStart = $i + 2;
                        $argEnd = self::statementEnd($tokens, $i);
                    }
                } elseif (($v === 'location' || $v === 'href') && $prevDot) {
                    $parent = ($tokens[$i - 2] ?? null);
                    $parentName = $parent !== null && $parent['t'] === 'id' ? $parent['v'] : '';
                    if ($v === 'location' && in_array($parentName, ['window', 'document'], true) && !$isCall) {
                        if (($tokens[$i + 1]['t'] ?? '') === 'p' && $tokens[$i + 1]['v'] === '=') {
                            $method = $parentName . '.location=';
                            $argStart = $i + 2;
                            $argEnd = self::statementEnd($tokens, $i);
                        }
                    } elseif ($v === 'href' && in_array($parentName, ['window', 'document', 'location'], true)) {
                        if (($tokens[$i + 1]['t'] ?? '') === 'p' && $tokens[$i + 1]['v'] === '=') {
                            $method = 'location.href=';
                            $argStart = $i + 2;
                            $argEnd = self::statementEnd($tokens, $i);
                        }
                    }
                } elseif ($v === 'replace' && $prevDot && $isCall) {
                    $parent = ($tokens[$i - 2] ?? null);
                    if ($parent !== null && $parent['t'] === 'id' && in_array($parent['v'], ['location', 'href'], true)) {
                        $method = 'location.replace()';
                        $argStart = $i + 2;
                        $argEnd = $callClose ?? $i + 1;
                    }
                } elseif ($v === 'assign' && $prevDot && $isCall) {
                    $parent = ($tokens[$i - 2] ?? null);
                    if ($parent !== null && $parent['t'] === 'id' && in_array($parent['v'], ['location', 'href'], true)) {
                        $method = 'location.assign()';
                        $argStart = $i + 2;
                        $argEnd = $callClose ?? $i + 1;
                    }
                } elseif ($v === 'open' && $prevDot && $isCall) {
                    $parent = ($tokens[$i - 2] ?? null);
                    if ($parent !== null && $parent['t'] === 'id' && in_array($parent['v'], ['window', 'document'], true)) {
                        $method = 'window.open()';
                        $argStart = $i + 2;
                        $argEnd = $callClose ?? $i + 1;
                    }
                }
            } else {
                if ($v === 'wp_redirect' && $isCall) {
                    $method = 'wp_redirect()';
                    $argStart = $i + 2;
                    $argEnd = $callClose ?? $i + 1;
                } elseif ($v === 'wp_safe_redirect' && $isCall) {
                    $method = 'wp_safe_redirect()';
                    $argStart = $i + 2;
                    $argEnd = $callClose ?? $i + 1;
                } elseif ($v === 'header' && $isCall) {
                    $method = 'header()';
                    $argStart = $i + 2;
                    $argEnd = $callClose ?? $i + 1;
                }
            }

            if ($v === 'eval' && $isCall) {
                $method = 'eval()';
                $argStart = $i + 2;
                $argEnd = $callClose ?? $i + 1;
            } elseif ($v === 'Function' && $isCall) {
                $twoBack = ($tokens[$i - 2] ?? null);
                $isNew = $prev !== null && $prev['t'] === 'id' && $prev['v'] === 'new';
                if ($isNew || $twoBack === null || ($twoBack['t'] === 'p' && in_array($twoBack['v'], ['(', ',', '=', ':', '[', '{', '!'], true))) {
                    $method = 'Function()';
                    $argStart = $i + 2;
                    $argEnd = $callClose ?? $i + 1;
                }
            }

            if ($method === '') {
                continue;
            }

            $line = (int) $tk['l'];
            $stmtStart = self::statementStart($tokens, $i);
            $stmtEnd = $argEnd !== null ? self::statementEnd($tokens, $argEnd - 1) : $i;

            // header(): extract Location/Refresh destination from first arg
            if ($method === 'header()') {
                $inner = self::tokensToText($tokens, range($argStart, $argEnd - 1));
                $inner = self::decodeLiteral(trim($inner));
                if (preg_match('~^Location\s*:\s*(.*)$~i', $inner, $m)) {
                    $method = 'header(Location)';
                    $argStart = -1;
                    $argEnd = -1;
                    $out[] = ['method' => $method, 'idx' => $i, 'line' => $line, 'argStart' => -1, 'argEnd' => -1, 'stmtStart' => $stmtStart, 'stmtEnd' => $stmtEnd, 'rawDest' => trim($m[1])];
                    continue;
                }
                if (preg_match('~^Refresh\s*:\s*[^;]*url\s*=\s*(.*)$~i', $inner, $m)) {
                    $method = 'header(Refresh)';
                    $out[] = ['method' => $method, 'idx' => $i, 'line' => $line, 'argStart' => -1, 'argEnd' => -1, 'stmtStart' => $stmtStart, 'stmtEnd' => $stmtEnd, 'rawDest' => trim($m[1])];
                    continue;
                }
                continue;
            }

            $out[] = ['method' => $method, 'idx' => $i, 'line' => $line, 'argStart' => $argStart ?? $i, 'argEnd' => $argEnd ?? $i, 'stmtStart' => $stmtStart, 'stmtEnd' => $stmtEnd];
        }
        return $out;
    }

    /* ------------------------------------------------------------------
     * Per-primitive classification
     * ---------------------------------------------------------------- */

    private static function classifyPrimitive(array $primitive, array $tokens, array $pairs, array $struct, string $path, string $lang, ?array $forcedExec = null): ?array {        $idx = $primitive['idx'];

        $func = self::enclosingFunction($struct['funcs'], $idx);
        $exec = $forcedExec !== null ? $forcedExec : self::executionMode($func, $tokens, $pairs, $struct, $lang);
        $context = self::contextInfo($func, $tokens, $struct, $lang);

        $chain = self::enclosingChain($struct['chains'], $idx, $tokens);
        $cond = self::enclosingCondition($struct['conds'], $idx, $tokens, $pairs);
        $conditionText = '';
        if ($chain !== null) {
            $conditionText = self::tokensToText($tokens, range($chain['left'], $chain['opIdx'] - 1));
        } elseif ($cond !== null && $cond['condStart'] !== null && $cond['condEnd'] !== null) {
            $conditionText = self::tokensToText($tokens, range($cond['condStart'], $cond['condEnd'] - 1));
        }
        $conditional = ($chain !== null || $cond !== null);
        $mobileGated = $conditional && self::isMobileCondition($conditionText);

        $isRedirect = in_array($primitive['method'], self::REDIRECT_METHODS, true);

        $dest = isset($primitive['rawDest']) ? $primitive['rawDest'] : '';
        $resolved = isset($primitive['rawDest']);
        $obfuscated = false;

        if ($isRedirect) {
            if (!isset($primitive['rawDest'])) {
                $argText = self::tokensToText($tokens, range($primitive['argStart'], max($primitive['argStart'], $primitive['argEnd'] - 1)));
                $resolution = self::resolveDestination($argText, $lang);
                $dest = (string) $resolution['dest'];
                $resolved = (bool) $resolution['resolved'];
                $obfuscated = (bool) $resolution['obfuscated'];
                $primitive['argText'] = $argText;
            }
            $result = self::classifyRedirect($primitive, $dest, $resolved, $obfuscated, $exec, $context, $conditional, $mobileGated, $conditionText, $path, $lang);
        } else {
            $argText = self::tokensToText($tokens, range($primitive['argStart'], max($primitive['argStart'], $primitive['argEnd'] - 1)));
            $result = self::classifyEval($primitive, $argText, $exec, $context, $conditional, $mobileGated, $path, $lang);
        }

        if ($result === null) {
            return null;
        }

        $stmtText = self::tokensToText($tokens, range($primitive['stmtStart'], max($primitive['stmtStart'], $primitive['stmtEnd'])));
        $result['path'] = $path;
        $result['line'] = $primitive['line'];
        $result['call'] = $primitive['method'];
        $result['method'] = $primitive['method'];
        $result['function'] = $func !== null ? ($func['name'] !== '' ? $func['name'] : '(anonymous)') : '(top-level)';
        $result['note'] = $result['reason'];
        $result['snippet'] = substr(trim($stmtText), 0, 400);
        return $result;
    }

    private static function classifyRedirect(array $primitive, string $dest, bool $resolved, bool $obfuscated, array $exec, array $context, bool $conditional, bool $mobileGated, string $conditionText, string $path, string $lang): ?array {
        $origin = RedirectEngine::originOf($path);
        $trusted = self::sourceTrusted($origin);

        $destFlags = self::destFlags($dest, $lang);
        $internal = (bool) $destFlags['internal'];
        $external = (bool) $destFlags['external'];
        $opaque = !$resolved || ($dest === '' && !$destFlags['scheme']);

        // Deny list (google.com, t.co, ushort.company): always critical, any execution
        // mode, any source — the destination itself is the malware.
        $denied = RedirectEngine::deniedHost($dest);
        if ($denied !== '') {
            return self::buildResult(
                RedirectEngine::MALICIOUS,
                'critical',
                self::CONFIDENCE_CRITICAL,
                'Redirect to denied host ' . $denied,
                $primitive,
                $exec,
                $context,
                $conditional,
                $mobileGated,
                100,
                100,
                $obfuscated ? 40 : 0,
                100,
                $dest,
                $resolved,
                $obfuscated,
                $origin
            );
        }

        $execution = $exec['mode'];
        $automatic = in_array($execution, ['immediate', 'iife', 'timer', 'interval', 'raf', 'ready', 'ready-dom', 'observer', 'hook-frontend', 'hook-ajax', 'hook-rest', 'hook-cron'], true);
        $interaction = $execution === 'interaction';
        $never = $execution === 'never';

        if ($internal || !$external) {
            $sev = $execution === 'never' ? 'info' : ($interaction ? 'safe' : 'info');
            $class = ($destFlags['relative'] ?? false) ? RedirectEngine::SAFE : RedirectEngine::EXPECTED;
            if ($interaction) {
                $class = RedirectEngine::SAFE;
                $sev = 'safe';
            }
            return self::buildResult(
                $class,
                $sev,
                self::CONFIDENCE_LOW,
                'Internal or same-site destination' . ($dest !== '' && $dest !== '__wp_internal__' ? ': ' . self::cut($dest, 120) : ''),
                $primitive,
                $exec,
                $context,
                $conditional,
                $mobileGated,
                0,
                0,
                0,
                0,
                $dest === '__wp_internal__' ? '' : $dest,
                $resolved,
                $obfuscated,
                $origin
            );
        }

        // --- Verified (official/trusted) sources: external redirects are
        // normal code — support links, upsells, oembed, bundler chunk
        // loaders. Wordfence never flags them. Obfuscation inside a
        // verified package is minified-bundle noise (atob/fromCharCode
        // is ubiquitous in webpack output), so it stays an inspectable
        // warning instead of an accusation. ---
        if ($trusted) {
            if ($obfuscated) {
                return self::buildResult(
                    RedirectEngine::SUSPICIOUS,
                    'warning',
                    self::CONFIDENCE_MEDIUM,
                    'Obfuscated external redirect from a verified source (' . $exec['trigger'] . ')',
                    $primitive,
                    $exec,
                    $context,
                    $conditional,
                    $mobileGated,
                    60,
                    75,
                    40,
                    55,
                    $dest,
                    $resolved,
                    $obfuscated,
                    $origin
                );
            }
            return self::buildResult(
                RedirectEngine::EXPECTED,
                'info',
                self::CONFIDENCE_LOW,
                'External redirect from a verified source (' . $exec['trigger'] . ')',
                $primitive,
                $exec,
                $context,
                $conditional,
                $mobileGated,
                0,
                0,
                0,
                0,
                $dest,
                $resolved,
                $obfuscated,
                $origin
            );
        }

        // --- Unverified sources from here on ---

        if ($mobileGated) {
            if ($never) {
                return self::buildResult(
                    RedirectEngine::SUSPICIOUS,
                    'warning',
                    self::CONFIDENCE_MEDIUM,
                    'Mobile-gated external redirect inside a function that is never invoked automatically',
                    $primitive,
                    $exec,
                    $context,
                    $conditional,
                    $mobileGated,
                    5,
                    90,
                    $obfuscated ? 40 : 0,
                    40,
                    $dest,
                    $resolved,
                    $obfuscated,
                    $origin
                );
            }
            if ($obfuscated) {
                return self::buildResult(
                    RedirectEngine::MALICIOUS,
                    'critical',
                    self::CONFIDENCE_HIGH,
                    'Obfuscated automatic external redirect gated by mobile detection (matchMedia/userAgent)',
                    $primitive,
                    $exec,
                    $context,
                    $conditional,
                    $mobileGated,
                    100,
                    95,
                    40,
                    100,
                    $dest,
                    $resolved,
                    $obfuscated,
                    $origin
                );
            }
            return self::buildResult(
                RedirectEngine::SUSPICIOUS,
                'warning',
                self::CONFIDENCE_MEDIUM,
                'Automatic external redirect gated by mobile detection (matchMedia/userAgent)',
                $primitive,
                $exec,
                $context,
                $conditional,
                $mobileGated,
                100,
                90,
                0,
                70,
                $dest,
                $resolved,
                $obfuscated,
                $origin
            );
        }

        if ($never) {
            return self::buildResult(
                RedirectEngine::SUSPICIOUS,
                'info',
                self::CONFIDENCE_LOW,
                'External redirect inside a function that is never invoked automatically',
                $primitive,
                $exec,
                $context,
                $conditional,
                $mobileGated,
                5,
                75,
                $obfuscated ? 40 : 0,
                20,
                $dest,
                $resolved,
                $obfuscated,
                $origin
            );
        }

        if ($interaction) {
            return self::buildResult(
                RedirectEngine::SUSPICIOUS,
                'warning',
                self::CONFIDENCE_MEDIUM,
                'External redirect after user interaction from an unverified source',
                $primitive,
                $exec,
                $context,
                $conditional,
                $mobileGated,
                10,
                75,
                $obfuscated ? 40 : 0,
                55,
                $dest,
                $resolved,
                $obfuscated,
                $origin
            );
        }

        if ($execution === 'immediate' || $execution === 'iife' || $execution === 'timer' || $execution === 'interval' || $execution === 'raf') {
            if ($obfuscated) {
                return self::buildResult(
                    RedirectEngine::MALICIOUS,
                    'critical',
                    self::CONFIDENCE_CRITICAL,
                    'Automatic obfuscated external redirect: ' . $exec['trigger'] . ' — no user interaction required',
                    $primitive,
                    $exec,
                    $context,
                    $conditional,
                    $mobileGated,
                    100,
                    90,
                    40,
                    100,
                    $dest,
                    $resolved,
                    $obfuscated,
                    $origin
                );
            }
            return self::buildResult(
                RedirectEngine::SUSPICIOUS,
                'warning',
                self::CONFIDENCE_MEDIUM,
                'Automatic external redirect: ' . $exec['trigger'] . ' — no user interaction required',
                $primitive,
                $exec,
                $context,
                $conditional,
                $mobileGated,
                100,
                90,
                0,
                65,
                $dest,
                $resolved,
                $obfuscated,
                $origin
            );
        }

        if ($execution === 'hook-admin' || $execution === 'hook-login') {
            return self::buildResult(
                RedirectEngine::MALICIOUS,
                'warning',
                self::CONFIDENCE_MEDIUM,
                'External redirect from an admin/login-side hook (' . $context['hook'] . ')',
                $primitive,
                $exec,
                $context,
                $conditional,
                $mobileGated,
                30,
                75,
                $obfuscated ? 40 : 0,
                50,
                $dest,
                $resolved,
                $obfuscated,
                $origin
            );
        }

        if ($automatic) {
            return self::buildResult(
                RedirectEngine::SUSPICIOUS,
                'warning',
                self::CONFIDENCE_MEDIUM,
                'Automatic external redirect (' . $exec['trigger'] . ')',
                $primitive,
                $exec,
                $context,
                $conditional,
                $mobileGated,
                70,
                75,
                $obfuscated ? 40 : 0,
                60,
                $dest,
                $resolved,
                $obfuscated,
                $origin
            );
        }

        return self::buildResult(
            RedirectEngine::SUSPICIOUS,
            'warning',
            self::CONFIDENCE_MEDIUM,
            'External redirect with deferred or uncertain execution (' . $exec['trigger'] . ')',
            $primitive,
            $exec,
            $context,
            $conditional,
            $mobileGated,
            50,
            75,
            $obfuscated ? 40 : 0,
            60,
            $dest,
            $resolved,
            $obfuscated,
            $origin
        );
    }

    private static function classifyEval(array $primitive, string $argText, array $exec, array $context, bool $conditional, bool $mobileGated, string $path, string $lang): ?array {
        $origin = RedirectEngine::originOf($path);
        $static = self::resolveDestination($argText, $lang);
        $decodedPayload = $static['resolved'] && $static['dest'] !== '' && $static['obfuscated'];

        $execution = $exec['mode'];
        $automatic = in_array($execution, ['immediate', 'iife', 'timer', 'interval', 'raf', 'ready', 'ready-dom', 'observer', 'hook-frontend', 'hook-ajax', 'hook-rest', 'hook-cron'], true);

        // Trusted plugin/theme code executes Function()/eval as bundler
        // boilerplate (webpack `new Function("return this")` runtime,
        // module loaders). Without a statically decodable payload this is
        // an expected pattern, not a finding. An encoded payload inside
        // trusted code stays malicious — obfuscation hides intent.
        if (self::sourceTrusted($origin) && !$decodedPayload) {
            return self::buildResult(
                RedirectEngine::EXPECTED,
                'info',
                self::CONFIDENCE_LOW,
                'Dynamic code execution (' . $primitive['method'] . ') in trusted source (' . (!empty($origin['plugin']) ? 'plugin: ' . $origin['plugin'] : (!empty($origin['theme']) ? 'theme: ' . $origin['theme'] : 'source')) . ')',
                $primitive,
                $exec,
                $context,
                $conditional,
                $mobileGated,
                20,
                0,
                $automatic ? 15 : 20,
                $automatic ? 10 : 15,
                '',
                false,
                true,
                $origin
            );
        }

        if (!$automatic) {
            return self::buildResult(
                RedirectEngine::SUSPICIOUS,
                'info',
                self::CONFIDENCE_LOW,
                'Dynamic code execution (' . $primitive['method'] . ') inside ' . $exec['trigger'],
                $primitive,
                $exec,
                $context,
                $conditional,
                $mobileGated,
                $execution === 'never' ? 5 : 30,
                0,
                60,
                $execution === 'never' ? 10 : 35,
                '',
                false,
                true,
                $origin
            );
        }

        return self::buildResult(
            RedirectEngine::MALICIOUS,
            'warning',
            $decodedPayload ? self::CONFIDENCE_HIGH : self::CONFIDENCE_MEDIUM,
            'Dynamic code execution (' . $primitive['method'] . ') at ' . $exec['trigger'] . ($decodedPayload ? ' with a statically decodable payload' : ''),
            $primitive,
            $exec,
            $context,
            $conditional,
            $mobileGated,
            $automatic ? 75 : 40,
            0,
            $decodedPayload ? 100 : 70,
            $automatic ? 70 : 45,
            '',
            $decodedPayload,
            true,
            $origin
        );
    }

    /**
     * Assemble a standardized finding.
     */
    private static function buildResult(string $class, string $severity, string $confidence, string $reason, array $primitive, array $exec, array $context, bool $conditional, bool $mobileGated, int $execScore, int $redirectScore, int $obfScore, int $behaviorScore, string $dest, bool $resolved, bool $obfuscated, array $origin): array {
        $risk = (int) round(0.30 * $execScore + 0.30 * $redirectScore + 0.15 * $obfScore + 0.25 * $behaviorScore);
        return [
            'class'      => $class,
            'severity'   => $severity,
            'confidence' => $confidence,
            'reason'     => $reason,
            'action'     => self::actionFor($confidence),
            'trigger'    => $exec['trigger'],
            'dest'       => $dest,
            'resolved'   => $resolved,
            'obfuscated' => $obfuscated,
            'scores'     => [
                'execution'   => $execScore,
                'redirect'    => $redirectScore,
                'obfuscation' => $obfScore,
                'behavior'    => $behaviorScore,
                'risk'        => $risk,
            ],
            'context'    => array_merge($context, [
                'conditional'  => $conditional,
                'mobile_gated' => $mobileGated,
                'suspicious'   => $class === RedirectEngine::MALICIOUS || $class === RedirectEngine::SUSPICIOUS,
            ]),
            'origin'     => $origin,
        ];
    }

    /* ------------------------------------------------------------------
     * Execution mode
     * ---------------------------------------------------------------- */

    private static function enclosingFunction(array $funcs, int $idx): ?array {
        $best = null;
        foreach ($funcs as $func) {
            if ($func['bodyOpen'] < $idx && $idx < $func['bodyClose']) {
                if ($best === null || $func['bodyOpen'] > $best['bodyOpen']) {
                    $best = $func;
                }
            }
        }
        return $best;
    }

    /**
     * How/when a function (or top-level code) executes.
     *
     * @return array{mode: string, trigger: string}
     */
    private static function executionMode(?array $func, array $tokens, array $pairs, array $struct, string $lang): array {
        if ($func === null) {
            return ['mode' => 'immediate', 'trigger' => 'top-level immediate execution'];
        }

        if (!empty($func['reg'])) {
            return self::modeFromReg($func['reg'], $lang);
        }

        // named function passed by reference to a timer/listener/observer
        if ($func['name'] !== '') {
            foreach ($struct['regs'] as $reg) {
                if (!empty($reg['ref']) && $reg['ref'] === $func['name']) {
                    return self::modeFromReg($reg, $lang);
                }
            }
        }

        // IIFE: `function(){...}()`, `(function(){...})()`, `!function(){...}()`
        $afterClose = ($tokens[$func['bodyClose'] + 1] ?? null);
        if ($afterClose !== null && $afterClose['t'] === 'p' && $afterClose['v'] === '(') {
            return ['mode' => 'iife', 'trigger' => 'immediate execution via IIFE'];
        }
        $pre = ($tokens[$func['idx'] - 1] ?? null);
        if ($pre !== null && $pre['t'] === 'p' && $pre['v'] === '(') {
            $groupClose = $pairs[$func['idx'] - 1] ?? null;
            if ($groupClose !== null && (($tokens[$groupClose + 1] ?? null)['v'] ?? '') === '(') {
                return ['mode' => 'iife', 'trigger' => 'immediate execution via IIFE'];
            }
        }

        if ($func['kind'] === 'decl' || ($func['kind'] === 'arrow' && $func['name'] === '')) {
            if (self::isReferenced($func['name'], $struct, $tokens, $func['idx'])) {
                return ['mode' => 'unknown-deferred', 'trigger' => 'invoked as ' . ($func['name'] !== '' ? 'function ' . $func['name'] : 'an anonymous callback')];
            }
            return ['mode' => 'never', 'trigger' => 'never invoked automatically'];
        }

        return ['mode' => 'unknown-deferred', 'trigger' => 'inside a function with deferred execution'];
    }

    private static function modeFromReg(array $reg, string $lang): array {
        switch ($reg['type']) {
            case 'timer':
                $delay = (int) ($reg['delay'] ?? 0);
                return ['mode' => 'timer', 'trigger' => 'delayed ' . $delay . ' ms via setTimeout'];
            case 'interval':
                return ['mode' => 'interval', 'trigger' => 'repeated via setInterval'];
            case 'raf':
                return ['mode' => 'raf', 'trigger' => 'deferred via requestAnimationFrame'];
            case 'ready':
                return ['mode' => 'ready', 'trigger' => 'on jQuery document ready'];
            case 'listener':
                $event = (string) ($reg['event'] ?? '');
                if (preg_match('/^(?:click|submit|change|keyup|keydown|keypress|mouseover|mouseout|mousedown|mouseup|scroll|resize|focus|blur|input|dblclick|touchstart|touchend|hover)$/i', $event) === 1) {
                    return ['mode' => 'interaction', 'trigger' => 'after user ' . strtolower($event) . ' interaction'];
                }
                if (stripos($event, 'load') !== false || stripos($event, 'DOMContentLoaded') !== false || $event === '') {
                    return ['mode' => 'ready-dom', 'trigger' => 'on document ' . ($event !== '' ? $event : 'load/ready')];
                }
                return ['mode' => 'interaction', 'trigger' => 'after ' . ($event !== '' ? $event : 'browser') . ' event'];
            case 'observer':
                return ['mode' => 'observer', 'trigger' => 'triggered by DOM MutationObserver/IntersectionObserver'];
            case 'promise':
                return ['mode' => 'promise', 'trigger' => 'deferred via promise .then()'];
            case 'hook':
                return self::hookExecution($reg, $lang);
            case 'rest':
                return ['mode' => 'hook-rest', 'trigger' => 'as a REST route callback (public endpoint)'];
            default:
                return ['mode' => 'unknown-deferred', 'trigger' => 'inside a registered callback'];
        }
    }

    private static function hookExecution(array $reg, string $lang): array {
        $hook = (string) ($reg['event'] ?? '');
        if ($hook === '') {
            return ['mode' => 'hook-frontend', 'trigger' => 'as a WordPress hook callback'];
        }
        if (preg_match('/^admin_/i', $hook) || preg_match('/(?:admin|dashboard|update-|plugin|theme|user|site)-/i', $hook)) {
            return ['mode' => 'hook-admin', 'trigger' => 'admin-side hook ' . $hook];
        }
        if (preg_match('/^wp_ajax/i', $hook)) {
            return ['mode' => 'hook-ajax', 'trigger' => 'AJAX endpoint hook ' . $hook];
        }
        if (preg_match('/^rest_/i', $hook) || preg_match('/rest_pre/i', $hook)) {
            return ['mode' => 'hook-rest', 'trigger' => 'REST hook ' . $hook];
        }
        if (preg_match('/^wp_cron/i', $hook) || preg_match('/cron/i', $hook)) {
            return ['mode' => 'hook-cron', 'trigger' => 'cron hook ' . $hook];
        }
        if (preg_match('/^wp_login/i', $hook) || preg_match('/^login/i', $hook)) {
            return ['mode' => 'hook-login', 'trigger' => 'login-side hook ' . $hook];
        }
        return ['mode' => 'hook-frontend', 'trigger' => 'frontend hook ' . $hook];
    }

    /**
     * Context labels for the report (admin/frontend/ajax/rest/cron flags).
     */
    private static function contextInfo(?array $func, array $tokens, array $struct, string $lang): array {
        $ctx = [
            'admin_only'    => false,
            'frontend_only' => false,
            'ajax_only'     => false,
            'rest_only'     => false,
            'mobile_only'   => false,
            'execution'     => 'immediate',
            'timing'        => 'top-level',
            'wrapper'       => 'none',
            'function'      => '',
            'hook'          => '',
            'obfuscated'    => false,
        ];
        if ($func === null) {
            return $ctx;
        }
        $ctx['function'] = $func['name'] !== '' ? $func['name'] : '(anonymous)';
        if (!empty($func['reg'])) {
            $reg = $func['reg'];
            $ctx['wrapper'] = $reg['type'];
            if ($reg['type'] === 'hook') {
                $hook = (string) ($reg['event'] ?? '');
                $ctx['hook'] = $hook;
                if (preg_match('/^admin_/i', $hook) || preg_match('/(?:admin|dashboard|plugin|theme|update)-/i', $hook)) {
                    $ctx['admin_only'] = true;
                } elseif (preg_match('/^wp_ajax/i', $hook)) {
                    $ctx['ajax_only'] = true;
                } elseif (preg_match('/^rest_/i', $hook)) {
                    $ctx['rest_only'] = true;
                } else {
                    $ctx['frontend_only'] = true;
                }
            } elseif ($reg['type'] === 'rest') {
                $ctx['rest_only'] = true;
            } elseif ($reg['type'] === 'listener') {
                $event = (string) ($reg['event'] ?? '');
                if (preg_match('/^(?:click|submit|change|keyup|keydown|keypress|mouseover|mouseout|mousedown|mouseup|scroll|resize|focus|blur|input|dblclick|touchstart|touchend|hover)$/i', $event) === 1) {
                    $ctx['execution'] = 'interaction';
                    $ctx['timing'] = 'user-' . strtolower($event);
                } else {
                    $ctx['execution'] = 'deferred';
                    $ctx['timing'] = $event !== '' ? $event : 'document-ready';
                }
            } elseif ($reg['type'] === 'timer' || $reg['type'] === 'interval' || $reg['type'] === 'raf') {
                $ctx['execution'] = 'deferred';
                $ctx['timing'] = $reg['type'] === 'timer' ? 'setTimeout(' . (int) ($reg['delay'] ?? 0) . 'ms)' : $reg['type'];
            } elseif ($reg['type'] === 'observer') {
                $ctx['execution'] = 'deferred';
                $ctx['timing'] = 'observer';
            } else {
                $ctx['execution'] = 'deferred';
                $ctx['timing'] = $reg['type'];
            }
        } elseif ($func['kind'] === 'decl') {
            $ctx['execution'] = self::isReferenced($func['name'], $struct, $tokens, $func['idx']) ? 'deferred' : 'never';
            $ctx['timing'] = $ctx['execution'] === 'never' ? 'function never invoked' : 'function invoked elsewhere';
        } elseif ($func['kind'] === 'arrow') {
            $ctx['execution'] = 'deferred';
            $ctx['timing'] = 'anonymous arrow function';
        }
        return $ctx;
    }

    /**
     * Is a named function referenced (called or passed) anywhere?
     */
    private static function isReferenced(string $name, array $struct, array $tokens, int $ownIdx): bool {
        if ($name === '') {
            return true;
        }
        foreach ($struct['regs'] as $reg) {
            if (!empty($reg['ref']) && $reg['ref'] === $name) {
                return true;
            }
        }
        $n = count($tokens);
        for ($i = 0; $i < $n; $i++) {
            if ($i === $ownIdx || $i === $ownIdx + 1) {
                continue;
            }
            if ($tokens[$i]['t'] === 'id' && $tokens[$i]['v'] === $name) {
                $next = ($tokens[$i + 1] ?? null);
                $prev = ($tokens[$i - 1] ?? null);
                $notMethod = $prev === null || !($prev['t'] === 'p' && $prev['v'] === '.');
                if ($next !== null && $next['t'] === 'p' && $next['v'] === '(' && $notMethod) {
                    return true;
                }
                if ($prev !== null && $prev['t'] === 'p' && $prev['v'] === '=') {
                    return true;
                }
            }
        }
        return false;
    }

    /* ------------------------------------------------------------------
     * Conditions
     * ---------------------------------------------------------------- */

    private static function enclosingChain(array $chains, int $idx, array $tokens): ?array {
        $best = null;
        foreach ($chains as $chain) {
            if ($chain['left'] <= $idx && $idx <= $chain['right']) {
                if ($best === null || $chain['opIdx'] > $best['opIdx']) {
                    $best = $chain;
                }
            }
        }
        return $best;
    }

    private static function enclosingCondition(array $conds, int $idx, array $tokens, array $pairs): ?array {
        $best = null;
        foreach ($conds as $cond) {
            $start = $cond['idx'];
            $end = null;
            if ($cond['condEnd'] !== null) {
                $end = $cond['condEnd'];
            } else {
                $end = self::conditionBodyEnd($tokens, $pairs, $cond['idx']);
            }
            if ($end === null) {
                continue;
            }
            if ($start < $idx && $idx < $end) {
                if ($best === null || $start > $best['idx']) {
                    $best = $cond;
                }
            }
        }
        return $best;
    }

    private static function conditionBodyEnd(array $tokens, array $pairs, int $condIdx): ?int {
        // if/else/case bodies: find the next statement boundary at depth 0
        $n = count($tokens);
        $depth = 0;
        for ($i = $condIdx + 1; $i < $n; $i++) {
            $tk = $tokens[$i];
            if ($tk['t'] === 'p' && in_array($tk['v'], ['(', '[', '{'], true)) {
                $depth++;
                if ($tk['v'] === '{') {
                    return $pairs[$i] ?? null;
                }
            } elseif ($tk['t'] === 'p' && in_array($tk['v'], [')', ']', '}'], true)) {
                $depth--;
            }
            if ($depth === 0 && $tk['t'] === 'p' && ($tk['v'] === ';' || $tk['v'] === '{')) {
                return $i;
            }
        }
        return null;
    }

    private static function isMobileCondition(string $text): bool {
        if ($text === '') {
            return false;
        }
        return preg_match(
            '~matchMedia\s*\(\s*["\'][^"\']*(?:pointer\s*:\s*coarse|hover\s*:\s*none|any-pointer\s*:\s*coarse|any-hover\s*:\s*none|max-width|max-device-width)[^"\']*["\']'
            . '|navigator\s*\.\s*userAgent'
            . '|navigator\s*\.\s*platform'
            . '|screen\s*\.\s*(?:width|height|availWidth|availHeight)'
            . '|window\s*\.\s*orientation'
            . '|\b(?:Android|iPhone|iPad|iPod|Mobile|Tablet|Windows\s*Phone|Opera\s*Mini|Mobi|BlackBerry|Symbian)\b'
            . '|wp_is_mobile\s*\('
            . '|is_mobile\s*\('
            . '|\bon\s*(?:android|ios|mobile|tablet)\b'
            . '~i',
            $text
        ) === 1;
    }

    /* ------------------------------------------------------------------
     * Destination resolution (static only — nothing is executed)
     * ---------------------------------------------------------------- */

    /**
     * @return array{dest: string, resolved: bool, obfuscated: bool, internal: bool, external: bool, scheme: bool}
     */
    private static function resolveDestination(string $text, string $lang): array {
        $base = ['dest' => '', 'resolved' => false, 'obfuscated' => false, 'internal' => false, 'external' => false, 'scheme' => false];
        $text = trim($text);
        if ($text === '') {
            return $base;
        }

        if ($lang === 'php' && preg_match('~^(?:home_url|admin_url|site_url|wp_logout_url|wp_login_url|wp_registration_url|get_home_url|get_site_url|wp_get_referer|wp_get_original_referer|get_permalink|get_post_permalink|wp_nonce_url|add_query_arg|remove_query_arg|get_edit_post_link|wp_customize_url|wp_get_attachment_url|wp_upload_dir)\(~i', $text) === 1) {
            return ['dest' => '__wp_internal__', 'resolved' => true, 'obfuscated' => false, 'internal' => true, 'external' => false, 'scheme' => false];
        }

        $static = self::resolveStatic($text, $lang);
        if (!$static['resolved']) {
            $decoderHints = self::hasDecoderHints($text, $lang);
            return [
                'dest'       => '',
                'resolved'   => false,
                'obfuscated' => $decoderHints,
                'internal'   => false,
                'external'   => false,
                'scheme'     => self::hasScheme($text),
            ];
        }

        $value = (string) $static['value'];
        $flags = self::destFlags($value, $lang);
        return [
            'dest'       => $value,
            'resolved'   => true,
            'obfuscated' => $static['obfuscated'],
            'internal'   => $flags['internal'],
            'external'   => $flags['external'],
            'scheme'     => $flags['scheme'],
        ];
    }

    /**
     * @return array{value: string, resolved: bool, obfuscated: bool}
     */
    private static function resolveStatic(string $text, string $lang): array {
        $text = trim($text);
        $no = ['value' => '', 'resolved' => false, 'obfuscated' => false];

        // single quoted / double quoted literal (no nested unescaped quotes)
        if (preg_match('/^(["\'])((?:(?!\1).)*)\1$/s', $text, $m) === 1) {
            return ['value' => self::decodeLiteral($m[2]), 'resolved' => true, 'obfuscated' => self::hasEscapes($m[2])];
        }
        // template literal without interpolation
        if (strlen($text) >= 2 && $text[0] === '`' && substr($text, -1) === '`' && strpos($text, '${') === false) {
            return ['value' => self::decodeLiteral(substr($text, 1, -1)), 'resolved' => true, 'obfuscated' => false];
        }
        // atob("...")
        if (preg_match('/^atob\s*\(\s*(["\'])(.*?)\1\s*\)$/is', $text, $m) === 1) {
            $decoded = base64_decode($m[2], true);
            if ($decoded !== false && self::isPrintable($decoded)) {
                return ['value' => $decoded, 'resolved' => true, 'obfuscated' => true];
            }
            return $no;
        }
        // String.fromCharCode(...)
        if (preg_match('/^String\s*\.\s*fromCharCode\s*\((.*)\)$/is', $text, $m) === 1) {
            $codes = array_map('trim', explode(',', $m[1]));
            $value = '';
            foreach ($codes as $code) {
                $code = trim($code);
                if (!preg_match('/^(\d+)(?:\s*\+\s*(\d+))?$/', $code, $cm)) {
                    return $no;
                }
                $num = (int) $cm[1];
                if (isset($cm[2])) {
                    $num += (int) $cm[2];
                }
                $value .= chr($num);
            }
            return ['value' => $value, 'resolved' => true, 'obfuscated' => true];
        }
        // array join: ["a","b"].join("")
        if (preg_match('/^\[(.*)\]\s*\.\s*join\s*\(\s*(["\']).*?\2\s*\)$/is', $text, $m) === 1) {
            $parts = self::splitTop($m[1], ',');
            $value = '';
            foreach ($parts as $part) {
                $part = trim($part);
                if (!preg_match('/^(["\'])(.*)\1$/s', $part, $pm)) {
                    return $no;
                }
                $value .= self::decodeLiteral($pm[2]);
            }
            return ['value' => $value, 'resolved' => true, 'obfuscated' => true];
        }
        // PHP base64_decode('...') / gzuncompress(base64_decode(...)) static
        if ($lang === 'php') {
            if (preg_match('/^base64_decode\s*\(\s*(["\'])(.*?)\1\s*\)$/is', $text, $m) === 1) {
                $decoded = base64_decode($m[2], true);
                if ($decoded !== false && self::isPrintable($decoded)) {
                    return ['value' => $decoded, 'resolved' => true, 'obfuscated' => true];
                }
                return $no;
            }
            if (preg_match('/^(?:gzuncompress|gzinflate|gzdecode)\s*\(\s*base64_decode\s*\(\s*(["\'])(.*?)\1\s*\)\s*\)$/is', $text, $m) === 1) {
                $decoded = @gzuncompress(base64_decode($m[2], true) ?: '');
                if ($decoded !== false && $decoded !== '' && self::isPrintable($decoded)) {
                    return ['value' => $decoded, 'resolved' => true, 'obfuscated' => true];
                }
                return $no;
            }
        }
        // decodeURIComponent("...")
        if (preg_match('/^decodeURIComponent\s*\(\s*(["\'])(.*?)\1\s*\)$/is', $text, $m) === 1) {
            return ['value' => rawurldecode(self::decodeLiteral($m[2])), 'resolved' => true, 'obfuscated' => true];
        }

        // concatenation chains
        $sep = $lang === 'php' ? '.' : '+';
        $parts = self::splitTop($text, $sep);
        if (count($parts) > 1) {
            $value = '';
            $obf = false;
            foreach ($parts as $part) {
                $part = trim($part);
                $res = self::resolveStatic($part, $lang);
                if (!$res['resolved']) {
                    return $no;
                }
                $value .= (string) $res['value'];
                $obf = $obf || $res['obfuscated'];
            }
            return ['value' => $value, 'resolved' => true, 'obfuscated' => $obf];
        }

        // bare hex/unicode escape sequence
        if (preg_match('~^(?:\\\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}))+$~', $text) === 1) {
            return ['value' => self::decodeLiteral($text), 'resolved' => true, 'obfuscated' => true];
        }
        // plain number
        if (is_numeric($text)) {
            return ['value' => $text, 'resolved' => true, 'obfuscated' => false];
        }
        return $no;
    }

    /**
     * Destination flags: relative / internal (same-host, system path,
     * whitelisted) vs external, and whether a scheme is present.
     *
     * @return array{relative: bool, internal: bool, external: bool, scheme: bool}
     */
    private static function destFlags(string $dest, string $lang): array {
        $dest = trim($dest);
        if ($dest === '' || $dest === '__wp_internal__') {
            return ['relative' => false, 'internal' => $dest === '__wp_internal__', 'external' => false, 'scheme' => false];
        }
        if (RedirectEngine::isRelative($dest)) {
            return ['relative' => true, 'internal' => true, 'external' => false, 'scheme' => false];
        }
        if (RedirectEngine::isSameHost($dest)) {
            return ['relative' => false, 'internal' => true, 'external' => false, 'scheme' => true];
        }
        if (RedirectEngine::isSystemPath($dest)) {
            return ['relative' => false, 'internal' => true, 'external' => false, 'scheme' => true];
        }
        if (RedirectEngine::isWhitelistedDomain($dest) || RedirectEngine::matchesWhitelistPattern($dest)) {
            return ['relative' => false, 'internal' => true, 'external' => false, 'scheme' => true];
        }
        $scheme = (string) wp_parse_url($dest, PHP_URL_SCHEME);
        return [
            'relative' => false,
            'internal' => false,
            'external' => $scheme !== '',
            'scheme'   => $scheme !== '',
        ];
    }

    private static function sourceTrusted(array $origin): bool {
        if (!empty($origin['plugin'])) {
            return Trust::level($origin['plugin'], 'plugin') !== Trust::UNKNOWN;
        }
        if (!empty($origin['theme'])) {
            return Trust::level($origin['theme'], 'theme') !== Trust::UNKNOWN;
        }
        return false;
    }

    /* ------------------------------------------------------------------
     * Token helpers
     * ---------------------------------------------------------------- */

    private static function tokensToText(array $tokens, array $range): string {
        $out = '';
        foreach ($range as $i) {
            if (!isset($tokens[$i])) {
                continue;
            }
            $out .= $tokens[$i]['v'];
        }
        return $out;
    }

    private static function statementStart(array $tokens, int $idx): int {
        $depth = 0;
        for ($i = $idx; $i >= 0; $i--) {
            $tk = $tokens[$i];
            if ($tk['t'] === 'p') {
                if (in_array($tk['v'], [')', ']', '}'], true)) {
                    $depth++;
                } elseif (in_array($tk['v'], ['(', '[', '{'], true)) {
                    $depth--;
                } elseif ($depth === 0 && in_array($tk['v'], [';', '{', '}'], true)) {
                    return $i + 1;
                }
            }
        }
        return 0;
    }

    private static function statementEnd(array $tokens, int $idx): int {
        $depth = 0;
        $n = count($tokens);
        for ($i = $idx; $i < $n; $i++) {
            $tk = $tokens[$i];
            if ($tk['t'] === 'p') {
                if (in_array($tk['v'], ['(', '[', '{'], true)) {
                    $depth++;
                } elseif (in_array($tk['v'], [')', ']', '}'], true)) {
                    if ($depth === 0) {
                        return $i;
                    }
                    $depth--;
                } elseif ($depth === 0 && $tk['v'] === ';') {
                    return $i;
                }
            }
        }
        return $n - 1;
    }

    private static function expressionEnd(array $tokens, int $idx): int {
        $depth = 0;
        $n = count($tokens);
        for ($i = $idx; $i < $n; $i++) {
            $tk = $tokens[$i];
            if ($tk['t'] === 'p') {
                if (in_array($tk['v'], ['(', '[', '{'], true)) {
                    $depth++;
                } elseif (in_array($tk['v'], [')', ']', '}'], true)) {
                    if ($depth === 0) {
                        return $i - 1;
                    }
                    $depth--;
                } elseif ($depth === 0 && ($tk['v'] === ';' || $tk['v'] === ',')) {
                    return $i - 1;
                }
            }
        }
        return $n - 1;
    }

    private static function skipToBrace(array $tokens, int $idx): ?int {
        $depth = 0;
        $n = count($tokens);
        for ($i = $idx; $i < $n; $i++) {
            $tk = $tokens[$i];
            if ($tk['t'] === 'p') {
                if ($tk['v'] === '(') {
                    $depth++;
                } elseif ($tk['v'] === ')') {
                    $depth--;
                } elseif ($tk['v'] === '{' && $depth === 0) {
                    return $i;
                } elseif ($tk['v'] === ';' && $depth === 0) {
                    return null;
                }
            }
        }
        return null;
    }

    private static function operandStart(array $tokens, int $idx): ?int {
        return self::statementStart($tokens, $idx);
    }

    private static function operandEnd(array $tokens, int $idx, array $pairs): ?int {
        return self::statementEnd($tokens, $idx);
    }

    private static function ternaryColon(array $tokens, int $qIdx, array $pairs): ?int {
        $depth = 0;
        $n = count($tokens);
        for ($i = $qIdx + 1; $i < $n; $i++) {
            $tk = $tokens[$i];
            if ($tk['t'] === 'p') {
                if (in_array($tk['v'], ['(', '[', '{'], true)) {
                    $depth++;
                } elseif (in_array($tk['v'], [')', ']', '}'], true)) {
                    if ($depth === 0) {
                        return null;
                    }
                    $depth--;
                } elseif ($depth === 0 && $tk['v'] === ':') {
                    return $i;
                } elseif ($depth === 0 && ($tk['v'] === ';' || $tk['v'] === ',')) {
                    return null;
                }
            }
        }
        return null;
    }

    private static function splitTop(string $text, string $sep): array {
        $parts = [];
        $depth = 0;
        $cur = '';
        $quote = '';
        $len = strlen($text);
        for ($i = 0; $i < $len; $i++) {
            $c = $text[$i];
            if ($quote !== '') {
                $cur .= $c;
                if ($c === '\\') {
                    if ($i + 1 < $len) {
                        $cur .= $text[++$i];
                    }
                    continue;
                }
                if ($c === $quote) {
                    $quote = '';
                }
                continue;
            }
            if ($c === '"' || $c === "'") {
                $quote = $c;
                $cur .= $c;
                continue;
            }
            if ($c === '(' || $c === '[' || $c === '{') {
                $depth++;
            } elseif ($c === ')' || $c === ']' || $c === '}') {
                $depth--;
            }
            if ($depth === 0 && $c === $sep) {
                $parts[] = trim($cur);
                $cur = '';
                continue;
            }
            $cur .= $c;
        }
        if (trim($cur) !== '') {
            $parts[] = trim($cur);
        }
        return $parts;
    }

    /**
     * Decode string escapes (\\n, \xHH, \uHHHH, \t, ...) — never executes.
     */
    private static function decodeLiteral(string $raw): string {
        $out = '';
        $len = strlen($raw);
        for ($i = 0; $i < $len; $i++) {
            $c = $raw[$i];
            if ($c !== '\\' || $i + 1 >= $len) {
                $out .= $c;
                continue;
            }
            $n = $raw[++$i];
            if ($n === 'n') {
                $out .= "\n";
            } elseif ($n === 't') {
                $out .= "\t";
            } elseif ($n === 'r') {
                $out .= "\r";
            } elseif ($n === '\\' || $n === '"' || $n === "'" || $n === '`') {
                $out .= $n;
            } elseif ($n === 'x' && $i + 2 < $len && ctype_xdigit($raw[$i + 1]) && ctype_xdigit($raw[$i + 2])) {
                $out .= chr((int) hexdec(substr($raw, $i + 1, 2)));
                $i += 2;
            } elseif ($n === 'u' && $i + 4 < $len && preg_match('/^[0-9a-fA-F]{4}$/', substr($raw, $i + 1, 4))) {
                $code = (int) hexdec(substr($raw, $i + 1, 4));
                if (function_exists('mb_chr')) {
                    $out .= mb_chr($code, 'UTF-8');
                } else {
                    $out .= self::chrUtf8($code);
                }
                $i += 4;
            } else {
                $out .= $n;
            }
        }
        return $out;
    }

    /**
     * UTF-8 encoder fallback when mbstring is unavailable.
     */
    private static function chrUtf8(int $code): string {
        if ($code < 0x80) {
            return chr($code);
        }
        if ($code < 0x800) {
            return chr(0xC0 | ($code >> 6)) . chr(0x80 | ($code & 0x3F));
        }
        if ($code < 0x10000) {
            return chr(0xE0 | ($code >> 12)) . chr(0x80 | (($code >> 6) & 0x3F)) . chr(0x80 | ($code & 0x3F));
        }
        return chr(0xF0 | ($code >> 18)) . chr(0x80 | (($code >> 12) & 0x3F)) . chr(0x80 | (($code >> 6) & 0x3F)) . chr(0x80 | ($code & 0x3F));
    }

    private static function hasEscapes(string $raw): bool {
        return strpos($raw, '\\x') !== false || strpos($raw, '\\u') !== false || strpos($raw, '\\u{') !== false;
    }

    private static function hasDecoderHints(string $text, string $lang): bool {
        if ($lang === 'php') {
            return preg_match('/\b(?:base64_decode|gzuncompress|gzinflate|gzdecode|str_rot13|eval)\s*\(/i', $text) === 1;
        }
        return preg_match('/\b(?:atob|btoa|decodeURIComponent|unescape|String\s*\.\s*fromCharCode)\s*\(/i', $text) === 1;
    }

    private static function hasScheme(string $text): bool {
        return preg_match('~^[a-z][a-z0-9+.-]*\s*:~i', trim($text)) === 1;
    }

    private static function isPrintable(string $value): bool {
        if ($value === '') {
            return false;
        }
        return preg_match('/^[\x20-\x7E\r\n\t]+$/', $value) === 1;
    }

    private static function stringContent(string $raw): string {
        if (strlen($raw) >= 2) {
            return self::decodeLiteral(substr($raw, 1, -1));
        }
        return '';
    }

    private static function cut(string $value, int $length): string {
        if (function_exists('mb_substr')) {
            return mb_substr($value, 0, $length);
        }
        return substr($value, 0, $length);
    }
}
