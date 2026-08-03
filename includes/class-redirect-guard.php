<?php
/**
 * RedirectGuard: behavior-based runtime redirect protection.
 *
 * Every server-side redirect (wp_redirect / wp_safe_redirect, admin-post,
 * admin-ajax, cron, REST responses with a Location header and direct
 * header('Location:') calls) is classified by RedirectEngine with a
 * confidence rating. Actions:
 *
 *   HIGH   -> block the redirect, quarantine the source file, notify.
 *   MEDIUM -> log + notify, allow.
 *   LOW    -> log only.
 *   SAFE / EXPECTED -> allowed silently.
 *
 * Monitor-only mode disables blocking and quarantine everywhere.
 *
 * A standalone must-use plugin with the same logic is generated on
 * activation and re-generated when the plugin version changes.
 *
 * @package Watchdog
 */

declare(strict_types=1);

namespace Watchdog;

/**
 * RedirectGuard
 */
final class RedirectGuard {

    private const MU_FILE = 'security-guard.php';
    private const MU_VERSION_OPTION = 'watchdog_mu_version';

    /** Redirects already handled this request (for shutdown dedup). */
    private static array $handled = [];

    /**
     * Hook the redirect filters unless the MU plugin is already active.
     */
    public static function init(): void {
        if (self::muActive()) {
            return;
        }
        add_filter('wp_redirect', [self::class, 'filterRedirect'], PHP_INT_MAX, 2);
        add_filter('wp_safe_redirect', [self::class, 'filterRedirect'], PHP_INT_MAX, 2);
        add_filter('rest_request_after_callbacks', [self::class, 'filterRestRedirect'], PHP_INT_MAX, 3);
        add_action('shutdown', [self::class, 'logDirectHeaders'], 5);
    }

    /**
     * Classify a server-side redirect and act on confidence.
     *
     * @param mixed $location Destination passed by WordPress.
     * @param mixed $status   HTTP status code.
     *
     * @return string
     */
    public static function filterRedirect($location, $status): string {
        return self::delegate((string) $location, (int) $status);
    }

    /**
     * Single runtime decision point. Called by the main plugin filters and
     * by the generated MU guard when the main plugin is loaded, so both
     * paths always use exactly the same engine, trust model and actions.
     *
     * @return string The (possibly rewritten) location.
     */
    public static function delegate(string $location, int $status): string {
        $origin = self::originFromBacktrace();
        $decision = RedirectEngine::classifyServerRedirect($location, $origin);
        self::$handled[$location] = $decision;

        if ($decision['class'] === RedirectEngine::SAFE || $decision['class'] === RedirectEngine::EXPECTED) {
            return $location;
        }

        self::logDecision('wp_redirect', $location, $decision, $origin, $status);

        if ($decision['confidence'] === RedirectEngine::CONFIDENCE_HIGH) {
            if (!RedirectEngine::monitorOnly()) {
                self::quarantineSource($origin);
                return home_url('/');
            }
        }

        return $location;
    }

    /**
     * REST responses carrying a redirect (301/302/303/307/308 + Location).
     */
    public static function filterRestRedirect($response, $handler, $request) {
        return self::delegateRest($response, $request);
    }

    /**
     * Shared REST decision point (main plugin + generated MU guard).
     */
    public static function delegateRest($response, $request) {
        if (is_wp_error($response) || !is_object($response) || !method_exists($response, 'get_headers') || !method_exists($response, 'get_status')) {
            return $response;
        }

        $location = $response->get_header('Location');
        $status = (int) $response->get_status();
        if (!$location || !in_array($status, [301, 302, 303, 307, 308], true)) {
            return $response;
        }

        $origin = self::restOrigin($request);
        $decision = RedirectEngine::classifyServerRedirect((string) $location, $origin);
        self::$handled[(string) $location] = $decision;

        if ($decision['class'] === RedirectEngine::SAFE || $decision['class'] === RedirectEngine::EXPECTED) {
            return $response;
        }

        self::logDecision(
            'rest-api',
            (string) $location,
            $decision,
            $origin,
            $status,
            is_object($request) && method_exists($request, 'get_route') ? (string) $request->get_route() : ''
        );

        if ($decision['confidence'] === RedirectEngine::CONFIDENCE_HIGH && !RedirectEngine::monitorOnly()) {
            $response->header('Location', home_url('/'));
            $response->set_status(302);
        }

        return $response;
    }

    /**
     * Direct header('Location:') calls bypass wp_redirect entirely. Nothing
     * can replace them after they are sent, but they can be detected and
     * logged on shutdown.
     */
    public static function logDirectHeaders(): void {
        foreach (headers_list() as $header) {
            if (stripos($header, 'Location:') !== 0) {
                continue;
            }
            $location = trim(substr($header, 9));
            if (isset(self::$handled[$location]) || $location === '') {
                continue;
            }
            $origin = self::originFromBacktrace();
            $decision = RedirectEngine::classifyServerRedirect($location, $origin);
            if ($decision['class'] === RedirectEngine::SAFE || $decision['class'] === RedirectEngine::EXPECTED) {
                continue;
            }
            self::$handled[$location] = $decision;
            self::logDecision('header()', $location, $decision, $origin, 302);
        }
    }

    /**
     * Origin of the redirect from the current backtrace (first content-dir
     * frame), so trusted sources are never blocked.
     */
    public static function originFromBacktrace(): array {
        foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 15) as $frame) {
            $file = isset($frame['file']) ? $frame['file'] : '';
            if ($file === '' || strpos($file, WP_CONTENT_DIR) !== 0) {
                continue;
            }
            if (strpos($file, __FILE__) !== false) {
                continue;
            }
            $relative = str_replace(WP_CONTENT_DIR . DIRECTORY_SEPARATOR, '', $file);
            $parts = explode(DIRECTORY_SEPARATOR, $relative);
            $origin = ['plugin' => '', 'theme' => '', 'core' => false, 'uploads' => false];
            if (isset($parts[0])) {
                if ($parts[0] === 'plugins' && isset($parts[1])) {
                    $origin['plugin'] = $parts[1];
                } elseif ($parts[0] === 'themes' && isset($parts[1])) {
                    $origin['theme'] = $parts[1];
                } elseif ($parts[0] === 'uploads') {
                    $origin['uploads'] = true;
                }
            }
            return $origin;
        }
        return ['plugin' => '', 'theme' => '', 'core' => false, 'uploads' => false];
    }

    /**
     * Resolve the plugin/theme behind a REST route by reflecting the
     * registered callback (never executed here).
     */
    public static function restOrigin($request): array {
        $file = '';
        try {
            $attributes = $request instanceof \WP_REST_Request ? $request->get_attributes() : [];
            $callback = isset($attributes['callback']) ? $attributes['callback'] : null;
            if (is_array($callback)) {
                $ref = new \ReflectionMethod($callback[0], $callback[1]);
            } elseif (is_callable($callback)) {
                $ref = new \ReflectionFunction($callback);
            } else {
                $ref = null;
            }
            if ($ref !== null) {
                $file = (string) $ref->getFileName();
            }
        } catch (\ReflectionException $e) {
            $file = '';
        }

        if ($file === '' || strpos($file, WP_CONTENT_DIR) !== 0) {
            return ['plugin' => '', 'theme' => '', 'core' => false, 'uploads' => false];
        }
        return RedirectEngine::originOf($file);
    }

    /**
     * True when the MU plugin file exists.
     */
    public static function muActive(): bool {
        return is_file(self::muDir() . DIRECTORY_SEPARATOR . self::MU_FILE);
    }

    /**
     * Remove the generated MU plugin (deactivation/uninstall). A file that
     * was manually edited (no @generated stamp) is never touched.
     */
    public static function removeMuPlugin(): bool {
        $target = self::muDir() . DIRECTORY_SEPARATOR . self::MU_FILE;
        if (!is_file($target)) {
            return true;
        }
        $content = (string) @file_get_contents($target);
        $stamp = self::muStamp($target);
        if ($stamp === '') {
            return false; // manually edited — leave it alone
        }
        if ($stamp !== Plugin::VERSION) {
            @copy($target, $target . '.bak-' . $stamp);
        }
        return @unlink($target);
    }

    /**
     * Write the MU plugin only when it is missing. Called on every page
     * load by Plugin::upgrade() so the guard installs itself the moment
     * the main plugin is active — no manual copying ever needed.
     */
    public static function ensureMuPlugin(): bool {
        if (self::muActive()) {
            return true;
        }
        return self::writeMuPlugin();
    }

    /**
     * Write the MU plugin. Overwrites generated files on version change
     * (backup kept); files without a @generated stamp (previous automatic
     * copies, manual copies) are backed up as .bak-unstamped before they
     * are replaced, so nothing is ever lost.
     */
    public static function writeMuPlugin(bool $force = false): bool {
        $dir = self::muDir();
        if (!wp_mkdir_p($dir)) {
            return false;
        }
        $target = $dir . DIRECTORY_SEPARATOR . self::MU_FILE;

        if (is_file($target)) {
            $stamp = self::muStamp($target);
            if (!$force && $stamp === Plugin::VERSION) {
                return true;
            }
            if ($stamp !== '' && $stamp !== Plugin::VERSION) {
                @copy($target, $target . '.bak-' . $stamp);
            } elseif ($stamp === '') {
                @copy($target, $target . '.bak-unstamped');
            }
        }
        if (!is_writable($dir)) {
            return false;
        }
        $written = @file_put_contents($target, self::muCode()) !== false;
        if ($written) {
            update_option(self::MU_VERSION_OPTION, Plugin::VERSION, false);
        }
        return $written;
    }

    /**
     * Version stamp embedded in a generated MU file.
     */
    private static function muStamp(string $target): string {
        $content = (string) @file_get_contents($target);
        return (string) preg_match('/@generated\s+v([0-9.]+)/', $content, $m) ? $m[1] : '';
    }

    /**
     * Directory for must-use plugins.
     */
    public static function muDir(): string {
        if (defined('WPMU_PLUGIN_DIR') && WPMU_PLUGIN_DIR) {
            return (string) WPMU_PLUGIN_DIR;
        }
        return WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'mu-plugins';
    }

    /**
     * Log a classified runtime redirect with the full context the logging
     * module requires: time, IP, user, source, destination, reason,
     * confidence, request URI, referer, user agent and stack trace.
     */
    private static function logDecision(string $source, string $location, array $decision, array $origin, int $status, string $route = ''): void {
        Logger::log(
            'redirect_blocked',
            $decision['severity'],
            $source,
            [
                'destination' => $location,
                'class'       => $decision['class'],
                'confidence'  => $decision['confidence'],
                'reason'      => $decision['reason'],
                'status'      => $status,
                'origin'      => $origin,
                'route'       => $route,
                'request_uri' => isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '',
                'referer'     => isset($_SERVER['HTTP_REFERER']) ? esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER'])) : '',
                'user_agent'  => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(substr(wp_unslash($_SERVER['HTTP_USER_AGENT']), 0, 300)) : '',
                'backtrace'   => self::backtrace(),
            ]
        );

        if ($decision['confidence'] === RedirectEngine::CONFIDENCE_HIGH || $decision['confidence'] === RedirectEngine::CONFIDENCE_MEDIUM) {
            Reporter::alert(
                'Watchdog: ' . strtoupper($decision['confidence']) . ' confidence redirect to ' . wp_parse_url($location, PHP_URL_HOST),
                '<p>Watchdog classified a redirect to <code>' . esc_html($location) . '</code> as '
                . '<strong>' . strtoupper($decision['class']) . '</strong> '
                . '(' . strtoupper($decision['confidence']) . ' confidence).</p>'
                . '<p>Reason: ' . esc_html($decision['reason']) . '</p>'
                . '<p>Source: ' . esc_html(wp_json_encode($origin)) . '</p>'
            );
        }
    }

    /**
     * Quarantine the file behind the redirect source (HIGH confidence).
     * Only plugin/theme/upload files are moved; core is never touched.
     */
    private static function quarantineSource(array $origin): void {
        if (RedirectEngine::monitorOnly()) {
            return;
        }
        $frame = self::firstSourceFrame();
        if ($frame === '' || strpos($frame, WP_CONTENT_DIR) !== 0) {
            return;
        }
        $quarantined = Quarantine::quarantineFile($frame);
        if ($quarantined !== null) {
            Logger::log('quarantined', 'critical', $frame, [
                'quarantine_file' => $quarantined['name'],
                'reason'          => 'HIGH confidence redirect source',
            ]);
        }
    }

    /**
     * First content-dir frame of the backtrace that is not this class.
     */
    private static function firstSourceFrame(): string {
        foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 15) as $frame) {
            $file = isset($frame['file']) ? $frame['file'] : '';
            if ($file === '' || strpos($file, WP_CONTENT_DIR) !== 0 || strpos($file, __FILE__) !== false) {
                continue;
            }
            $origin = RedirectEngine::originOf($file);
            if (!empty($origin['plugin']) || !empty($origin['theme']) || $origin['uploads']) {
                return $file;
            }
        }
        return '';
    }

    /**
     * Content-dir frames of the current backtrace.
     */
    private static function backtrace(): array {
        $backtrace = [];
        foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 10) as $frame) {
            $file = isset($frame['file']) ? $frame['file'] : '';
            if (strpos($file, WP_CONTENT_DIR) !== 0) {
                continue;
            }
            $backtrace[] = str_replace(WP_CONTENT_DIR . '/', '', $file)
                . ':' . (isset($frame['line']) ? $frame['line'] : '?')
                . ' ' . (isset($frame['function']) ? $frame['function'] : '');
        }
        return $backtrace;
    }

    /**
     * Source code of the generated MU plugin (standalone, no dependencies
     * on the main plugin). When the main Watchdog plugin is active its
     * RedirectEngine + RedirectGuard become the single decision point
     * (delegation); the embedded fallback below is only used when the main
     * plugin is deactivated, and mirrors RedirectEngine::classifyServerRedirect
     * rule-for-rule (same tiers, same confidence mapping).
     */
    public static function muCode(): string {
        $official = implode("\n", Trust::defaultOfficial());
        $code = <<<'PHP'
<?php
/**
 * Plugin Name: Watchdog Security Guard (auto-generated by Watchdog)
 * Description: Behavior-based redirect protection. Blocks HIGH-confidence
 * external redirects, allows expected ones, logs every decision. Loads
 * before every regular plugin.
 * @generated v{{VERSION}}
 */

if (!defined('ABSPATH')) {
    exit;
}

add_filter('wp_redirect', 'watchdog_guard_filter', PHP_INT_MAX, 2);
add_filter('wp_safe_redirect', 'watchdog_guard_filter', PHP_INT_MAX, 2);
add_filter('rest_request_after_callbacks', 'watchdog_guard_rest', PHP_INT_MAX, 3);
add_action('shutdown', 'watchdog_guard_shutdown', 5);

function watchdog_guard_denied()
{
    $raw = (string) get_option('watchdog_denied_domains', '');
    if (trim($raw) === '') {
        return array('google.com', 't.co', 'ushort.company');
    }
    $out = array();
    foreach (preg_split('/[\s,]+/', $raw) as $entry) {
        $entry = strtolower(trim($entry, " \t\n\r\0\x0B."));
        if ($entry !== '') {
            $out[] = $entry;
        }
    }
    return array_values(array_unique($out));
}

function watchdog_guard_is_denied_host($host)
{
    $host = strtolower(trim((string) $host));
    if ($host === '') {
        return false;
    }
    foreach (watchdog_guard_denied() as $denied) {
        if ($host === $denied || substr($host, -strlen($denied) - 1) === '.' . $denied) {
            return true;
        }
    }
    return false;
}

/**
 * When the main Watchdog plugin is loaded, every decision is delegated to
 * its RedirectEngine/RedirectGuard — one source of truth for the trust
 * model, whitelists and confidence rules. The fallback below only runs
 * when the main plugin is deactivated.
 */
function watchdog_guard_filter($location, $status)
{
    if (class_exists('Watchdog\\RedirectGuard')) {
        return \Watchdog\RedirectGuard::delegate((string) $location, (int) $status);
    }
    return watchdog_guard_standalone((string) $location, (int) $status);
}

function watchdog_guard_rest($response, $handler, $request)
{
    if (class_exists('Watchdog\\RedirectGuard')) {
        return \Watchdog\RedirectGuard::delegateRest($response, $request);
    }
    return watchdog_guard_rest_standalone($response);
}

function watchdog_guard_shutdown()
{
    if (class_exists('Watchdog\\RedirectGuard')) {
        \Watchdog\RedirectGuard::logDirectHeaders();
        return;
    }
    watchdog_guard_shutdown_standalone();
}

/* ------------------------------------------------------------------
 * Standalone fallback (main plugin not loaded).
 * Keep in sync with RedirectEngine::classifyServerRedirect.
 * ------------------------------------------------------------------ */

/**
 * Behavior-based classification with confidence. Safe/expected
 * destinations are relative URLs, same-host redirects, WordPress system
 * paths and admin-defined whitelists; denied hosts (google.com, t.co,
 * ushort.company by default) are always blocked.
 */
function watchdog_guard_classify($location, $origin = null)
{
    $dest = (string) $location;

    if (trim($dest) === '') {
        return array('class' => 'safe', 'reason' => 'empty destination', 'severity' => 'safe', 'confidence' => 'low');
    }
    if (preg_match('#^(?:https?:)?//#i', $dest) !== 1) {
        return array('class' => 'safe', 'reason' => 'relative URL (no host)', 'severity' => 'safe', 'confidence' => 'low');
    }
    if (preg_match('/^[a-z][a-z0-9+.-]*:/i', $dest) === 1 && preg_match('#^(?:https?|ftp):#i', $dest) !== 1) {
        if (preg_match('/^(?:javascript|data|vbscript|file|jar):/i', $dest) === 1) {
            return array('class' => 'malicious', 'reason' => 'javascript:/data: destination', 'severity' => 'critical', 'confidence' => 'medium');
        }
        return array('class' => 'suspicious', 'reason' => 'non-web destination scheme', 'severity' => 'warning', 'confidence' => 'low');
    }

    $host = strtolower((string) wp_parse_url($dest, PHP_URL_HOST));
    $site = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
    if ($host === '' || $site === '') {
        return array('class' => 'expected', 'reason' => 'same-host or unparsable destination', 'severity' => 'info', 'confidence' => 'low');
    }
    if (watchdog_guard_is_denied_host($host)) {
        return array('class' => 'malicious', 'reason' => 'destination host is denied', 'severity' => 'critical', 'confidence' => 'high');
    }
    if ($host === $site) {
        return array('class' => 'expected', 'reason' => 'same-host redirect', 'severity' => 'info', 'confidence' => 'low');
    }
    if (get_option('watchdog_allow_subdomains', 1) && substr($host, -strlen($site) - 1) === '.' . $site) {
        return array('class' => 'expected', 'reason' => 'same-host subdomain redirect', 'severity' => 'info', 'confidence' => 'low');
    }
    if (watchdog_guard_whitelisted($host, $dest)) {
        return array('class' => 'expected', 'reason' => 'destination is whitelisted', 'severity' => 'info', 'confidence' => 'low');
    }
    if (is_array($origin) && watchdog_guard_source_allowed($origin)) {
        return array('class' => 'expected', 'reason' => 'redirect from trusted source', 'severity' => 'info', 'confidence' => 'low');
    }
    if (is_array($origin) && empty($origin['slug'])) {
        return array('class' => 'suspicious', 'reason' => 'external redirect from core code', 'severity' => 'warning', 'confidence' => 'low');
    }
    $confidence = watchdog_guard_origin_unknown($origin) ? 'high' : 'medium';
    return array('class' => 'malicious', 'reason' => 'external redirect from unlisted source', 'severity' => 'critical', 'confidence' => $confidence);
}

/**
 * First plugin/theme frame of the current backtrace, if any.
 */
function watchdog_guard_origin()
{
    foreach (array_slice(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS), 0, 15) as $frame) {
        if (!isset($frame['file']) || strpos($frame['file'], WP_CONTENT_DIR) !== 0) {
            continue;
        }
        $rel = str_replace(WP_CONTENT_DIR . '/', '', $frame['file']);
        $parts = explode('/', $rel);
        if (isset($parts[1]) && ($parts[0] === 'plugins' || $parts[0] === 'themes')) {
            return array('kind' => $parts[0], 'slug' => $parts[1]);
        }
    }
    return array('kind' => '', 'slug' => '');
}

function watchdog_guard_origin_unknown($origin)
{
    if (!is_array($origin) || empty($origin['slug'])) {
        return true;
    }
    $option = $origin['kind'] === 'plugins' ? 'watchdog_trust_plugins' : 'watchdog_trust_themes';
    $map = (array) get_option($option, array());
    $slug = strtolower($origin['slug']);
    if (isset($map[$slug])) {
        return $map[$slug] === 'unknown';
    }
    return !in_array($slug, watchdog_guard_official(), true);
}

/**
 * Built-in known-good slugs, embedded from the main plugin's trust model
 * at generation time (kept in sync automatically on every version change).
 */
function watchdog_guard_official()
{
    static $slugs = null;
    if ($slugs === null) {
        $slugs = array();
        foreach (explode("\n", '{{OFFICIAL}}') as $line) {
            $line = strtolower(trim($line));
            if ($line !== '') {
                $slugs[] = $line;
            }
        }
    }
    return $slugs;
}

function watchdog_guard_source_allowed($origin)
{
    if (!is_array($origin) || empty($origin['slug'])) {
        return false;
    }
    $option = $origin['kind'] === 'plugins' ? 'watchdog_whitelist_plugins' : 'watchdog_whitelist_themes';
    foreach (watchdog_guard_lines($option) as $entry) {
        if (strtolower(trim($entry)) === strtolower($origin['slug'])) {
            return true;
        }
    }
    $trust = (array) get_option($origin['kind'] === 'plugins' ? 'watchdog_trust_plugins' : 'watchdog_trust_themes', array());
    $slug = strtolower($origin['slug']);
    if (isset($trust[$slug])) {
        return $trust[$slug] !== 'unknown';
    }
    return in_array($slug, watchdog_guard_official(), true);
}

function watchdog_guard_whitelisted($host, $dest)
{
    foreach (watchdog_guard_lines('watchdog_whitelist_domains') as $entry) {
        $entry = strtolower(trim($entry));
        if ($entry !== '' && ($host === $entry || substr($host, -strlen($entry) - 1) === '.' . $entry)) {
            return true;
        }
    }
    foreach (watchdog_guard_lines('watchdog_whitelist_patterns') as $pattern) {
        if (@preg_match('~' . $pattern . '~i', $dest) === 1) {
            return true;
        }
    }
    return false;
}

function watchdog_guard_lines($option)
{
    $out = array();
    foreach (explode("\n", (string) get_option($option, '')) as $line) {
        $line = trim($line);
        if ($line !== '') {
            $out[] = $line;
        }
    }
    return $out;
}

function watchdog_guard_standalone($location, $status)
{
    $origin = watchdog_guard_origin();
    $decision = watchdog_guard_classify($location, $origin);
    $GLOBALS['watchdog_guard_seen'][(string) $location] = $decision;

    if ($decision['class'] === 'malicious' || $decision['class'] === 'suspicious') {
        watchdog_guard_log('redirect_blocked', $decision['severity'], $location, $decision['reason'], $status, $decision['confidence'], $origin);

        if ($decision['class'] === 'malicious' && $decision['confidence'] === 'high' && !get_option('watchdog_monitor_only', 0)) {
            return home_url('/');
        }
    }

    return $location;
}

function watchdog_guard_rest_standalone($response)
{
    if (!is_object($response) || !method_exists($response, 'get_headers') || !method_exists($response, 'get_status')) {
        return $response;
    }
    $location = $response->get_header('Location');
    $status = (int) $response->get_status();
    if (!$location || !in_array($status, array(301, 302, 303, 307, 308), true)) {
        return $response;
    }

    $decision = watchdog_guard_classify($location, watchdog_guard_origin());
    $GLOBALS['watchdog_guard_seen'][(string) $location] = $decision;

    if ($decision['class'] === 'malicious' || $decision['class'] === 'suspicious') {
        watchdog_guard_log('redirect_blocked', $decision['severity'], $location, $decision['reason'], $status, $decision['confidence'], array());

        if ($decision['class'] === 'malicious' && $decision['confidence'] === 'high' && !get_option('watchdog_monitor_only', 0)) {
            $response->header('Location', home_url('/'));
            $response->set_status(302);
        }
    }
    return $response;
}

/**
 * Direct header('Location: ...') calls cannot be replaced once sent; they
 * are detected and logged on shutdown.
 */
function watchdog_guard_shutdown_standalone()
{
    foreach (headers_list() as $header) {
        if (stripos($header, 'Location:') !== 0) {
            continue;
        }
        $location = trim(substr($header, 9));
        if ($location === '' || isset($GLOBALS['watchdog_guard_seen'][$location])) {
            continue;
        }
        $decision = watchdog_guard_classify($location, watchdog_guard_origin());
        if ($decision['class'] !== 'safe' && $decision['class'] !== 'expected') {
            watchdog_guard_log('redirect_blocked', $decision['severity'], $location, $decision['reason'], 302, $decision['confidence'], array());
        }
    }
}

function watchdog_guard_log($type, $severity, $location, $reason, $status, $confidence, $origin)
{
    error_log('[Security Guard] ' . strtoupper($confidence) . ': ' . $reason . ' -> ' . $location);

    global $wpdb;
    if (!$wpdb) {
        return;
    }
    $table = $wpdb->prefix . 'watchdog_events';
    $exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table));
    if (!$exists) {
        return;
    }

    $trace = array();
    foreach (array_slice(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS), 0, 10) as $frame) {
        if (isset($frame['file']) && strpos($frame['file'], WP_CONTENT_DIR) === 0) {
            $trace[] = str_replace(WP_CONTENT_DIR . '/', '', $frame['file'])
                . ':' . (isset($frame['line']) ? $frame['line'] : '?')
                . ' ' . (isset($frame['function']) ? $frame['function'] : '');
        }
    }

    $user = is_user_logged_in() ? wp_get_current_user() : null;

    $wpdb->insert($table, array(
        'event_time' => current_time('mysql'),
        'type'       => 'redirect_blocked',
        'severity'   => $severity,
        'source'     => 'mu-plugin',
        'details'    => wp_json_encode(array(
            'destination' => $location,
            'reason'      => $reason,
            'confidence'  => $confidence,
            'status'      => $status,
            'origin'      => $origin,
            'request_uri' => isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '',
            'referer'     => isset($_SERVER['HTTP_REFERER']) ? esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER'])) : '',
            'user_agent'  => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(substr(wp_unslash($_SERVER['HTTP_USER_AGENT']), 0, 300)) : '',
            'backtrace'   => $trace,
        )),
        'ip'         => isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '',
        'username'   => $user && $user->exists() ? $user->user_login : '',
    ), array('%s', '%s', '%s', '%s', '%s', '%s', '%s'));
}
PHP;
        return str_replace(
            ['{{VERSION}}', '{{OFFICIAL}}'],
            [Plugin::VERSION, $official],
            $code
        );
    }
}
