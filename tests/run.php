<?php
/**
 * Watchdog test suite.
 *
 * Standalone: runs without WordPress (the bundled stubs below provide
 * the small WP surface the plugin uses). Every payload used by the
 * tests is stored as base64 in payloads.txt and decoded at runtime,
 * so this file never contains executable code samples.
 *
 * Exit code 0 = all tests passed; 1 = one or more failures.
 */

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '1');

define('ABSPATH', str_replace('\\', '/', dirname(__DIR__, 4)) . '/');
define('WD_PLUGIN_DIR', str_replace('\\', '/', dirname(__DIR__)) . '/');
define('WP_CONTENT_DIR', ABSPATH . 'wp-content');
define('WP_PLUGIN_DIR', ABSPATH . 'wp-content/plugins');
define('WP_CONTENT_URL', 'https://random.local/wp-content');
define('WP_PLUGIN_URL', 'https://random.local/wp-content/plugins');
define('WATCHDOG_TEST_HOME', 'https://random.local');
define('WATCHDOG_TEST_CORE_VERSION', '6.5.0');
define('HOUR_IN_SECONDS', 3600);
define('DAY_IN_SECONDS', 86400);
define('MINUTE_IN_SECONDS', 60);
define('ARRAY_A', 'ARRAY_A');
define('OBJECT', 'OBJECT');

require_once WD_PLUGIN_DIR . 'includes/class-heuristics.php';
require_once WD_PLUGIN_DIR . 'includes/class-redirect-analyzer.php';
require_once WD_PLUGIN_DIR . 'includes/class-redirect-engine.php';
require_once WD_PLUGIN_DIR . 'includes/class-execution-context.php';
require_once WD_PLUGIN_DIR . 'includes/class-checksums.php';
require_once WD_PLUGIN_DIR . 'includes/class-trust.php';
require_once WD_PLUGIN_DIR . 'includes/class-site-checks.php';
require_once WD_PLUGIN_DIR . 'includes/class-scanner.php';

use Watchdog\Heuristics;
use Watchdog\RedirectEngine;
use Watchdog\ExecutionContext;
use Watchdog\Checksums;
use Watchdog\Trust;
use Watchdog\SiteChecks;
use Watchdog\Scanner;

/* ------------------------------------------------------------------
 * WP surface stubs
 * ---------------------------------------------------------------- */

$GLOBALS['wd_options'] = [];
$GLOBALS['wd_transients'] = [];
$GLOBALS['wd_users'] = [];
$GLOBALS['wd_db_posts'] = [];
$GLOBALS['wd_db_comments'] = [];

if (!class_exists('WP_Error', false)) {
    class WP_Error {
        public array $errors = [];

        public function get_error_message(): string {
            return 'mock';
        }

        public function get_error_code(): string {
            return 'mock_error';
        }
    }
}

if (!function_exists('is_wp_error')) {
    function is_wp_error($thing): bool {
        return $thing instanceof WP_Error;
    }
}

if (!function_exists('get_option')) {
    function get_option(string $key, $default = false) {
        return $GLOBALS['wd_options'][$key] ?? $default;
    }

    function update_option(string $key, $value, $autoload = null): bool {
        $GLOBALS['wd_options'][$key] = $value;
        return true;
    }

    function add_option(string $key, $value, $deprecated = '', $autoload = null): bool {
        if (array_key_exists($key, $GLOBALS['wd_options'])) {
            return false;
        }
        $GLOBALS['wd_options'][$key] = $value;
        return true;
    }

    function delete_option(string $key): bool {
        unset($GLOBALS['wd_options'][$key]);
        return true;
    }

    function get_transient(string $key) {
        return $GLOBALS['wd_transients'][$key] ?? false;
    }

    function set_transient(string $key, $value, int $expiration = 0): bool {
        $GLOBALS['wd_transients'][$key] = $value;
        return true;
    }

    function delete_transient(string $key): bool {
        unset($GLOBALS['wd_transients'][$key]);
        return true;
    }

    function get_users(array $args = []): array {
        return $GLOBALS['wd_users'];
    }

    function wp_check_password(string $password, string $hash, $userId = 0): bool {
        return $password === $hash;
    }

    function current_time(string $type = 'timestamp') {
        return $type === 'mysql' ? date('Y-m-d H:i:s') : time();
    }

    function home_url(string $path = ''): string {
        return WATCHDOG_TEST_HOME . $path;
    }

    function site_url(string $path = ''): string {
        return WATCHDOG_TEST_HOME . $path;
    }

    function get_bloginfo(string $show = ''): string {
        return $show === 'version' ? WATCHDOG_TEST_CORE_VERSION : 'Test Site';
    }

    function get_locale(): string {
        return 'en_US';
    }

    function apply_filters(string $tag, $value) {
        return $value;
    }

    function wp_parse_url(string $url, int $component = -1) {
        return parse_url($url, $component);
    }

    function sanitize_key(string $key): string {
        return strtolower((string) preg_replace('/[^a-z0-9_\-]/i', '', $key));
    }

    function sanitize_file_name(string $name): string {
        return trim(str_replace(['..', '/', '\\', ':', ';', ' '], '', $name));
    }

    function sanitize_text_field(string $str): string {
        return trim($str);
    }

    function wp_remote_get($url, array $args = []) {
        return new WP_Error('http_request_failed', 'offline');
    }

    function wp_remote_retrieve_body($response): string {
        return is_wp_error($response) ? '' : '';
    }

    function wp_remote_retrieve_response_code($response): int {
        return is_wp_error($response) ? 0 : 200;
    }

    function wp_upload_dir(): array {
        return ['basedir' => sys_get_temp_dir() . '/wd-uploads-mock'];
    }

    function wp_json_encode($data, int $flags = 0): string {
        return json_encode($data, $flags);
    }

    function wp_mkdir_p(string $dir): bool {
        return is_dir($dir) || mkdir($dir, 0777, true);
    }
}

class WD_Wpdb {
    public string $prefix = 'wp_';
    public string $posts = 'wp_posts';
    public string $comments = 'wp_comments';

    public function prepare(string $query, ...$args): string {
        return $query;
    }

    public function get_results(string $query, $output = null): array {
        return strpos($query, 'wp_comments') !== false
            ? $GLOBALS['wd_db_comments']
            : $GLOBALS['wd_db_posts'];
    }

    public function get_var(?string $query = null, ...$args) {
        return null;
    }

    public function query(string $query): bool {
        return true;
    }
}

$GLOBALS['wpdb'] = new WD_Wpdb();

/* ------------------------------------------------------------------
 * Test harness helpers
 * ---------------------------------------------------------------- */

$GLOBALS['wd_tests'] = 0;
$GLOBALS['wd_failed'] = [];

function t(string $name, callable $fn): void {
    $GLOBALS['wd_tests']++;
    try {
        $fn();
    } catch (Throwable $e) {
        $GLOBALS['wd_failed'][] = $name . ' => ' . $e->getMessage();
    }
}

function ok(bool $cond, string $msg): void {
    if (!$cond) {
        throw new RuntimeException($msg);
    }
}

function eq($actual, $expected, string $msg = ''): void {
    if ($actual !== $expected) {
        throw new RuntimeException(
            $msg . ' expected=' . var_export($expected, true) . ' actual=' . var_export($actual, true)
        );
    }
}

function same($actual, $expected, string $msg = ''): void {
    eq($actual, $expected, $msg);
}

/**
 * Decode payload #i from payloads.php (byte arrays decoded at runtime
 * with chr() — this file never contains executable code samples).
 */
function wd_payload(int $i): string {
    static $payloads = null;
    if ($payloads === null) {
        $payloads = require __DIR__ . '/payloads.php';
    }
    return implode('', array_map('chr', $payloads[$i]));
}

function wd_tree(): string {
    $base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wd-test-' . bin2hex(random_bytes(4));
    foreach (['uploads', 'imgroot', 'outside', 'core'] as $sub) {
        @mkdir($base . DIRECTORY_SEPARATOR . $sub, 0777, true);
    }
    return $base;
}

function wd_rmrf(string $dir): void {
    if (!is_dir($dir)) {
        return;
    }
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $entry) {
        if ($entry->isDir()) {
            @rmdir($entry->getPathname());
        } else {
            @unlink($entry->getPathname());
        }
    }
    @rmdir($dir);
}

function wd_fixture(string $dir, string $rel, string $content): string {
    $path = $dir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
    @mkdir(dirname($path), 0777, true);
    file_put_contents($path, $content);
    return $path;
}

function wd_file(string $content): string {
    $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wd-f-' . bin2hex(random_bytes(4)) . '.php';
    file_put_contents($path, $content);
    return $path;
}

function wd_findings_ids(array $findings): array {
    return array_values(array_filter(array_map(
        static function ($item): string {
            return isset($item['id']) ? (string) $item['id'] : '';
        },
        $findings
    )));
}

function wd_admin(string $login, string $pass, string $registered, int $id = 1): stdClass {
    $u = new stdClass();
    $u->ID = $id;
    $u->user_login = $login;
    $u->user_pass = $pass;
    $u->user_registered = $registered;
    return $u;
}

/* ------------------------------------------------------------------
 * heuristics
 * ---------------------------------------------------------------- */

t('heuristics: clean php produces no signatures', function (): void {
    eq(Heuristics::scan(wd_payload(9), 'php'), [], 'clean scan');
});

t('heuristics: empty signature set classifies as clean', function (): void {
    eq(Heuristics::classify([])['sev'], '', 'empty sev');
});

t('heuristics: request-param command payload is critical', function (): void {
    eq(Heuristics::classify(Heuristics::scan(wd_payload(0), 'php'))['sev'], 'critical', 'sev');
});

t('heuristics: request-param command payload has critical signature', function (): void {
    ok(Heuristics::hasCriticalSignature(Heuristics::scan(wd_payload(0), 'php')), 'missing');
});

t('heuristics: encoded eval request is critical', function (): void {
    eq(Heuristics::classify(Heuristics::scan(wd_payload(1), 'php'))['sev'], 'critical', 'sev');
});

t('heuristics: encoded eval request has critical signature', function (): void {
    ok(Heuristics::hasCriticalSignature(Heuristics::scan(wd_payload(1), 'php')), 'missing');
});

t('heuristics: fixed command string is warning, not critical', function (): void {
    eq(Heuristics::classify(Heuristics::scan(wd_payload(2), 'php'))['sev'], 'warning', 'sev');
});

t('heuristics: fixed command string has no critical signature', function (): void {
    ok(!Heuristics::hasCriticalSignature(Heuristics::scan(wd_payload(2), 'php')), 'unexpected');
});

t('heuristics: shell command primitive is warning', function (): void {
    eq(Heuristics::classify(Heuristics::scan(wd_payload(3), 'php'))['sev'], 'warning', 'sev');
});

t('heuristics: process exec primitive is warning', function (): void {
    eq(Heuristics::classify(Heuristics::scan(wd_payload(4), 'php'))['sev'], 'warning', 'sev');
});

t('heuristics: inflate-only payload is warning', function (): void {
    eq(Heuristics::classify(Heuristics::scan(wd_payload(5), 'php'))['sev'], 'warning', 'sev');
});

t('heuristics: two distinct warning categories escalate to critical', function (): void {
    $r = Heuristics::classify(Heuristics::scan(wd_payload(6), 'php'));
    eq($r['sev'], 'critical', 'sev');
    eq($r['label'], 'multiple suspicious indicators', 'label');
});

t('heuristics: eval of a fixed literal is warning', function (): void {
    eq(Heuristics::classify(Heuristics::scan(wd_payload(7), 'php'))['sev'], 'warning', 'sev');
});

t('heuristics: eval over decoded string is critical', function (): void {
    eq(Heuristics::classify(Heuristics::scan(wd_payload(8), 'php'))['sev'], 'critical', 'sev');
});

t('heuristics: eval over decoded string has critical signature', function (): void {
    ok(Heuristics::hasCriticalSignature(Heuristics::scan(wd_payload(8), 'php')), 'missing');
});

t('heuristics: benign markup classifies clean', function (): void {
    $found = Heuristics::scan(wd_payload(9), 'php');
    ok($found === [] || Heuristics::classify($found)['sev'] === '', 'not clean');
});

t('heuristics: seo keyword payload is warning', function (): void {
    eq(Heuristics::classify(Heuristics::scan(wd_payload(10), 'php'))['sev'], 'warning', 'sev');
});

t('heuristics: keyword inside a longer word does not match', function (): void {
    eq(Heuristics::scan('word specialised word', 'php'), [], 'false positive');
});

t('heuristics: js location usage is info only', function (): void {
    eq(Heuristics::classify(Heuristics::scan('window.location.href = "https://x.example/";', 'js'))['sev'], 'info', 'sev');
});

t('heuristics: js decoders never escalate on their own', function (): void {
    $found = Heuristics::scan('var s = atob("aGk="); window.location.assign(s);', 'js');
    eq(Heuristics::classify($found)['sev'], 'info', 'sev');
});

t('heuristics: js exec keyword is not a php execution primitive', function (): void {
    eq(Heuristics::scan('var r = /x/.exec("x");', 'js'), [], 'false positive');
});

t('heuristics: entropy blob without decoder context is ignored', function (): void {
    eq(Heuristics::scan(str_repeat('A', 100), 'php'), [], 'blob flagged');
});

t('heuristics: entropy blob with decoder context is info', function (): void {
    $content = '<?php ' . wd_payload(11) . '("' . str_repeat('A', 90) . '");';
    $found = Heuristics::scan($content, 'php');
    ok(in_array('High-entropy blob', $found, true), 'blob missing');
    eq(Heuristics::classify($found)['sev'], 'info', 'sev');
});

t('heuristics: wp redirect primitive is info', function (): void {
    eq(Heuristics::classify(Heuristics::scan('wp_redirect("https://x.example/");', 'php'))['sev'], 'info', 'sev');
});

t('heuristics: header location primitive is info', function (): void {
    eq(Heuristics::classify(Heuristics::scan('header("Location: https://x.example/");', 'php'))['sev'], 'info', 'sev');
});

t('heuristics: remote include is warning', function (): void {
    eq(Heuristics::classify(Heuristics::scan('include("http://x.example/a.php");', 'php'))['sev'], 'warning', 'sev');
});

t('heuristics: shortener domain is info', function (): void {
    eq(Heuristics::classify(Heuristics::scan('http://bit.ly/abc', 'php'))['sev'], 'info', 'sev');
});

t('heuristics: malware domain is critical', function (): void {
    eq(Heuristics::classify(Heuristics::scan('http://ushort.company/x', 'php'))['sev'], 'critical', 'sev');
});

t('heuristics: miner marker is warning', function (): void {
    eq(Heuristics::classify(Heuristics::scan('coinhive.min.js', 'php'))['sev'], 'warning', 'sev');
});

t('heuristics: hidden iframe in html is warning', function (): void {
    eq(Heuristics::classify(Heuristics::scan('<iframe src="http://x.example/" style="display:none"></iframe>', 'html'))['sev'], 'warning', 'sev');
});

t('heuristics: hidden iframe pattern does not match js files', function (): void {
    eq(Heuristics::scan('<iframe src="http://x.example/" style="display:none"></iframe>', 'js'), [], 'false positive');
});

t('heuristics: new Function in js is info only', function (): void {
    eq(Heuristics::classify(Heuristics::scan('var f = new Function("return this");', 'js'))['sev'], 'info', 'sev');
});

t('heuristics: severity ranking order', function (): void {
    eq(Heuristics::rank('critical'), 3, 'critical');
    eq(Heuristics::rank('warning'), 2, 'warning');
    eq(Heuristics::rank('info'), 1, 'info');
    eq(Heuristics::rank('safe'), 0, 'safe');
});

t('heuristics: locateLines finds the exact flagged line', function (): void {
    $dir = wd_tree();
    try {
        $path = $dir . '/sample.php';
        $code = "<?php\n\$ok = true;\n\$x = 'clean line';\nshell_exec(\$cmd);\nheader('Location: https://x.example/');\n";
        file_put_contents($path, $code);
        $found = Heuristics::scan($code, 'php');
        ok(in_array('Execution: shell_exec()', $found, true), 'shell_exec not matched');
        $lines = Heuristics::locateLines($path, $found);
        $byLine = [];
        foreach ($lines as $hit) {
            $byLine[$hit['line']] = $hit['code'];
        }
        ok(isset($byLine[4]), 'line 4 (shell_exec) not located; got ' . implode(',', array_keys($byLine)));
        ok(strpos((string) $byLine[4], 'shell_exec') !== false, 'line 4 text mismatch: ' . ($byLine[4] ?? ''));
        ok(strpos((string) ($byLine[5] ?? ''), 'header') !== false, 'line 5 text mismatch: ' . ($byLine[5] ?? ''));
    } finally {
        wd_rmrf($dir);
    }
});

/* ------------------------------------------------------------------
 * trust
 * ---------------------------------------------------------------- */

t('trust: unknown plugin has unknown level', function (): void {
    eq(Trust::level('some-unknown-plugin'), Trust::UNKNOWN, 'level');
});

t('trust: official plugin ships with official level', function (): void {
    eq(Trust::level('woocommerce'), Trust::OFFICIAL, 'level');
});

t('trust: set trusted level persists', function (): void {
    Trust::set('my-custom-plugin', Trust::TRUSTED, 'plugin');
    eq(Trust::level('my-custom-plugin'), Trust::TRUSTED, 'level');
});

t('trust: reset to unknown removes the entry', function (): void {
    Trust::set('my-custom-plugin', Trust::UNKNOWN, 'plugin');
    eq(Trust::level('my-custom-plugin'), Trust::UNKNOWN, 'level');
});

t('trust: themes default to unknown', function (): void {
    eq(Trust::level('twentytwentyfour', 'theme'), Trust::UNKNOWN, 'level');
});

t('trust: trusted theme persists', function (): void {
    Trust::set('my-custom-theme', Trust::TRUSTED, 'theme');
    eq(Trust::level('my-custom-theme', 'theme'), Trust::TRUSTED, 'level');
});

t('trust: official list is non-empty', function (): void {
    ok(count(Trust::defaultOfficial()) > 10, 'too small');
});

/* ------------------------------------------------------------------
 * redirect engine
 * ---------------------------------------------------------------- */

t('redirect: relative destination is safe', function (): void {
    $r = RedirectEngine::classify(['dest' => '/some/page', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    eq($r['class'], RedirectEngine::SAFE, 'class');
});

t('redirect: same-host destination is expected', function (): void {
    $r = RedirectEngine::classify(['dest' => 'https://random.local/other', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    eq($r['class'], RedirectEngine::EXPECTED, 'class');
});

t('redirect: subdomain is same host when allowed', function (): void {
    $r = RedirectEngine::classify(['dest' => 'https://sub.random.local/other', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    eq($r['class'], RedirectEngine::EXPECTED, 'class');
});

t('redirect: subdomain is external when subdomains disallowed', function (): void {
    update_option('watchdog_allow_subdomains', 0);
    $r = RedirectEngine::classify(['dest' => 'https://sub.random.local/other', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    update_option('watchdog_allow_subdomains', 1);
    ok(in_array($r['class'], [RedirectEngine::MALICIOUS, RedirectEngine::SUSPICIOUS], true), 'not flagged: ' . $r['class']);
});

t('redirect: javascript scheme is malicious', function (): void {
    $r = RedirectEngine::classify(['dest' => 'javascript:alert(1)', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    eq($r['class'], RedirectEngine::MALICIOUS, 'class');
});

t('redirect: wordpress.org destination is expected', function (): void {
    $r = RedirectEngine::classify(['dest' => 'https://wordpress.org/plugins/x/', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    eq($r['class'], RedirectEngine::EXPECTED, 'class');
});

t('redirect: whitelisted domain is expected', function (): void {
    update_option('watchdog_whitelist_domains', "example.net\ngood-site.com");
    $r = RedirectEngine::classify(['dest' => 'https://example.net/path', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    eq($r['class'], RedirectEngine::EXPECTED, 'class');
    delete_option('watchdog_whitelist_domains');
});

t('redirect: whitelisted pattern is expected', function (): void {
    update_option('watchdog_whitelist_patterns', 'cdn-cdn\.net');
    $r = RedirectEngine::classify(['dest' => 'https://static.cdn-cdn.net/x.js', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    eq($r['class'], RedirectEngine::EXPECTED, 'class');
    delete_option('watchdog_whitelist_patterns');
});

t('redirect: system path destination is expected', function (): void {
    $r = RedirectEngine::classify(['dest' => 'https://other.example.com/wp-login.php', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    eq($r['class'], RedirectEngine::EXPECTED, 'class');
});

t('redirect: monitor-only mode reflects the option', function (): void {
    update_option('watchdog_monitor_only', 1);
    ok(RedirectEngine::monitorOnly(), 'should be on');
    update_option('watchdog_monitor_only', 0);
    ok(!RedirectEngine::monitorOnly(), 'should be off');
});

t('redirect: plain external redirect from unknown plugin is suspicious, not malicious', function (): void {
    $file = WP_PLUGIN_DIR . '/mystery-plugin/index.php';
    $r = RedirectEngine::classify(['dest' => 'https://evil.example.net/steal', 'method' => 'href', 'line' => 1], $file);
    eq($r['class'], RedirectEngine::SUSPICIOUS, 'class');
});

t('redirect: external redirect from trusted plugin is expected', function (): void {
    Trust::set('mystery-plugin', Trust::TRUSTED, 'plugin');
    $file = WP_PLUGIN_DIR . '/mystery-plugin/index.php';
    $r = RedirectEngine::classify(['dest' => 'https://evil.example.net/steal', 'method' => 'href', 'line' => 1], $file);
    eq($r['class'], RedirectEngine::EXPECTED, 'class');
    Trust::set('mystery-plugin', Trust::UNKNOWN, 'plugin');
});

t('redirect: external redirect from uploads is suspicious', function (): void {
    $file = WP_CONTENT_DIR . '/uploads/2026/01/pic.php';
    $r = RedirectEngine::classify(['dest' => 'https://evil.example.net/x', 'method' => 'href', 'line' => 1], $file);
    eq($r['class'], RedirectEngine::SUSPICIOUS, 'class');
});

t('redirect: obfuscated external destination from unknown source is malicious', function (): void {
    $r = RedirectEngine::classify([
        'dest' => 'https://evil.example.net/x',
        'method' => 'href',
        'arg' => wd_payload(11) . '("aGVsbG8=")',
        'line' => 1,
    ], WP_PLUGIN_DIR . '/unknown-thing/index.php');
    eq($r['class'], RedirectEngine::MALICIOUS, 'class');
});

t('redirect: obfuscated external destination in verified source is expected', function (): void {
    Trust::set('verified-thing', Trust::OFFICIAL, 'plugin');
    $r = RedirectEngine::classify([
        'dest' => 'https://example.net/x',
        'method' => 'href',
        'arg' => wd_payload(11) . '("aGVsbG8=")',
        'line' => 1,
    ], WP_PLUGIN_DIR . '/verified-thing/index.php');
    eq($r['class'], RedirectEngine::EXPECTED, 'class');
    Trust::set('verified-thing', Trust::UNKNOWN, 'plugin');
});

t('redirect: mobile-gated external from unknown source is suspicious', function (): void {
    $r = RedirectEngine::classify([
        'dest' => 'https://evil.example.net/x',
        'method' => 'href',
        'mobile' => true,
        'line' => 1,
    ], WP_PLUGIN_DIR . '/other-plugin/index.php');
    eq($r['class'], RedirectEngine::SUSPICIOUS, 'class');
});

t('redirect: mobile-gated external from trusted source is suspicious', function (): void {
    Trust::set('other-plugin', Trust::TRUSTED, 'plugin');
    $r = RedirectEngine::classify([
        'dest' => 'https://evil.example.net/x',
        'method' => 'href',
        'mobile' => true,
        'line' => 1,
    ], WP_PLUGIN_DIR . '/other-plugin/index.php');
    eq($r['class'], RedirectEngine::SUSPICIOUS, 'class');
    Trust::set('other-plugin', Trust::UNKNOWN, 'plugin');
});

t('redirect: unresolved destination from trusted source is expected', function (): void {
    Trust::set('dyn-plugin', Trust::TRUSTED, 'plugin');
    $r = RedirectEngine::classify(['dest' => '', 'method' => 'header', 'line' => 3], WP_PLUGIN_DIR . '/dyn-plugin/index.php');
    eq($r['class'], RedirectEngine::EXPECTED, 'class');
    Trust::set('dyn-plugin', Trust::UNKNOWN, 'plugin');
});

t('redirect: unresolved obfuscated destination from unknown source is suspicious', function (): void {
    $r = RedirectEngine::classify(['dest' => '', 'method' => 'header', 'arg' => wd_payload(11) . '("eA==")', 'line' => 3], WP_PLUGIN_DIR . '/unknown-thing/index.php');
    eq($r['class'], RedirectEngine::SUSPICIOUS, 'class');
});

t('redirect: unresolved obfuscated destination from trusted source is expected', function (): void {
    Trust::set('dyn-plugin', Trust::TRUSTED, 'plugin');
    $r = RedirectEngine::classify(['dest' => '', 'method' => 'header', 'arg' => wd_payload(11) . '("eA==")', 'line' => 3], WP_PLUGIN_DIR . '/dyn-plugin/index.php');
    eq($r['class'], RedirectEngine::EXPECTED, 'class');
    Trust::set('dyn-plugin', Trust::UNKNOWN, 'plugin');
});

t('redirect: origin detection for plugin paths', function (): void {
    $o = RedirectEngine::originOf(WP_PLUGIN_DIR . '/woocommerce/woocommerce.php');
    eq($o['plugin'], 'woocommerce', 'plugin');
});

t('redirect: origin detection for core paths', function (): void {
    $o = RedirectEngine::originOf(ABSPATH . 'wp-includes/version.php');
    ok($o['core'], 'not core');
});

t('redirect: origin detection for uploads paths', function (): void {
    $o = RedirectEngine::originOf(WP_CONTENT_DIR . '/uploads/img/x.jpg');
    ok($o['uploads'], 'not uploads');
});

t('redirect: scheme helpers', function (): void {
    ok(RedirectEngine::hasNonWebScheme('javascript:void(0)'), 'scheme');
    ok(RedirectEngine::isPayloadScheme('data:text/html,x'), 'payload scheme');
    ok(!RedirectEngine::hasNonWebScheme('https://x.example/'), 'https');
});

t('redirect: relative url helper', function (): void {
    ok(RedirectEngine::isRelative('/relative'), 'path');
    ok(RedirectEngine::isRelative('?query=1'), 'query');
    ok(!RedirectEngine::isRelative('//cdn.example.net/x.js'), 'protocol-relative');
});

t('redirect: denied host google.com is malicious from any source', function (): void {
    delete_option('watchdog_denied_domains');
    $r = RedirectEngine::classify(['dest' => 'https://www.google.com/search?q=x', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    eq($r['class'], RedirectEngine::MALICIOUS, 'class');
    eq($r['confidence'], RedirectEngine::CONFIDENCE_HIGH, 'confidence');
});

t('redirect: denied host ushort.company is malicious', function (): void {
    delete_option('watchdog_denied_domains');
    $r = RedirectEngine::classify(['dest' => 'https://ushort.company/x', 'method' => 'href', 'line' => 1], WP_PLUGIN_DIR . '/trusted-plugin/index.php');
    eq($r['class'], RedirectEngine::MALICIOUS, 'class');
    $r = RedirectEngine::classifyServerRedirect('http://ushort.company/abc', ['plugin' => 'known-plugin', 'theme' => '', 'core' => false, 'uploads' => false]);
    eq($r['class'], RedirectEngine::MALICIOUS, 'server class');
    eq($r['confidence'], RedirectEngine::CONFIDENCE_HIGH, 'confidence');
});

t('redirect: denied host t.co is malicious even from a trusted plugin', function (): void {
    Trust::set('trusted-plugin', Trust::TRUSTED, 'plugin');
    $r = RedirectEngine::classify(['dest' => 'https://t.co/abc123', 'method' => 'href', 'line' => 1], WP_PLUGIN_DIR . '/trusted-plugin/index.php');
    eq($r['class'], RedirectEngine::MALICIOUS, 'class');
    Trust::set('trusted-plugin', Trust::UNKNOWN, 'plugin');
});

t('redirect: subdomain of a denied host is malicious', function (): void {
    $r = RedirectEngine::classify(['dest' => 'https://www.t.co/abc', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    eq($r['class'], RedirectEngine::MALICIOUS, 'class');
});

t('redirect: lookalike host is not denied', function (): void {
    $r = RedirectEngine::classify(['dest' => 'https://google.com.evil.net/steal', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    ok($r['class'] !== RedirectEngine::MALICIOUS, 'not denied: ' . $r['class']);
});

t('redirect: server redirect to denied host is blocked from a trusted source', function (): void {
    $origin = ['plugin' => 'known-plugin', 'theme' => '', 'core' => false, 'uploads' => false];
    $r = RedirectEngine::classifyServerRedirect('https://t.co/x', $origin);
    eq($r['class'], RedirectEngine::MALICIOUS, 't.co');
    $r = RedirectEngine::classifyServerRedirect('https://www.google.com/x', $origin);
    eq($r['class'], RedirectEngine::MALICIOUS, 'google.com');
    eq($r['confidence'], RedirectEngine::CONFIDENCE_HIGH, 'high confidence');
});

t('redirect: deny list honors a custom option', function (): void {
    update_option('watchdog_denied_domains', "evil.example.com\nmalware.test");
    $r = RedirectEngine::classify(['dest' => 'https://sub.malware.test/x', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    eq($r['class'], RedirectEngine::MALICIOUS, 'custom host denied');
    $r = RedirectEngine::classify(['dest' => 'https://t.co/abc', 'method' => 'href', 'line' => 1], ABSPATH . 'index.php');
    ok($r['class'] !== RedirectEngine::MALICIOUS, 'defaults replaced by custom list: ' . $r['class']);
    delete_option('watchdog_denied_domains');
});

/* ------------------------------------------------------------------
 * execution context
 * ---------------------------------------------------------------- */

t('context: clean php yields no findings', function (): void {
    eq(ExecutionContext::analyzeFile('<?php echo "hello";', ABSPATH . 'index.php'), [], 'findings');
});

t('context: benign markup yields no findings', function (): void {
    eq(ExecutionContext::analyzeFile(wd_payload(9), ABSPATH . 'index.php'), [], 'findings');
});

t('context: eval of fixed literal is not malicious', function (): void {
    $findings = ExecutionContext::analyzeFile(wd_payload(7), WP_PLUGIN_DIR . '/known-plugin/index.php');
    ok($findings !== [], 'no findings at all');
    foreach ($findings as $f) {
        ok(($f['class'] ?? '') !== RedirectEngine::MALICIOUS, 'malicious verdict on literal eval');
    }
});

t('context: encoded eval stays malicious in any origin', function (): void {
    foreach ([WP_PLUGIN_DIR . '/known-plugin/index.php', ABSPATH . 'wp-includes/version.php'] as $path) {
        $findings = ExecutionContext::analyzeFile(wd_payload(8), $path);
        $seen = false;
        foreach ($findings as $f) {
            if (($f['class'] ?? '') === RedirectEngine::MALICIOUS) {
                $seen = true;
            }
        }
        ok($seen, 'encoded eval not malicious in ' . $path);
    }
});

t('context: encoded eval request is malicious', function (): void {
    $findings = ExecutionContext::analyzeFile(wd_payload(1), WP_PLUGIN_DIR . '/other/index.php');
    $seen = false;
    foreach ($findings as $f) {
        if (($f['class'] ?? '') === RedirectEngine::MALICIOUS) {
            $seen = true;
        }
    }
    ok($seen, 'not malicious');
});

t('context: webpack-style Function runtime is not malicious', function (): void {
    $js = '(function () { var g = new Function("return this")(); return g; })();';
    Trust::set('bundled', Trust::TRUSTED, 'plugin');
    foreach ([WP_PLUGIN_DIR . '/bundled/index.js'] as $path) {
        foreach (ExecutionContext::analyzeFile($js, $path) as $f) {
            ok(($f['class'] ?? '') !== RedirectEngine::MALICIOUS, 'false malicious in ' . $path);
        }
    }
    Trust::set('bundled', Trust::UNKNOWN, 'plugin');
    foreach (ExecutionContext::analyzeFile($js, ABSPATH . 'wp-includes/js/x.js') as $f) {
        ok(($f['severity'] ?? '') !== 'critical', 'core path over-escalated');
        ok(($f['confidence'] ?? '') !== 'high', 'core path over-escalated');
    }
});

t('context: incident report has the expected shape', function (): void {
    $f = ExecutionContext::analyzeFile(wd_payload(8), WP_PLUGIN_DIR . '/known-plugin/index.php');
    $report = ExecutionContext::incidentReport($f[0]);
    foreach (['confidence', 'risk_score', 'execution_context', 'filename', 'plugin_theme', 'line', 'destination', 'trigger', 'reason', 'action'] as $key) {
        ok(array_key_exists($key, $report), 'missing key ' . $key);
    }
});

t('context: action mapping covers confidence levels', function (): void {
    ok(ExecutionContext::actionFor('critical') !== '', 'critical');
    ok(ExecutionContext::actionFor('high') !== '', 'high');
    ok(ExecutionContext::actionFor('medium') !== '', 'medium');
    ok(ExecutionContext::actionFor('low') !== '', 'low');
});

t('context: redirect to a denied host is critical in any file', function (): void {
    $js = 'window.location.href = "https://www.google.com/x";';
    $seen = false;
    foreach (ExecutionContext::analyzeFile($js, ABSPATH . 'wp-includes/js/x.js') as $f) {
        $seen = true;
        eq($f['class'] ?? '', RedirectEngine::MALICIOUS, 'class');
        eq($f['severity'] ?? '', 'critical', 'severity');
    }
    ok($seen, 'no finding produced');
});

t('context: delayed JS redirect to a denied host is critical', function (): void {
    $js = 'window.setTimeout(function () { location.href = "https://t.co/xyz"; }, 4000);';
    $seen = false;
    foreach (ExecutionContext::analyzeFile($js, WP_PLUGIN_DIR . '/trusted-plugin/index.js') as $f) {
        $seen = true;
        eq($f['class'] ?? '', RedirectEngine::MALICIOUS, 'class');
    }
    ok($seen, 'no finding produced');
});

/* ------------------------------------------------------------------
 * checksums
 * ---------------------------------------------------------------- */

t('checksums: default verify status is idle', function (): void {
    $status = Checksums::verifyStatus();
    eq($status['active'], '', 'active');
    eq($status['packages']['installed'], 0, 'installed');
});

t('checksums: markActive surfaces in status', function (): void {
    Checksums::markActive('core');
    eq(Checksums::verifyStatus()['active'], 'core', 'active');
});

t('checksums: markIdle clears the marker', function (): void {
    Checksums::markIdle();
    eq(Checksums::verifyStatus()['active'], '', 'active');
});

t('checksums: package result defaults empty', function (): void {
    eq(Checksums::packageResult('plugin', 'nope'), [], 'result');
});

t('checksums: core verify result defaults empty', function (): void {
    eq(Checksums::coreVerifyResult(), [], 'result');
});

t('checksums: core tree trust for wp-includes', function (): void {
    ok(Checksums::coreTreeTrust(ABSPATH . 'wp-includes/version.php'), 'wp-includes not trusted');
});

t('checksums: core tree trust for root php files', function (): void {
    ok(Checksums::coreTreeTrust(ABSPATH . 'index.php'), 'index.php not trusted');
});

t('checksums: core tree trust rejects plugin files', function (): void {
    ok(!Checksums::coreTreeTrust(WP_PLUGIN_DIR . '/x/index.php'), 'plugin trusted');
});

/* ------------------------------------------------------------------
 * site checks
 * ---------------------------------------------------------------- */

t('site-checks: high-sensitivity option set has 10 checks', function (): void {
    eq(count(SiteChecks::OPTIONS), 10, 'count');
});

t('site-checks: every check defaults to on', function (): void {
    foreach (array_keys(SiteChecks::OPTIONS) as $option) {
        ok(SiteChecks::enabled($option), $option . ' not enabled by default');
    }
});

t('site-checks: disabled check reports off', function (): void {
    update_option('watchdog_check_passwords', 0);
    ok(!SiteChecks::enabled('watchdog_check_passwords'), 'still on');
    delete_option('watchdog_check_passwords');
});

t('site-checks: plain filenames are fine', function (): void {
    eq(SiteChecks::suspectedName('notes.php'), '', 'notes.php flagged');
    eq(SiteChecks::suspectedName('page-2.html'), '', 'html flagged');
});

t('site-checks: kit-style filenames are flagged', function (): void {
    ok(SiteChecks::suspectedName('c99.php') !== '', 'c99 not flagged');
    ok(SiteChecks::suspectedName('r57shell.php') !== '', 'r57 not flagged');
    ok(SiteChecks::suspectedName('wso.php') !== '', 'wso not flagged');
});

t('site-checks: core root files are not flagged as shell names', function (): void {
    eq(SiteChecks::suspectedName('xmlrpc.php'), '', 'xmlrpc.php flagged');
    eq(SiteChecks::suspectedName('wp-login.php'), '', 'wp-login.php flagged');
});

t('site-checks: random hex names are flagged', function (): void {
    ok(SiteChecks::suspectedName('a3f9c2b8e7d4f60123456789abcdef01.php') !== '', 'not flagged');
});

t('site-checks: spam iframe content is detected', function (): void {
    ok(SiteChecks::matchSpam('<iframe src="http://x.example/" style="display:none"></iframe>') !== '', 'not detected');
});

t('site-checks: seo keyword content is detected', function (): void {
    ok(SiteChecks::matchSpam(wd_payload(10)) !== '', 'not detected');
});

t('site-checks: clean content passes', function (): void {
    eq(SiteChecks::matchSpam('A normal post about gardening and recipes.'), '', 'false positive');
});

t('site-checks: encoded payload content is detected', function (): void {
    $content = wd_payload(11) . '("x")';
    ok(SiteChecks::matchSpam($content) !== '', 'not detected');
});

t('site-checks: miner content is detected', function (): void {
    ok(SiteChecks::matchSpam('coin-hive/Coinhive.min.js') !== '', 'not detected');
});

t('site-checks: shortener content is detected', function (): void {
    ok(SiteChecks::matchSpam('<a href="http://bit.ly/abc">more</a>') !== '', 'not detected');
});

t('site-checks: plain image content is clean', function (): void {
    eq(SiteChecks::matchImagePayload('GIF89a binary data here without php'), '', 'false positive');
});

t('site-checks: php without exec calls in image is informational', function (): void {
    eq(SiteChecks::matchImagePayload(wd_payload(9)), 'PHP code embedded in image', 'label');
});

t('site-checks: exec-carrying php in image is flagged strongly', function (): void {
    eq(SiteChecks::matchImagePayload(wd_payload(2)), 'PHP payload with executable calls', 'label');
});

t('site-checks: script tag content in images is detected', function (): void {
    eq(SiteChecks::matchImagePayload('<script src="http://x.example/a.js"></script>'), 'JavaScript embedded in SVG/HTML payload', 'label');
});

t('site-checks: suspected files walk finds php in uploads', function (): void {
    $tree = wd_tree();
    wd_fixture($tree, 'uploads/evil.php', wd_payload(0));
    wd_fixture($tree, 'uploads/photo.jpg.php', wd_payload(9));
    wd_fixture($tree, 'uploads/clean.php5', wd_payload(9));
    $findings = SiteChecks::suspectedFiles($tree . DIRECTORY_SEPARATOR . 'uploads');
    $ids = wd_findings_ids($findings);
    $labels = array_column($findings, 'label');
    eq(count($ids), 3, 'count: ' . implode(' | ', array_map('strval', $labels)));
    ok(in_array('suspected_file', $ids, true), 'missing id');
    $labels = array_column($findings, 'label');
    ok(count(array_filter($labels, static fn ($l) => strpos((string) $l, 'Double-extension') !== false)) === 1, 'double-extension label missing');
    wd_rmrf($tree);
});

t('site-checks: image scan finds embedded payloads', function (): void {
    $tree = wd_tree();
    wd_fixture($tree, 'imgroot/bad.gif', 'GIF89a' . wd_payload(2));
    wd_fixture($tree, 'imgroot/ok.png', 'GIF89a plain bytes');
    wd_fixture($tree, 'imgroot/soft.php', wd_payload(9));
    $findings = SiteChecks::scanImages(10.0, $tree . DIRECTORY_SEPARATOR . 'imgroot');
    $ids = wd_findings_ids($findings);
    ok(in_array('image_payload', $ids, true), 'missing image_payload: ' . implode(',', $ids));
    foreach ($findings as $f) {
        if (strpos((string) $f['label'], 'bad.gif') !== false || strpos((string) $f['details'], 'bad.gif') !== false) {
            eq($f['sev'], 'warning', 'bad.gif severity');
        }
    }
    wd_rmrf($tree);
});

t('site-checks: outside scan finds php outside the install', function (): void {
    $tree = wd_tree();
    wd_fixture($tree, 'outside/evil.php', wd_payload(0));
    wd_fixture($tree, 'uploads/noise.php', wd_payload(9));
    $findings = SiteChecks::scanOutside(10.0, $tree);
    $ids = wd_findings_ids($findings);
    ok(in_array('outside_wp', $ids, true), 'missing outside_wp: ' . implode(',', $ids));
    foreach ($findings as $f) {
        ok(strpos((string) $f['details'], 'noise.php') === false, 'benign file reported');
    }
    wd_rmrf($tree);
});

t('site-checks: full run surfaces the high-sensitivity findings', function (): void {
    $tree = wd_tree();

    update_option('watchdog_check_suspected_files', 0);
    update_option('watchdog_scan_images', 0);
    update_option('watchdog_scan_outside', 0);
    update_option('watchdog_check_old_versions', 1);
    update_option('admin_email', 'admin@example.com');
    update_option('users_can_register', 0);
    update_option('default_role', 'subscriber');

    set_transient('watchdog_core_latest', '6.6.0');

    $GLOBALS['wd_users'] = [
        wd_admin('admin', 'admin123', date('Y-m-d H:i:s', time() - 10 * DAY_IN_SECONDS), 1),
        wd_admin('alice', 'str0ng-Pass!', date('Y-m-d H:i:s', time() - 50 * DAY_IN_SECONDS), 2),
        wd_admin('bob', 'another-Pass!', date('Y-m-d H:i:s', time() - 5 * DAY_IN_SECONDS), 3),
        wd_admin('carol', 'yet-Another1', date('Y-m-d H:i:s', time() - 300 * DAY_IN_SECONDS), 4),
    ];

    $GLOBALS['wd_db_posts'] = [
        [
            'ID' => 7,
            'post_title' => 'Promo',
            'post_content' => '<iframe src="http://x.example/" style="display:none"></iframe>',
            'post_status' => 'publish',
            'post_type' => 'post',
        ],
        [
            'ID' => 8,
            'post_title' => 'Recipes',
            'post_content' => 'Just a normal post about gardening.',
            'post_status' => 'publish',
            'post_type' => 'post',
        ],
    ];

    $GLOBALS['wd_db_comments'] = [
        ['comment_ID' => 3, 'comment_content' => '<a href="http://bit.ly/abc" style="position:absolute">click</a>'],
        ['comment_ID' => 4, 'comment_content' => 'Thanks for the post!'],
    ];

    $findings = SiteChecks::run(25);
    $ids = wd_findings_ids($findings);

    $expected = [
        'old_core_version',
        'default_admin_user',
        'many_admins',
        'recent_admin',
        'weak_admin_password',
        'suspicious_post',
        'suspicious_comment',
        'xmlrpc_enabled',
        'file_edit_enabled',
    ];
    foreach ($expected as $id) {
        ok(in_array($id, $ids, true), 'missing finding ' . $id . ' (got: ' . implode(',', $ids) . ')');
    }

    $forbidden = [
        'open_registration',
        'privileged_default_role',
        'empty_admin_email',
        'suspected_file',
        'image_payload',
        'outside_wp',
    ];
    foreach ($forbidden as $id) {
        ok(!in_array($id, $ids, true), 'unexpected finding ' . $id);
    }

    delete_option('watchdog_check_suspected_files');
    delete_option('watchdog_scan_images');
    delete_option('watchdog_scan_outside');
    delete_option('watchdog_check_old_versions');
    delete_option('admin_email');
    delete_option('users_can_register');
    delete_option('default_role');
    delete_transient('watchdog_core_latest');
    $GLOBALS['wd_users'] = [];
    $GLOBALS['wd_db_posts'] = [];
    $GLOBALS['wd_db_comments'] = [];
    wd_rmrf($tree);
});

/* ------------------------------------------------------------------
 * scanner
 * ---------------------------------------------------------------- */

t('scanner: watchdog plugin directory is always skipped', function (): void {
    ok(Scanner::isSkipped(__DIR__ . '/run.php'), 'suite file not skipped');
    ok(Scanner::isSkipped(__DIR__ . '/../watchdog.php'), 'plugin main file not skipped');
});

t('scanner: core files are not skipped', function (): void {
    ok(!Scanner::isSkipped(ABSPATH . 'index.php'), 'index.php skipped');
    ok(!Scanner::isSkipped(ABSPATH . 'wp-includes/version.php'), 'version.php skipped');
});

t('scanner: excluded paths are skipped', function (): void {
    $tree = wd_tree();
    update_option('watchdog_exclusions', $tree);
    ok(Scanner::isSkipped($tree . DIRECTORY_SEPARATOR . 'x.php'), 'not skipped');
    delete_option('watchdog_exclusions');
    wd_rmrf($tree);
});

t('scanner: lock is released by default', function (): void {
    ok(!Scanner::scanLocked(), 'locked');
});

t('scanner: clean file scans safe', function (): void {
    $path = wd_file(wd_payload(9));
    $r = Scanner::scanFile($path);
    ok($r['hash'] !== '', 'no hash');
    eq($r['severity'], 'safe', 'severity: ' . var_export($r['severity'], true));
    unlink($path);
});

t('scanner: request-param payload file is critical', function (): void {
    $path = wd_file(wd_payload(0));
    $r = Scanner::scanFile($path);
    eq($r['severity'], 'critical', 'severity: ' . var_export($r['severity'], true));
    unlink($path);
});

t('scanner: fixed-command payload file is warning', function (): void {
    $path = wd_file(wd_payload(2));
    $r = Scanner::scanFile($path);
    eq($r['severity'], 'warning', 'severity: ' . var_export($r['severity'], true));
    unlink($path);
});

t('scanner: encoded eval payload file is critical', function (): void {
    $path = wd_file(wd_payload(8));
    $r = Scanner::scanFile($path);
    eq($r['severity'], 'critical', 'severity: ' . var_export($r['severity'], true));
    unlink($path);
});

t('scanner: core file severity stays informational via known-good clamp', function (): void {
    $path = ABSPATH . 'index.php';
    $r = Scanner::scanFile($path);
    ok(in_array($r['severity'], ['safe', 'info', ''], true), 'unexpected severity: ' . var_export($r['severity'], true));
});

t('scanner: core js with dynamic code stays informational via clamp', function (): void {
    $path = ABSPATH . 'wp-includes/js/heartbeat.min.js';
    $r = Scanner::scanFile($path);
    ok(in_array($r['severity'], ['safe', 'info', ''], true), 'unexpected severity: ' . var_export($r['severity'], true));
});

t('scanner: lastScan reflects the stored summary', function (): void {
    update_option(Scanner::LAST_SCAN_OPTION, ['time' => 1234, 'mode' => 'full']);
    $run = Scanner::lastScan();
    eq($run['time'], 1234, 'time');
    eq($run['mode'], 'full', 'mode');
    delete_option(Scanner::LAST_SCAN_OPTION);
});

t('scanner: buildReport guarantees its keys', function (): void {
    update_option(Scanner::LAST_SCAN_OPTION, ['time' => 1, 'mode' => 'full']);
    $report = Scanner::buildReport();
    foreach (['time', 'mode', 'total', 'scanned', 'expected', 'malware', 'suspicious', 'info', 'changed', 'new', 'deleted', 'moved', 'domains'] as $key) {
        ok(array_key_exists($key, $report), 'missing key ' . $key);
    }
    delete_option(Scanner::LAST_SCAN_OPTION);
});

/* ------------------------------------------------------------------
 * summary
 * ---------------------------------------------------------------- */

$total = $GLOBALS['wd_tests'];
$failed = $GLOBALS['wd_failed'];

echo "Watchdog test suite\n";
echo "===================\n";
echo 'tests: ' . $total . "\n";
echo 'failed: ' . count($failed) . "\n";
if ($failed !== []) {
    echo "\nfailures:\n";
    foreach ($failed as $fail) {
        echo '  - ' . $fail . "\n";
    }
    echo "\n";
    exit(1);
}
echo "all green\n";
exit(0);
