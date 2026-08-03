<?php
/**
 * Plugin Name:       Watchdog - Real-Time Malware Detection & Response
 * Description:       SHA-256 file integrity, redirect analyzer, malware heuristics, quarantine, event timeline and email alerts.
 * Version:           3.4.6
 * Author:            Watchdog
 * Text Domain:       watchdog
 */

if (!defined('ABSPATH')) {
    exit;
}

spl_autoload_register(static function ($class) {
    $prefix = 'Watchdog\\';
    if (strpos($class, $prefix) !== 0) {
        return;
    }
    $name = strtolower(preg_replace('/(?<!^)[A-Z]/', '-$0', substr($class, strlen($prefix))));
    $file = __DIR__ . '/includes/class-' . $name . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});

use Watchdog\Plugin;

register_activation_hook(__FILE__, [Plugin::class, 'activate']);
register_deactivation_hook(__FILE__, [Plugin::class, 'deactivate']);
register_uninstall_hook(__FILE__, [Plugin::class, 'uninstall']);

add_action('plugins_loaded', static function () {
    Plugin::instance();
    Plugin::upgrade();
});
