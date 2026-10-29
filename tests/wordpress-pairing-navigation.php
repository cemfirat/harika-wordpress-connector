<?php
declare(strict_types=1);
require __DIR__ . '/fixtures/wordpress-pairing-runtime.php';

final class Pairing_Redirect extends RuntimeException {}
function expect($condition, string $message): void { if (!$condition) throw new RuntimeException($message); }
function add_options_page($title, $menu, $capability, $slug, $callback): void { $GLOBALS['pairing_admin_pages'][$slug] = $capability; }
function register_setting(...$args): void {}
function wp_doing_ajax(): bool { return false; }
function wp_doing_cron(): bool { return false; }
function is_network_admin(): bool { return !empty($GLOBALS['pairing_network']); }
function wp_safe_redirect($url): void { throw new Pairing_Redirect($url); }

function admin_request(?string $page, bool $bulk = false): string {
    $_GET = $page === null ? [] : ['page' => $page];
    $_REQUEST = $bulk ? ['activate-multi' => 1] : [];
    $GLOBALS['pairing_admin_pages'] = [];
    try {
        // WordPress loads admin_menu and checks page access before admin_init.
        // An unregistered old slug must be redirected before this real boundary.
        foreach ($GLOBALS['pairing_hooks']['admin_menu'] ?? [] as $callback) $callback();
        if ($page !== null && (!isset($GLOBALS['pairing_admin_pages'][$page]) || !current_user_can($GLOBALS['pairing_admin_pages'][$page]))) return '403';
        foreach ($GLOBALS['pairing_hooks']['admin_init'] ?? [] as $callback) $callback();
        return 'render';
    } catch (Pairing_Redirect $redirect) { return $redirect->getMessage(); }
}

$settings = 'https://customer.example/wp-admin/options-general.php?page=harika-connector';
expect(admin_request('ccf-google-ads') === $settings, 'Old settings link must redirect before WordPress denies an unregistered page');
expect(admin_request('harika-connector') === 'render', 'Canonical settings must render without redirect loop');
$GLOBALS['pairing_admins'][7] = false;
expect(admin_request('ccf-google-ads') === '403', 'Old link must not redirect or grant access to a non-admin');
expect(admin_request('harika-connector') === '403', 'Canonical page retains manage_options');
$GLOBALS['pairing_admins'][7] = true;
$GLOBALS['pairing_options'] = []; $_REQUEST = [];
Harika_Pairing::activate();
expect(admin_request(null) === $settings, 'Individual first activation reaches setup before normal page rendering');
expect(admin_request(null) === 'render', 'Activation redirect is consumed only once');
set_transient('harika_pairing_redirect_7', 1, 60);
expect(admin_request(null, true) === 'render', 'Bulk activation does not redirect');
$GLOBALS['pairing_network'] = true;
set_transient('harika_pairing_redirect_7', 1, 60);
expect(admin_request(null) === 'render', 'Network admin does not redirect to site settings');
echo "WordPress admin navigation and access-boundary tests passed.\n";
