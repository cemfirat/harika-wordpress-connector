<?php
/** Isolated WordPress API surface; all pairing/control code is the real plugin. */
declare(strict_types=1);
define('ABSPATH', __DIR__ . '/');
$GLOBALS['pairing_options'] = [];
$GLOBALS['pairing_transients'] = [];
$GLOBALS['pairing_admins'] = [7 => true, 8 => true];
$GLOBALS['pairing_origin'] = 'https://customer.example';
$GLOBALS['pairing_user'] = 7;
$GLOBALS['pairing_hooks'] = [];
class WP_Error {
    public $code; public $message; public $data;
    public function __construct($code, $message, $data = []) { $this->code=$code; $this->message=$message; $this->data=$data; }
    public function get_error_code() { return $this->code; }
    public function get_error_message() { return $this->message; }
}
class WP_REST_Response {
    public $data; public $status; public $headers = [];
    public function __construct($data, $status = 200) { $this->data=$data; $this->status=$status; }
    public function get_data() { return $this->data; }
    public function header($name,$value) { $this->headers[$name]=$value; }
}
class Pairing_Request {
    private $headers; private $query;
    public function __construct(array $headers = [], array $query = []) { $this->headers=array_change_key_case($headers); $this->query=$query; }
    public function get_param($key) { return $this->query[$key] ?? null; }
    public function get_method() { return 'GET'; }
    public function get_route() { return '/ccf-sites/v1/connection'; }
    public function get_header($key) { return $this->headers[strtolower($key)] ?? ''; }
    public function get_query_params() { return $this->query; }
    public function get_body() { return ''; }
}
$GLOBALS['wpdb'] = new class {
    public $options = 'wp_options';
    public function prepare($sql, ...$args) { return $args; }
    public function query($args) {
        [$key,$value]=$args;
        if (($GLOBALS['pairing_options'][$key] ?? null) !== $value) return 0;
        unset($GLOBALS['pairing_options'][$key]); return 1;
    }
};
function add_action($hook,$callback,...$args): void { $GLOBALS['pairing_hooks'][$hook][]=$callback; }
function add_filter(...$args): void {}
function remove_filter(...$args): void {}
function register_activation_hook($file,$callback): void { $GLOBALS['pairing_hooks']['activation'][]=$callback; }
function register_rest_route($namespace,$route,$args,...$rest): void { $GLOBALS['pairing_routes'][$namespace.$route]=$args; }
function is_wp_error($v): bool { return $v instanceof WP_Error; }
function current_user_can($cap): bool { return user_can(get_current_user_id(),$cap); }
function user_can($user,$cap): bool { return $cap==='manage_options' && !empty($GLOBALS['pairing_admins'][$user]); }
function get_current_user_id(): int { return $GLOBALS['pairing_user']; }
function home_url($path=''): string { return $GLOBALS['pairing_origin'].$path; }
function admin_url($path=''): string { return $GLOBALS['pairing_origin'].'/wp-admin/'.$path; }
function wp_parse_url($value,$component=-1) { return parse_url($value,$component); }
function wp_salt($scheme): string { return 'isolated-pairing-salt-'.$scheme; }
function wp_json_encode($value): string { return json_encode($value,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR); }
function sanitize_key($value): string { return strtolower(preg_replace('/[^a-zA-Z0-9_\-]/','',(string)$value)); }
function sanitize_text_field($value): string { return trim(strip_tags((string)$value)); }
function esc_url_raw($value): string { return (string)$value; }
function get_option($key,$default=false) { return $GLOBALS['pairing_options'][$key] ?? $default; }
function update_option($key,$value,...$args): bool { $GLOBALS['pairing_options'][$key]=$value; return true; }
function add_option($key,$value,...$args): bool { if (array_key_exists($key,$GLOBALS['pairing_options'])) return false; $GLOBALS['pairing_options'][$key]=$value; return true; }
function delete_option($key): bool { unset($GLOBALS['pairing_options'][$key]); return true; }
function get_transient($key) { return $GLOBALS['pairing_transients'][$key] ?? false; }
function set_transient($key,$value,$ttl): bool { $GLOBALS['pairing_transients'][$key]=$value; return true; }
function delete_transient($key): bool { unset($GLOBALS['pairing_transients'][$key]); return true; }
function wp_cache_delete(...$args): void {}
function wp_safe_remote_post($url,$args) { return ($GLOBALS['pairing_transport'])($url,$args); }
function wp_remote_retrieve_response_code($response): int { return $response['status']; }
function wp_remote_retrieve_body($response): string { return $response['body']; }
require __DIR__.'/../../wordpress/harika-wordpress-connector.php';
