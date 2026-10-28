<?php
/**
 * Offline CLI bridge for the pinned Harika <-> WordPress cross-repository test.
 * Uses the real plugin authorize()/connection() methods after loading the
 * existing WordPress test fixture. No real WordPress installation or secrets.
 */
declare(strict_types=1);
require __DIR__ . '/wordpress-control.php';

$target = (string) (getenv('HARIKA_CROSS_REPO_EVENTS_URL') ?: '');
if (!preg_match('#^http://127\\.0\\.0\\.1:[0-9]{2,5}$#', $target)) {
    throw new RuntimeException('The cross-repo test accepts a loopback target only.');
}
$input = json_decode((string) stream_get_contents(STDIN), true);
if (!is_array($input) || ($input['method'] ?? '') !== 'GET') {
    throw new RuntimeException('The cross-repo test accepts signed GET only.');
}
$url = parse_url((string) ($input['url'] ?? ''));
if (!is_array($url) || ($url['scheme'] ?? '') !== 'https' ||
    ($url['host'] ?? '') !== 'customer.example' ||
    ($url['path'] ?? '') !== '/wp-json/ccf-sites/v1/connection') {
    throw new RuntimeException('Unexpected WordPress route/host in cross-repo fixture.');
}
parse_str((string) ($url['query'] ?? ''), $query);
if (!is_array($query)) throw new RuntimeException('Invalid signed query.');
$headers = [];
foreach (($input['headers'] ?? []) as $key => $value) {
    $headers[strtolower((string) $key)] = (string) $value;
}
$GLOBALS['harika_crossrepo_target'] = $target;
$GLOBALS['connection_probe_mode'] = (string) (getenv('HARIKA_CROSS_REPO_MODE') ?: 'ok');

$request = new Test_Request('GET', '/ccf-sites/v1/connection', '', $headers, $query);
$authorized = Harika_Control::authorize($request);
if ($authorized !== true) {
    $status = $authorized instanceof WP_Error ? (int) ($authorized->data['status'] ?? 403) : 403;
    $result = ['status' => $status, 'body' => ['error' => 'signature_rejected']];
} else {
    $response = Harika_Status_Overlay::connection();
    $result = [
        'status' => $response instanceof WP_REST_Response ? $response->status : 500,
        'body' => $response instanceof WP_REST_Response ? $response->data : ['error' => 'invalid_plugin_reply'],
    ];
}
echo 'HARIKA_CROSS_REPO_JSON:' . json_encode($result, JSON_THROW_ON_ERROR) . "\n";
