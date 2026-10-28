<?php

defined('ABSPATH') || exit;

final class Harika_Status_Overlay {
    public static function init(): void {
        add_action('rest_api_init', [self::class, 'register_route'], 20);
    }

    public static function register_route(): void {
        register_rest_route('ccf-sites/v1', '/status', [
            'methods' => 'GET',
            'permission_callback' => [Harika_Control::class, 'authorize'],
            'callback' => [self::class, 'status'],
        ], true);
        register_rest_route('ccf-sites/v1', '/connection', [
            'methods' => 'GET',
            'permission_callback' => [Harika_Control::class, 'authorize'],
            'callback' => [self::class, 'connection'],
        ]);
    }

    public static function status() {
        $response = Harika_Control::status();
        if (!$response instanceof WP_REST_Response) {
            return $response;
        }
        $envelope = $response->get_data();
        if (!is_array($envelope) || !isset($envelope['data']) || !is_array($envelope['data'])) {
            return $response;
        }
        $data = $envelope['data'];
        $data['plugin'] = [
            'name' => 'Harika Connector',
            'version' => defined('HARIKA_CONNECTOR_VERSION') ? HARIKA_CONNECTOR_VERSION : (defined('CCF_SITES_ADS_PLUGIN_VERSION') ? CCF_SITES_ADS_PLUGIN_VERSION : '1.2.0'),
        ];
        $capabilities = isset($data['capabilities']) && is_array($data['capabilities']) ? $data['capabilities'] : [];
        $data['capabilities'] = array_values(array_unique(array_merge($capabilities, [
            'wordpress.content.create-draft',
            'wordpress.content.trash-unpublished',
            'wordpress.taxonomy.read',
            'wordpress.taxonomy.write',
            'wordpress.media.read',
            'wordpress.media.import-image',
            'wordpress.featured-image.write-unpublished',
            'acf.read',
            'acf.write-unpublished',
            'rank-math.draft-write',
            'rank-math.abilities.read',
            'rank-math.abilities.execute',
        ])));
        $envelope['data'] = $data;
        $response->set_data($envelope);
        return $response;
    }

    /**
     * Called only after the normal signed, one-time-nonce WordPress authorization.
     * The reverse probe is a status-only POST; no event, conversion or WordPress write is created.
     */
    public static function connection() {
        $client_id = Harika_Connector::client_id();
        $site_id = Harika_Connector::site_id();
        $environment = Harika_Connector::environment();
        $website_host = strtolower((string) wp_parse_url(home_url('/'), PHP_URL_HOST));
        $endpoint = rtrim(Harika_Connector::control_endpoint(), '/');
        $report = [
            'status' => 'not_verified',
            'token_accepted' => false,
            'control_endpoint' => $endpoint,
            'control' => null,
            'reason' => 'not_configured',
        ];
        $envelope = static function (array $result) use ($client_id, $site_id, $environment, $website_host): WP_REST_Response {
            return new WP_REST_Response([
                'schema_version' => '1.0',
                'site' => [
                    'client_id' => $client_id,
                    'site_id' => $site_id,
                    'environment' => $environment,
                    'website_host' => $website_host,
                ],
                'data' => $result,
            ], 200);
        };

        $url = wp_parse_url($endpoint);
        if (!is_array($url) || ($url['scheme'] ?? '') !== 'https' ||
            empty($url['host']) || !empty($url['user']) || !empty($url['pass']) ||
            !empty($url['query']) || !empty($url['fragment']) ||
            !in_array($url['path'] ?? '', ['', '/'], true) ||
            $client_id === '' || $site_id === '' ||
            !preg_match('/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/', $website_host) ||
            strlen(Harika_Connector::site_token()) < 32) {
            return $envelope($report);
        }

        try {
            $challenge = bin2hex(random_bytes(16));
        } catch (Throwable $error) {
            return $envelope($report);
        }
        $payload = [
            'client_id' => $client_id,
            'site_id' => $site_id,
            'environment' => $environment,
            'website_host' => $website_host,
            'challenge' => $challenge,
        ];
        $result = wp_safe_remote_post($endpoint . '/v1/connection-check', [
            'timeout' => 5,
            'redirection' => 0,
            'limit_response_size' => 2048,
            'headers' => [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . Harika_Connector::site_token(),
                'X-CCF-Client-ID' => $client_id,
                'X-CCF-Site-ID' => $site_id,
                'X-CCF-Timestamp' => (string) time(),
            ],
            'body' => wp_json_encode($payload),
        ]);
        if (is_wp_error($result)) {
            $report['reason'] = 'control_unreachable';
            return $envelope($report);
        }
        if ((int) wp_remote_retrieve_response_code($result) !== 200) {
            $report['reason'] = 'control_rejected';
            return $envelope($report);
        }
        $control = json_decode((string) wp_remote_retrieve_body($result), true);
        if (!is_array($control) || ($control['status'] ?? null) !== 'verified' ||
            ($control['token_accepted'] ?? null) !== true ||
            ($control['client_id'] ?? null) !== $client_id ||
            ($control['site_id'] ?? null) !== $site_id ||
            ($control['environment'] ?? null) !== $environment ||
            ($control['website_host'] ?? null) !== $website_host ||
            ($control['challenge'] ?? null) !== $challenge) {
            $report['reason'] = 'control_identity_mismatch';
            return $envelope($report);
        }
        $report['status'] = 'verified';
        $report['token_accepted'] = true;
        $report['reason'] = null;
        // Whitelist validated identity fields only; never relay raw upstream data or secrets.
        $report['control'] = [
            'status' => 'verified',
            'token_accepted' => true,
            'client_id' => $client_id,
            'site_id' => $site_id,
            'environment' => $environment,
            'website_host' => $website_host,
        ];
        return $envelope($report);
    }
}
