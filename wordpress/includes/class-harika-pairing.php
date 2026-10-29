<?php
/** Browser-authorized pairing; credentials stay in encrypted server-side options. */
defined('ABSPATH') || exit;

final class Harika_Pairing {
    private const APP = 'https://app.getharika.com';
    private const OPTION = 'harika_pairing_private_v1';
    private const MANAGED = 'harika_pairing_managed_v1';
    private const LOCK = 'harika_pairing_lock_v1';
    private const CHECKS = ['response_schema', 'token_accepted', 'client_id', 'site_id', 'environment', 'website_host', 'control_endpoint', 'reverse_control'];

    public static function init(): void {
        add_action('rest_api_init', [self::class, 'routes']);
        add_action('admin_init', [self::class, 'admin_redirect']);
        add_action('admin_post_harika_pairing_start', [self::class, 'start_action']);
        add_action('admin_post_harika_pairing_callback', [self::class, 'callback_action']);
        add_action('admin_post_harika_pairing_check', [self::class, 'check_action']);
        add_action('admin_post_harika_pairing_revoke', [self::class, 'revoke_action']);
        add_action('wp_ajax_harika_pairing_status', [self::class, 'status_action']);
        if (function_exists('register_activation_hook')) register_activation_hook(HARIKA_CONNECTOR_FILE, [self::class, 'activate']);
    }
    private static function error(string $code): WP_Error {
        $messages = [
            'harika_pairing_forbidden' => 'Du benötigst WordPress-Administratorrechte.',
            'harika_pairing_locked' => 'Die Verbindung wird bereits bearbeitet. Bitte kurz warten.',
            'harika_pairing_configuration' => 'Die Einrichtung benötigt eine HTTPS-Website und eine passende WordPress-Admin-Adresse. Feste Verbindungswerte in wp-config.php müssen zuerst bewusst entfernt werden.',
            'harika_pairing_start_invalid' => 'Dieser Verbindungsversuch ist ungültig oder abgelaufen. Starte ihn in WordPress erneut.',
            'harika_pairing_unavailable' => 'Harika ist derzeit nicht erreichbar. Der bisherige Verbindungsstand bleibt geschützt. Bitte Status erneut prüfen.',
            'harika_pairing_checking' => 'Eine Verbindung wird bereits geprüft. Prüfe ihren Status oder brich diesen Versuch ab.',
            'harika_pairing_storage' => 'Die Verbindung konnte nicht sicher gespeichert werden. Prüfe die WordPress-Serverkonfiguration.',
            'pairing_authority_changed' => 'Berechtigung oder Website-Zuordnung wurde geändert. Bitte Verbindung erneut einrichten.',
            'pairing_expired' => 'Der Verbindungsversuch ist abgelaufen. Bitte erneut starten.',
            'pairing_token_invalid' => 'Die Website-Zugangsdaten wurden abgelehnt oder widerrufen. Bitte erneut verbinden.',
            'pairing_verification_failed' => 'Die beiden Verbindungsrichtungen stimmen nicht überein. Bitte Verbindung erneut prüfen.',
            'pairing_wordpress_unreachable' => 'Harika kann diese WordPress-Website derzeit nicht erreichen.',
        ];
        return new WP_Error($code, $messages[$code] ?? 'Die Verbindung konnte nicht bestätigt werden. Bitte erneut prüfen.', ['status' => 409]);
    }
    private static function read(): array {
        $raw = get_option(self::OPTION, '');
        if ($raw === '') return [];
        $state = json_decode(Harika_Connector::open_pairing((string) $raw), true);
        // Corrupt/lost encryption must never restore the shared legacy credential.
        if (!is_array($state)) throw new RuntimeException('pairing_private_storage_unavailable');
        return $state;
    }
    private static function save(array $state): void {
        $sealed = Harika_Connector::protect_pairing((string) wp_json_encode($state));
        if ($sealed === '') throw new RuntimeException('pairing_private_storage_unavailable');
        update_option(self::OPTION, $sealed, false);
        if (get_option(self::OPTION, '') !== $sealed) throw new RuntimeException('pairing_private_storage_unavailable');
    }
    private static function mark_managed(): void {
        update_option(self::MANAGED, true, false);
        if (!get_option(self::MANAGED, false)) throw new RuntimeException('pairing_private_storage_unavailable');
    }
    private static function locked(callable $action) {
        if (!current_user_can('manage_options')) return self::error('harika_pairing_forbidden');
        // add_option is atomic (unique option_name). A timed-out worker may only
        // release its own exact lease, never a replacement worker's lock.
        $lease = time() . ':' . bin2hex(random_bytes(16));
        if (!add_option(self::LOCK, $lease, '', false)) {
            $old = (string) get_option(self::LOCK, '');
            if ((int) $old + 60 >= time()) return self::error('harika_pairing_locked');
            self::release($old);
            if (!add_option(self::LOCK, $lease, '', false)) return self::error('harika_pairing_locked');
        }
        try { return $action(); }
        catch (Throwable $error) { return self::error('harika_pairing_storage'); }
        finally { self::release($lease); }
    }
    private static function release(string $lease): void {
        global $wpdb;
        $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s", self::LOCK, $lease));
        wp_cache_delete(self::LOCK, 'options');
    }
    private static function origin(): string {
        $home = (string) home_url('/');
        $parts = wp_parse_url($home);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) ||
            isset($parts['port']) || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment']) ||
            !in_array($parts['path'] ?? '', ['', '/'], true)) return '';
        $origin = 'https://' . strtolower($parts['host']);
        return admin_url('admin-post.php') === $origin . '/wp-admin/admin-post.php' ? $origin : '';
    }
    private static function local_environment(): string {
        $settings = get_option('ccf_gads_settings', []);
        return defined('CCF_GADS_ENVIRONMENT') ? (string) CCF_GADS_ENVIRONMENT : (string) ($settings['environment'] ?? 'production');
    }
    /** null = untouched legacy installation; empty array = explicitly fail closed. */
    public static function configuration(): ?array {
        try {
            $state = self::read();
            $value = $state['candidate'] ?? $state['active'] ?? null;
            if (is_array($value)) {
                if (($value['origin'] ?? '') !== self::origin() || ($value['environment'] ?? '') !== self::local_environment()) return [];
                return $value;
            }
            return get_option(self::MANAGED, false) ? [] : null;
        } catch (Throwable $error) { return []; }
    }
    private static function remote(string $action, array $body, string $token = '') {
        $headers = ['Content-Type' => 'application/json', 'Accept' => 'application/json'];
        if ($token !== '') $headers['Authorization'] = 'Bearer ' . $token;
        $response = wp_safe_remote_post(self::APP . '/wordpress/' . $action, [
            'timeout' => 12, 'redirection' => 0, 'limit_response_size' => 16384,
            'headers' => $headers, 'body' => wp_json_encode((object) $body),
        ]);
        if (is_wp_error($response)) return self::error('harika_pairing_unavailable');
        $packet = json_decode((string) wp_remote_retrieve_body($response), true);
        $status = (int) wp_remote_retrieve_response_code($response);
        if ($status < 200 || $status >= 300 || !is_array($packet['data'] ?? null)) {
            $code = $packet['error']['code'] ?? '';
            return self::error(in_array($code, ['pairing_authority_changed', 'pairing_expired', 'pairing_token_invalid'], true) ? $code : 'harika_pairing_unavailable');
        }
        return $packet['data'];
    }
    /** A revoked scoped key must not keep authorizing signed WordPress writes. */
    public static function authorize_control($request) {
        $binding = self::configuration();
        if ($binding === null) return true; // Existing legacy installations retain their protocol.
        if (empty($binding['token'])) return new WP_Error('ccf_control_unauthorized', 'Website credentials unavailable.', ['status' => 401]);
        $status = self::remote('status', [], $binding['token']);
        if (is_wp_error($status)) return new WP_Error('ccf_control_unauthorized', 'Website authority could not be verified.', ['status' => 503]);
        if (($status['origin'] ?? '') !== self::origin() || ($status['environment'] ?? '') !== self::local_environment() ||
            !in_array($status['state'] ?? '', ['verified', 'not_verified', 'checking'], true)) {
            return new WP_Error('ccf_control_unauthorized', 'Website credentials rejected.', ['status' => 401]);
        }
        $active = is_string($status['activated_at'] ?? null) && $status['activated_at'] !== '';
        if (!$active && ($request->get_method() !== 'GET' || $request->get_route() !== '/ccf-sites/v1/connection')) {
            return new WP_Error('ccf_control_unauthorized', 'Website connection is not active.', ['status' => 401]);
        }
        return true;
    }
    public static function begin() {
        return self::locked(static function () {
            $state = self::read();
            if (isset($state['candidate'])) return self::error('harika_pairing_checking');
            foreach (['CCF_GADS_SITE_TOKEN', 'CCF_GADS_CLIENT_ID', 'CCF_GADS_SITE_ID', 'CCF_GADS_CONTROL_ENDPOINT', 'CCF_GADS_ENVIRONMENT'] as $constant) {
                if (defined($constant)) return self::error('harika_pairing_configuration');
            }
            $origin = self::origin(); $environment = self::local_environment();
            if ($origin === '' || !in_array($environment, ['production', 'staging', 'development'], true)) return self::error('harika_pairing_configuration');
            $nonce = self::random(); $verifier = self::random();
            $state['intent'] = ['state' => $nonce, 'verifier' => $verifier, 'user' => get_current_user_id(),
                'origin' => $origin, 'environment' => $environment, 'expires' => time() + 300];
            unset($state['last_error']); self::save($state);
            return self::APP . '/wordpress/connect?' . http_build_query(['origin' => $origin, 'environment' => $environment,
                'state' => $nonce, 'code_challenge' => self::challenge_value($verifier)], '', '&', PHP_QUERY_RFC3986);
        });
    }
    private static function random(): string { return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='); }
    private static function challenge_value(string $value): string { return rtrim(strtr(base64_encode(hash('sha256', $value, true)), '+/', '-_'), '='); }
    private static function intent_valid(array $intent): bool {
        return ($intent['expires'] ?? 0) > time() && ($intent['origin'] ?? '') === self::origin() &&
            ($intent['environment'] ?? '') === self::local_environment() && user_can((int) ($intent['user'] ?? 0), 'manage_options');
    }
    public static function routes(): void {
        register_rest_route('ccf-sites/v1', '/pairing/challenge', ['methods' => 'GET', 'permission_callback' => '__return_true', 'callback' => [self::class, 'challenge']]);
    }
    public static function challenge($request) {
        try {
            $state = self::read(); $intent = $state['intent'] ?? [];
            $nonce = $request->get_param('state');
            if (!is_string($nonce) || !preg_match('/^[A-Za-z0-9_-]{43}$/', $nonce) || !self::intent_valid($intent) ||
                !hash_equals((string) ($intent['state'] ?? ''), $nonce)) return new WP_Error('harika_pairing_start_invalid', 'Verbindungsnachweis nicht verfügbar.', ['status' => 404]);
            $response = new WP_REST_Response(['origin' => $intent['origin'], 'environment' => $intent['environment'],
                'code_challenge' => self::challenge_value($intent['verifier']),
                'callback_uri' => $intent['origin'] . '/wp-admin/admin-post.php?action=harika_pairing_callback']);
            $response->header('Cache-Control', 'no-store'); return $response;
        } catch (Throwable $error) { return self::error('harika_pairing_storage'); }
    }
    public static function finish(string $code, string $nonce) {
        return self::locked(static function () use ($code, $nonce) {
            $state = self::read(); $intent = $state['intent'] ?? [];
            if (!self::intent_valid($intent) || ($intent['user'] ?? 0) !== get_current_user_id() ||
                !preg_match('/^[A-Za-z0-9_-]{43}$/', $code) || !hash_equals((string) ($intent['state'] ?? ''), $nonce)) return self::error('harika_pairing_start_invalid');
            unset($state['intent']); self::save($state);
            $result = self::remote('exchange', ['code' => $code, 'verifier' => $intent['verifier']]);
            if (is_wp_error($result)) return $result;
            $endpoint = wp_parse_url((string) ($result['control_endpoint'] ?? ''));
            if (!preg_match('/^hwp_[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$/', (string) ($result['token'] ?? '')) ||
                !preg_match('/^[a-f0-9]{32}$/', (string) ($result['id'] ?? '')) ||
                strpos($result['token'], 'hwp_' . $result['id'] . '.') !== 0 ||
                !preg_match('/^[A-Za-z0-9_-]{1,128}$/', (string) ($result['client_id'] ?? '')) ||
                !preg_match('/^[A-Za-z0-9_-]{1,128}$/', (string) ($result['site_id'] ?? '')) ||
                ($result['origin'] ?? '') !== $intent['origin'] || ($result['environment'] ?? '') !== $intent['environment'] ||
                !is_string($result['organization'] ?? null) || !is_string($result['website'] ?? null) ||
                !is_array($endpoint) || ($endpoint['scheme'] ?? '') !== 'https' || empty($endpoint['host']) ||
                isset($endpoint['user']) || isset($endpoint['pass']) || isset($endpoint['port']) || isset($endpoint['query']) || isset($endpoint['fragment']) ||
                !in_array($endpoint['path'] ?? '', ['', '/'], true)) return self::error('harika_pairing_unavailable');
            $state['candidate'] = array_intersect_key($result, array_flip(['id', 'token', 'client_id', 'site_id', 'origin', 'environment', 'control_endpoint', 'organization', 'website']));
            // Save before requesting the asynchronous proof. Unknown HTTP outcomes
            // retain this candidate for idempotent complete/status resumption.
            self::save($state);
            self::remote('complete', [], $result['token']);
            return ['state' => 'checking'];
        });
    }
    private static function accept_status(array $state, array $result): array {
        $candidate = isset($state['candidate']); $binding = $state['candidate'] ?? $state['active'] ?? [];
        $terminal = in_array($result['state'] ?? '', ['failed', 'revoked'], true);
        if ($terminal) {
            // Only an explicitly never-activated candidate can restore an old
            // configuration. Lost activation responses cannot enable legacy auth.
            if (!array_key_exists('activated_at', $result)) return ['state' => 'not_verified', 'error' => 'harika_pairing_unavailable'];
            if (!$candidate || $result['activated_at'] !== null) {
                self::mark_managed(); unset($state['active']);
            }
            unset($state['candidate']); $state['last_error'] = $result['error'] ?? 'pairing_token_invalid'; self::save($state);
            return ['state' => $result['state'], 'error' => $state['last_error']];
        }
        $verified = ($result['state'] ?? '') === 'verified' && ($result['verification']['status'] ?? '') === 'verified' && ($result['verification']['failed'] ?? null) === [];
        foreach (self::CHECKS as $field) $verified = $verified && ($result['verification']['checks'][$field] ?? false) === true;
        $verified = $verified && ($result['origin'] ?? '') === self::origin() && ($result['environment'] ?? '') === self::local_environment();
        if ($verified && $candidate) {
            self::mark_managed();
            $state['active'] = $state['candidate']; unset($state['candidate'], $state['last_error']); self::save($state);
        }
        return ['state' => $verified ? 'verified' : (($result['state'] ?? '') === 'checking' ? 'checking' : 'not_verified'),
            'organization' => (string) ($result['organization'] ?? $binding['organization'] ?? ''),
            'website' => (string) ($result['website'] ?? $binding['website'] ?? ''),
            'origin' => (string) ($binding['origin'] ?? ''), 'error' => $result['error'] ?? null,
            'verification' => $result['verification'] ?? null];
    }
    public static function status() {
        return self::locked(static function () {
            $state = self::read(); $binding = $state['candidate'] ?? $state['active'] ?? null;
            if (!$binding) return ['state' => get_option(self::MANAGED, false) ? 'revoked' : (Harika_Connector::site_token() !== '' ? 'legacy' : 'not_connected'), 'error' => $state['last_error'] ?? null];
            $result = self::remote('status', [], $binding['token']);
            if (!is_wp_error($result) && isset($state['candidate']) && ($result['state'] ?? '') === 'pending') $result = self::remote('complete', [], $binding['token']);
            if (is_wp_error($result)) return $result;
            return self::accept_status($state, $result);
        });
    }
    public static function check() {
        return self::locked(static function () {
            $state = self::read(); $binding = $state['candidate'] ?? $state['active'] ?? null;
            if (!$binding) return self::error('pairing_token_invalid');
            $result = self::remote(isset($state['candidate']) ? 'complete' : 'check', [], $binding['token']);
            return is_wp_error($result) ? $result : self::accept_status($state, $result);
        });
    }
    public static function cancel() {
        return self::locked(static function () {
            $state = self::read(); $binding = $state['candidate'] ?? $state['active'] ?? null;
            if (!$binding) { unset($state['intent']); self::save($state); return ['state' => 'cancelled']; }
            $result = self::remote('revoke', [], $binding['token']);
            return is_wp_error($result) ? $result : self::accept_status($state, $result);
        });
    }
    public static function activate(bool $network_wide = false): void {
        if (!add_option('harika_pairing_first_activation', 1, '', false)) return;
        if ($network_wide || !empty($_REQUEST['activate-multi']) || !current_user_can('manage_options') || get_option('ccf_gads_settings', [])) return;
        set_transient('harika_pairing_redirect_' . get_current_user_id(), 1, 60);
    }
    public static function admin_redirect(): void {
        if (!current_user_can('manage_options') || wp_doing_ajax() || wp_doing_cron()) return;
        $alias = ($_GET['page'] ?? '') === 'ccf-google-ads';
        $key = 'harika_pairing_redirect_' . get_current_user_id();
        if (!$alias && !get_transient($key)) return;
        delete_transient($key);
        if (!empty($_REQUEST['activate-multi']) || is_network_admin()) return;
        wp_safe_redirect(admin_url('options-general.php?page=harika-connector')); exit;
    }
    private static function admin_guard(): void {
        if (!current_user_can('manage_options')) wp_die('Keine Berechtigung.', '', ['response' => 403]);
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') wp_die('POST erforderlich.', '', ['response' => 405]);
        check_admin_referer('harika_pairing');
    }
    private static function return_to_settings($result): void {
        if (is_wp_error($result)) set_transient('harika_pairing_notice_' . get_current_user_id(), $result->get_error_code(), 120);
        nocache_headers(); header('Referrer-Policy: no-referrer');
        wp_safe_redirect(admin_url('options-general.php?page=harika-connector')); exit;
    }
    public static function start_action(): void {
        self::admin_guard(); $result = self::begin();
        if (is_wp_error($result)) self::return_to_settings($result);
        nocache_headers(); header('Referrer-Policy: no-referrer');
        wp_redirect($result); exit; // Constructed exclusively with the fixed Harika origin.
    }
    public static function callback_action(): void {
        if (!current_user_can('manage_options')) wp_die('Keine Berechtigung.', '', ['response' => 403]);
        $code = $_GET['code'] ?? ''; $state = $_GET['state'] ?? '';
        self::return_to_settings(is_string($code) && is_string($state) ? self::finish($code, $state) : self::error('harika_pairing_start_invalid'));
    }
    public static function check_action(): void { self::admin_guard(); self::return_to_settings(self::check()); }
    public static function revoke_action(): void { self::admin_guard(); self::return_to_settings(self::cancel()); }
    public static function status_action(): void {
        self::admin_guard(); $result = self::status();
        wp_send_json(is_wp_error($result) ? ['state' => 'not_verified', 'message' => $result->get_error_message()] : self::public_status($result));
    }
    private static function public_status(array $value): array {
        $labels = ['verified' => 'Beidseitig verifiziert', 'checking' => 'Verbindung wird geprüft', 'revoked' => 'Verbindung widerrufen', 'failed' => 'Verbindung fehlgeschlagen', 'not_connected' => 'Noch nicht verbunden', 'legacy' => 'Manuell konfiguriert – beidseitiger Status hier noch nicht überprüfbar'];
        $result = array_intersect_key($value, array_flip(['state', 'organization', 'website', 'origin']));
        $result['message'] = isset($value['error']) ? self::error((string) $value['error'])->get_error_message() : ($labels[$value['state']] ?? 'Nicht verifiziert');
        return $result;
    }
    public static function render(): void {
        if (!current_user_can('manage_options')) return;
        $status = self::status(); $view = is_wp_error($status) ? ['state' => 'not_verified', 'message' => $status->get_error_message()] : self::public_status($status);
        $notice = get_transient('harika_pairing_notice_' . get_current_user_id());
        if ($notice) { $view['message'] = self::error((string) $notice)->get_error_message(); delete_transient('harika_pairing_notice_' . get_current_user_id()); }
        wp_enqueue_script('harika-pairing', plugins_url('assets/harika-pairing.js', HARIKA_CONNECTOR_FILE), [], HARIKA_CONNECTOR_VERSION, true);
        ?><div class="wrap"><h1>Harika Connector</h1>
        <p>Verbinde diese WordPress-Website mit ihrer bereits eingerichteten Website in Harika. Deine vorhandene Harika-Anmeldung wird verwendet.</p>
        <div id="harika-pairing-status" data-state="<?php echo esc_attr($view['state']); ?>" data-url="<?php echo esc_url(admin_url('admin-ajax.php')); ?>" data-nonce="<?php echo esc_attr(wp_create_nonce('harika_pairing')); ?>">
            <p role="status" data-message><?php echo esc_html($view['message']); ?></p>
            <p data-identity><?php echo esc_html(trim(($view['organization'] ?? '') . ' · ' . ($view['website'] ?? ''), ' ·')); ?></p>
        </div>
        <?php foreach (['start' => 'Mit Harika verbinden', 'check' => 'Verbindung erneut prüfen', 'revoke' => $view['state'] === 'checking' ? 'Verbindungsversuch abbrechen' : 'Verbindung widerrufen'] as $action => $label): ?>
            <?php if ($action !== 'start' && in_array($view['state'], ['not_connected', 'legacy', 'revoked'], true)) continue; ?>
            <form action="<?php echo esc_url(admin_url('admin-post.php')); ?>" method="post" style="display:inline-block;margin-right:8px">
                <input type="hidden" name="action" value="harika_pairing_<?php echo esc_attr($action); ?>">
                <?php wp_nonce_field('harika_pairing'); submit_button($label, $action === 'start' ? 'primary' : 'secondary', 'submit', false); ?>
            </form>
        <?php endforeach; ?>
        <p>Ein grüner Status setzt voraus, dass Harika diese Website und das Plugin den Control-Dienst erreicht. Die Prüfung erzeugt keine Tracking-Ereignisse.</p>
        <?php if (self::configuration() === null): ?><details><summary>Bestehende manuelle Konfiguration</summary><?php Harika_Connector::render_legacy_settings_page(); ?></details><?php endif; ?>
        </div><?php
    }
}
