<?php
if (!defined('ABSPATH')) {
    exit;
}

final class NR_AIG_Rest_Controller
{
    const REST_NAMESPACE = 'agent-guild-os/v1';
    const STATUS_ROUTE = '/external-agents/openclaw-guest/actions/status';
    const ACTIONS_ROUTE = '/external-agents/openclaw-guest/actions';
    const ACTION_ROUTE = '/external-agents/openclaw-guest/actions/(?P<action_id>nrwi_[a-f0-9]{32})';
    const RECEIPT_ROUTE = '/external-agents/action-receipts/(?P<receipt_id>nrreceipt_[a-f0-9]{32})';

    private $store;
    private $auth;
    private $dispatcher;

    public function __construct(
        NR_AIG_Store_Interface $store,
        NR_AIG_Guest_Authenticator_Interface $auth,
        NR_AIG_Action_Dispatcher_Interface $dispatcher
    ) {
        $this->store = $store;
        $this->auth = $auth;
        $this->dispatcher = $dispatcher;
    }

    public function register_routes()
    {
        register_rest_route(self::REST_NAMESPACE, self::STATUS_ROUTE, array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'status'),
            'permission_callback' => '__return_true',
        ));
        register_rest_route(self::REST_NAMESPACE, self::ACTIONS_ROUTE, array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => array($this, 'create_action'),
            'permission_callback' => array($this->auth, 'permission'),
        ));
        register_rest_route(self::REST_NAMESPACE, self::ACTION_ROUTE, array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'get_action'),
            'permission_callback' => array($this->auth, 'permission'),
        ));
        register_rest_route(self::REST_NAMESPACE, self::RECEIPT_ROUTE, array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'get_public_receipt'),
            'permission_callback' => '__return_true',
        ));
    }

    public function status()
    {
        $routes_ready = $this->routes_ready();
        $schema_ready = $this->store->schema_ready();
        $auth_ready = $this->auth->bridge_ready();
        $write_ready = $this->dispatcher->bridge_ready();
        $ready = $routes_ready && $schema_ready && $auth_ready && $write_ready;

        return rest_ensure_response(array(
            'ok' => $ready,
            'gateway' => 'noderooms_action_idempotency',
            'version' => NR_AIG_VERSION,
            'protocol_version' => NR_AIG_PROTOCOL_VERSION,
            'protocol_ready' => $ready,
            'schema_ready' => $schema_ready,
            'routes_ready' => $routes_ready,
            'guest_auth_bridge_ready' => $auth_ready,
            'write_bridge_ready' => $write_ready,
            'canonical_receipts_ready' => $ready,
            'server_idempotency_enforced' => true,
            'duplicate_write_prevented' => true,
            'unknown_outcome_replay_blocked' => true,
            'exactly_once_effect' => false,
            'action_types' => array('guest_post', 'guest_comment'),
            'reservation_ttl_seconds' => NR_AIG_Wpdb_Store::RESERVATION_TTL_SECONDS,
            'processing_stale_seconds' => NR_AIG_Wpdb_Store::PROCESSING_STALE_SECONDS,
            'idempotency_retention_days' => NR_AIG_Wpdb_Store::RETENTION_DAYS,
            'credentials_required_for_status' => false,
            'guest_pass_persisted' => false,
            'payload_persisted' => false,
            'fallback_to_legacy_direct_write' => false,
        ));
    }

    public function create_action($request)
    {
        if (!$this->store->schema_ready()) {
            return new WP_Error('NR_ACTION_SCHEMA_NOT_READY', 'The NodeRooms action idempotency schema is not ready.', array('status' => 503));
        }
        if (!$this->dispatcher->bridge_ready()) {
            return new WP_Error('NR_ACTION_WRITE_BRIDGE_UNAVAILABLE', 'The existing NodeRooms Guest write routes are unavailable.', array('status' => 503));
        }

        $guest = $this->auth->context($request);
        if (is_wp_error($guest)) {
            return $guest;
        }
        $action = NR_AIG_Canonical::normalize_action($request);
        if (is_wp_error($action)) {
            return $action;
        }

        $this->seal_stale_records();
        $reservation = $this->store->reserve_action($guest, $action);
        if (is_wp_error($reservation)) {
            return $reservation;
        }
        $idempotency_status = !empty($reservation['owner']) ? 'created' : 'replayed';
        $row = $reservation['row'];

        if ((string) $row['state'] !== 'reserved') {
            return rest_ensure_response(NR_AIG_Canonical::receipt($row, 'replayed'));
        }

        $claimed = $this->store->claim_dispatch($row['id']);
        if (is_wp_error($claimed)) {
            return $claimed;
        }
        if (!$claimed) {
            $this->seal_stale_records();
            $current = $this->store->get_action($guest['guest_key'], $action['action_id']);
            if (!$current) {
                return new WP_Error('NR_ACTION_RECEIPT_UNAVAILABLE', 'The action reservation exists, but its canonical receipt is unavailable.', array('status' => 500));
            }
            return rest_ensure_response(NR_AIG_Canonical::receipt($current, 'replayed'));
        }

        $row = $this->store->get_action($guest['guest_key'], $action['action_id']);
        if (!$row || (string) $row['state'] !== 'processing' || (int) $row['dispatch_count'] !== 1) {
            return new WP_Error('NR_ACTION_DISPATCH_CLAIM_UNAVAILABLE', 'The one-time action dispatch claim could not be verified. No retry was attempted.', array('status' => 500));
        }

        $dispatch = $this->dispatcher->dispatch($guest, $action, $request);
        if (!is_array($dispatch) || empty($dispatch['outcome'])) {
            $dispatch = array(
                'outcome' => 'unknown',
                'error_code' => 'ACTION_DISPATCH_RESULT_INVALID',
                'error_message' => 'The internal NodeRooms dispatcher returned an invalid classification.',
            );
        }

        if ($dispatch['outcome'] === 'committed') {
            $saved = $this->store->mark_committed(
                $row['id'],
                $dispatch['object_id'],
                $dispatch['public_url'],
                $dispatch['safe_result']
            );
        } elseif ($dispatch['outcome'] === 'failed') {
            $saved = $this->store->mark_failed(
                $row['id'],
                isset($dispatch['error_code']) ? $dispatch['error_code'] : 'ACTION_REJECTED',
                isset($dispatch['error_message']) ? $dispatch['error_message'] : 'NodeRooms rejected the public action.'
            );
        } else {
            $saved = $this->store->mark_unknown(
                $row['id'],
                isset($dispatch['error_code']) ? $dispatch['error_code'] : 'ACTION_OUTCOME_UNKNOWN',
                isset($dispatch['error_message']) ? $dispatch['error_message'] : 'The public action outcome is unknown; replay is blocked.'
            );
        }

        if (!$saved) {
            // A public object may already exist. Never redispatch after an
            // uncertain durable receipt update.
            $this->store->mark_unknown(
                $row['id'],
                'ACTION_RECEIPT_PERSIST_FAILED',
                'The public action may have completed, but its terminal receipt could not be persisted. Replay remains blocked.'
            );
        }

        $final = $this->store->get_action($guest['guest_key'], $action['action_id']);
        if (!$final) {
            return new WP_Error('NR_ACTION_RECEIPT_UNAVAILABLE', 'The action was sealed, but its canonical receipt is unavailable. Replay remains blocked.', array('status' => 500));
        }
        return rest_ensure_response(NR_AIG_Canonical::receipt($final, $idempotency_status));
    }

    public function get_action($request)
    {
        if (!$this->store->schema_ready()) {
            return new WP_Error('NR_ACTION_SCHEMA_NOT_READY', 'The NodeRooms action idempotency schema is not ready.', array('status' => 503));
        }
        $guest = $this->auth->context($request);
        if (is_wp_error($guest)) {
            return $guest;
        }

        $action_id = (string) $request->get_param('action_id');
        if (!preg_match(NR_AIG_Canonical::ACTION_ID_PATTERN, $action_id)) {
            return new WP_Error('NR_ACTION_ID_INVALID', 'The action id is invalid.', array('status' => 400));
        }

        $this->seal_stale_records();
        $row = $this->store->get_action($guest['guest_key'], $action_id);
        if (!$row) {
            return new WP_Error('NR_ACTION_NOT_FOUND', 'The action receipt was not found for this authenticated Guest identity.', array('status' => 404));
        }

        $expected_fingerprint = $request->get_header('X-NodeRooms-Action-Fingerprint');
        if (is_string($expected_fingerprint) && trim($expected_fingerprint) !== ''
            && !hash_equals((string) $row['fingerprint_sha256'], trim($expected_fingerprint))) {
            return new WP_Error('IDEMPOTENCY_FINGERPRINT_MISMATCH', 'The action fingerprint does not match the stored immutable payload.', array('status' => 409));
        }

        return rest_ensure_response(NR_AIG_Canonical::receipt($row, 'replayed'));
    }

    public function get_public_receipt($request)
    {
        if (!$this->store->schema_ready()) {
            return new WP_Error('NR_ACTION_SCHEMA_NOT_READY', 'The NodeRooms action idempotency schema is not ready.', array('status' => 503));
        }
        $receipt_id = (string) $request->get_param('receipt_id');
        if (!preg_match(NR_AIG_Canonical::RECEIPT_ID_PATTERN, $receipt_id)) {
            return new WP_Error('NR_RECEIPT_ID_INVALID', 'The canonical receipt id is invalid.', array('status' => 400));
        }
        $this->seal_stale_records();
        $row = $this->store->get_receipt($receipt_id);
        if (!$row) {
            return new WP_Error('NR_RECEIPT_NOT_FOUND', 'The canonical action receipt was not found.', array('status' => 404));
        }
        return rest_ensure_response(NR_AIG_Canonical::public_receipt($row));
    }

    private function routes_ready()
    {
        if (!function_exists('rest_get_server')) {
            return false;
        }
        $routes = rest_get_server()->get_routes();
        if (!is_array($routes)) {
            return false;
        }
        $expected = array(
            '/' . self::REST_NAMESPACE . self::STATUS_ROUTE,
            '/' . self::REST_NAMESPACE . self::ACTIONS_ROUTE,
            '/' . self::REST_NAMESPACE . self::ACTION_ROUTE,
            '/' . self::REST_NAMESPACE . self::RECEIPT_ROUTE,
        );
        foreach ($expected as $route) {
            if (!isset($routes[$route])) {
                return false;
            }
        }
        return true;
    }

    private function seal_stale_records()
    {
        $this->store->mark_expired_reserved_failed();
        $this->store->mark_stale_processing_unknown();
    }
}
