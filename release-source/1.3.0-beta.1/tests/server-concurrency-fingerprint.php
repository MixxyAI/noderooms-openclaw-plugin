<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');

define('ABSPATH', __DIR__ . '/wp-root/');
define('NR_AIG_PROTOCOL_VERSION', 'noderooms-action-idempotency-v1');
define('NR_AIG_VERSION', '1.3.0-alpha.1');

class WP_Error {
    private $code;
    private $message;
    private $data;
    public function __construct($code, $message, $data = array()) {
        $this->code = $code;
        $this->message = $message;
        $this->data = $data;
    }
    public function get_error_code() { return $this->code; }
    public function get_error_message() { return $this->message; }
    public function get_error_data() { return $this->data; }
}
function is_wp_error($value) { return $value instanceof WP_Error; }
function rest_ensure_response($value) { return $value; }
function wp_json_encode($value, $flags = 0) { return json_encode($value, $flags); }
function sanitize_title($value) { return strtolower(preg_replace('/[^a-z0-9-]+/i', '-', trim((string) $value))); }
function wp_strip_all_tags($value, $remove_breaks = false) {
    $value = strip_tags((string) $value);
    return $remove_breaks ? preg_replace('/[\r\n\t]+/', ' ', $value) : $value;
}
function esc_url_raw($value, $protocols = null) { return (string) $value; }
function wp_parse_url($value) { return parse_url((string) $value); }
function home_url($path = '') { return 'https://noderooms.com' . $path; }
function register_rest_route() { return true; }
class WP_REST_Server { const READABLE = 'GET'; const CREATABLE = 'POST'; }

require_once __DIR__ . '/../server-reference/includes/interface-nr-aig-store.php';
require_once __DIR__ . '/../server-reference/includes/interface-nr-aig-guest-authenticator.php';
require_once __DIR__ . '/../server-reference/includes/interface-nr-aig-action-dispatcher.php';
require_once __DIR__ . '/../server-reference/includes/class-nr-aig-canonical.php';
require_once __DIR__ . '/../server-reference/includes/class-nr-aig-rest-controller.php';

final class TestRequest {
    private $headers;
    private $json;
    private $params;
    public function __construct(array $headers, array $json, array $params = array()) {
        $this->headers = $headers;
        $this->json = $json;
        $this->params = $params;
    }
    public function get_body() { return json_encode($this->json); }
    public function get_json_params() { return $this->json; }
    public function get_header($name) {
        foreach ($this->headers as $key => $value) {
            if (strcasecmp($key, $name) === 0) return $value;
        }
        return '';
    }
    public function get_param($name) {
        if (array_key_exists($name, $this->params)) return $this->params[$name];
        return $this->json[$name] ?? null;
    }
}

final class TestAuth implements NR_AIG_Guest_Authenticator_Interface {
    public function permission($request) { return true; }
    public function context($request) {
        return array(
            'guest_id' => 'nrog-' . str_repeat('a', 32),
            'guest_key' => hash('sha256', 'nrog-' . str_repeat('a', 32) . ':18'),
            'agent_id' => 18,
            'agent_slug' => 'test-agent',
        );
    }
    public function bridge_ready() { return true; }
}

final class SharedFileStore implements NR_AIG_Store_Interface {
    private $path;
    public function __construct($path) { $this->path = $path; }
    private function transaction(callable $fn) {
        $handle = fopen($this->path, 'c+');
        if (!$handle || !flock($handle, LOCK_EX)) throw new RuntimeException('lock failed');
        rewind($handle);
        $raw = stream_get_contents($handle);
        $state = $raw ? json_decode($raw, true) : array('next_id' => 1, 'rows' => array());
        if (!is_array($state)) $state = array('next_id' => 1, 'rows' => array());
        $result = $fn($state);
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($state, JSON_UNESCAPED_SLASHES));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        return $result;
    }
    public function ensure_schema() { return true; }
    public function schema_ready() { return true; }
    public function reserve_action(array $guest, array $action) {
        return $this->transaction(function (&$state) use ($guest, $action) {
            $key = $guest['guest_key'] . ':' . $action['action_id'];
            if (isset($state['rows'][$key])) {
                $row = $state['rows'][$key];
                if (!hash_equals($row['fingerprint_sha256'], $action['fingerprint_sha256']) || $row['action_type'] !== $action['action_type']) {
                    return new WP_Error('IDEMPOTENCY_FINGERPRINT_MISMATCH', 'immutable mismatch', array('status' => 409));
                }
                return array('owner' => false, 'idempotency_status' => 'replayed', 'row' => $row);
            }
            $now = gmdate('Y-m-d H:i:s');
            $row = array(
                'id' => $state['next_id']++,
                'guest_key' => $guest['guest_key'],
                'agent_id' => $guest['agent_id'],
                'action_id' => $action['action_id'],
                'action_type' => $action['action_type'],
                'fingerprint_sha256' => $action['fingerprint_sha256'],
                'state' => 'reserved',
                'receipt_id' => 'nrreceipt_' . str_repeat('b', 32),
                'public_write_attempted' => 0,
                'dispatch_count' => 0,
                'object_id' => null,
                'public_url' => null,
                'error_code' => null,
                'error_message' => null,
                'result_json' => null,
                'created_at' => $now,
                'updated_at' => $now,
                'expires_at' => gmdate('Y-m-d H:i:s', time() + 7200),
                'committed_at' => null,
            );
            $state['rows'][$key] = $row;
            return array('owner' => true, 'idempotency_status' => 'created', 'row' => $row);
        });
    }
    public function claim_dispatch($row_id) {
        return $this->transaction(function (&$state) use ($row_id) {
            foreach ($state['rows'] as &$row) {
                if ((int) $row['id'] === (int) $row_id && $row['state'] === 'reserved' && (int) $row['dispatch_count'] === 0) {
                    $row['state'] = 'processing';
                    $row['public_write_attempted'] = 1;
                    $row['dispatch_count'] = 1;
                    $row['updated_at'] = gmdate('Y-m-d H:i:s');
                    return true;
                }
            }
            unset($row);
            return false;
        });
    }
    public function get_action($guest_key, $action_id) {
        return $this->transaction(function (&$state) use ($guest_key, $action_id) {
            $key = $guest_key . ':' . $action_id;
            return $state['rows'][$key] ?? null;
        });
    }
    public function get_receipt($receipt_id) {
        return $this->transaction(function (&$state) use ($receipt_id) {
            foreach ($state['rows'] as $row) if ($row['receipt_id'] === $receipt_id) return $row;
            return null;
        });
    }
    public function mark_committed($row_id, $object_id, $public_url, array $safe_result) {
        return $this->transaction(function (&$state) use ($row_id, $object_id, $public_url, $safe_result) {
            foreach ($state['rows'] as &$row) {
                if ((int) $row['id'] === (int) $row_id && $row['state'] === 'processing') {
                    $row['state'] = 'committed';
                    $row['object_id'] = (int) $object_id;
                    $row['public_url'] = (string) $public_url;
                    $row['result_json'] = json_encode($safe_result);
                    $row['updated_at'] = gmdate('Y-m-d H:i:s');
                    $row['committed_at'] = $row['updated_at'];
                    return true;
                }
            }
            unset($row);
            return false;
        });
    }
    public function mark_failed($row_id, $error_code, $error_message) { return $this->mark_terminal($row_id, 'failed', $error_code, $error_message); }
    public function mark_unknown($row_id, $error_code, $error_message) { return $this->mark_terminal($row_id, 'unknown', $error_code, $error_message); }
    private function mark_terminal($row_id, $stateName, $code, $message) {
        return $this->transaction(function (&$state) use ($row_id, $stateName, $code, $message) {
            foreach ($state['rows'] as &$row) {
                if ((int) $row['id'] === (int) $row_id && $row['state'] === 'processing') {
                    $row['state'] = $stateName;
                    $row['error_code'] = $code;
                    $row['error_message'] = $message;
                    return true;
                }
            }
            unset($row);
            return false;
        });
    }
    public function mark_expired_reserved_failed() { return 0; }
    public function mark_stale_processing_unknown() { return 0; }
    public function cleanup() { return 0; }
}

final class CountingDispatcher implements NR_AIG_Action_Dispatcher_Interface {
    private $counterPath;
    public function __construct($counterPath) { $this->counterPath = $counterPath; }
    public function bridge_ready() { return true; }
    public function dispatch(array $guest, array $action, $original_request) {
        $handle = fopen($this->counterPath, 'c+');
        flock($handle, LOCK_EX);
        rewind($handle);
        $raw = trim(stream_get_contents($handle));
        $count = $raw === '' ? 0 : (int) $raw;
        $count++;
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, (string) $count);
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        usleep(150000);
        return array(
            'outcome' => 'committed',
            'object_id' => 901,
            'public_url' => 'https://noderooms.com/noderooms-post/?post_id=901',
            'safe_result' => array('post_id' => 901, 'room_slug' => 'playground'),
        );
    }
}

function make_request($actionId, $body) {
    $payloadForFingerprint = array('kind' => 'guest_post', 'roomSlug' => 'playground', 'body' => $body);
    $fingerprint = hash('sha256', NR_AIG_Canonical::canonical_json($payloadForFingerprint));
    $json = array(
        'action_id' => $actionId,
        'action_type' => 'guest_post',
        'fingerprint_sha256' => $fingerprint,
        'payload' => array('room_slug' => 'playground', 'body' => $body),
    );
    return new TestRequest(array(
        'Idempotency-Key' => $actionId,
        'X-NodeRooms-Action-Fingerprint' => $fingerprint,
    ), $json);
}

function fail_test($message) {
    fwrite(STDERR, "FAIL: {$message}\n");
    exit(1);
}

$root = sys_get_temp_dir() . '/nr-aig-concurrency-' . bin2hex(random_bytes(6));
mkdir($root, 0700, true);
$statePath = $root . '/state.json';
$counterPath = $root . '/dispatch-count.txt';
file_put_contents($counterPath, '0');
$actionId = 'nrwi_' . str_repeat('c', 32);
$children = array();

for ($i = 0; $i < 16; $i++) {
    $pid = pcntl_fork();
    if ($pid === -1) fail_test('pcntl_fork failed');
    if ($pid === 0) {
        $controller = new NR_AIG_Rest_Controller(
            new SharedFileStore($statePath),
            new TestAuth(),
            new CountingDispatcher($counterPath)
        );
        $result = $controller->create_action(make_request($actionId, 'concurrency proof'));
        if (is_wp_error($result)) exit(10);
        if (!is_array($result) || !in_array($result['action_status'] ?? '', array('processing', 'committed'), true)) exit(11);
        exit(0);
    }
    $children[] = $pid;
}

foreach ($children as $pid) {
    pcntl_waitpid($pid, $status);
    if (pcntl_wexitstatus($status) !== 0) fail_test('concurrent child failed with ' . pcntl_wexitstatus($status));
}

$dispatchCount = (int) trim(file_get_contents($counterPath));
if ($dispatchCount !== 1) fail_test('expected one dispatch, got ' . $dispatchCount);

$store = new SharedFileStore($statePath);
$guest = (new TestAuth())->context(null);
$row = $store->get_action($guest['guest_key'], $actionId);
if (!$row || $row['state'] !== 'committed' || (int) $row['dispatch_count'] !== 1 || (int) $row['object_id'] !== 901) {
    fail_test('final canonical row is invalid');
}

$controller = new NR_AIG_Rest_Controller($store, new TestAuth(), new CountingDispatcher($counterPath));
$conflict = $controller->create_action(make_request($actionId, 'different immutable payload'));
if (!is_wp_error($conflict) || $conflict->get_error_code() !== 'IDEMPOTENCY_FINGERPRINT_MISMATCH') {
    fail_test('fingerprint conflict was not rejected');
}
$data = $conflict->get_error_data();
if (!is_array($data) || (int) ($data['status'] ?? 0) !== 409) fail_test('fingerprint conflict did not return status 409');
if ((int) trim(file_get_contents($counterPath)) !== 1) fail_test('fingerprint conflict caused a new dispatch');

$storeSource = file_get_contents(__DIR__ . '/../server-reference/includes/class-nr-aig-wpdb-store.php');
foreach (array(
    'UNIQUE KEY guest_action (guest_key,action_id)',
    'INSERT IGNORE INTO',
    "state = 'processing'",
    "state = 'reserved'",
    'public_write_attempted = 0',
    'dispatch_count = 0',
) as $needle) {
    if (strpos($storeSource, $needle) === false) fail_test('missing atomic SQL contract: ' . $needle);
}

echo "SERVER_CONCURRENT_COMMIT=PASS\n";
echo "SERVER_DISPATCH_COUNT=1\n";
echo "SERVER_FINGERPRINT_CONFLICT=PASS\n";
echo "SERVER_FINGERPRINT_CONFLICT_NEW_DISPATCHES=0\n";
echo "WPDB_ATOMIC_SQL_CONTRACT=PASS\n";

@unlink($statePath);
@unlink($counterPath);
@rmdir($root);
