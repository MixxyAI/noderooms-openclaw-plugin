<?php
if (!defined('ABSPATH')) {
    exit;
}

final class NR_AIG_Canonical
{
    const ACTION_ID_PATTERN = '/^nrwi_[a-f0-9]{32}$/D';
    const RECEIPT_ID_PATTERN = '/^nrreceipt_[a-f0-9]{32}$/D';
    const FINGERPRINT_PATTERN = '/^[a-f0-9]{64}$/D';
    const GUEST_ID_PATTERN = '/^nrog-[a-f0-9]{32}$/D';

    public static function normalize_action($request)
    {
        if (is_object($request) && method_exists($request, 'get_body')) {
            $raw_body = (string) $request->get_body();
            if (strlen($raw_body) > 8192) {
                return new WP_Error('NR_ACTION_BODY_TOO_LARGE', 'The action request body is too large.', array('status' => 413));
            }
        }
        $json = is_object($request) && method_exists($request, 'get_json_params')
            ? $request->get_json_params()
            : null;
        if (!is_array($json) || !self::has_exact_keys($json, array('action_id', 'action_type', 'fingerprint_sha256', 'payload'))) {
            return new WP_Error('NR_ACTION_BODY_INVALID', 'The action request must contain exactly action_id, action_type, fingerprint_sha256, and payload.', array('status' => 400));
        }

        $action_id = is_string($json['action_id']) ? $json['action_id'] : '';
        $action_type = is_string($json['action_type']) ? $json['action_type'] : '';
        $fingerprint = is_string($json['fingerprint_sha256']) ? $json['fingerprint_sha256'] : '';
        $payload = $json['payload'];

        if (!preg_match(self::ACTION_ID_PATTERN, $action_id)) {
            return new WP_Error('NR_ACTION_ID_INVALID', 'The action id is invalid.', array('status' => 400));
        }
        if (!preg_match(self::FINGERPRINT_PATTERN, $fingerprint)) {
            return new WP_Error('NR_ACTION_FINGERPRINT_INVALID', 'The action fingerprint must be a lowercase SHA-256 value.', array('status' => 400));
        }
        if ($action_type !== 'guest_post' && $action_type !== 'guest_comment') {
            return new WP_Error('NR_ACTION_TYPE_INVALID', 'The action type is unsupported.', array('status' => 400));
        }
        if (!is_array($payload)) {
            return new WP_Error('NR_ACTION_PAYLOAD_INVALID', 'The action payload is invalid.', array('status' => 400));
        }

        $idempotency_header = self::header($request, 'Idempotency-Key');
        $fingerprint_header = self::header($request, 'X-NodeRooms-Action-Fingerprint');
        if ($idempotency_header === '' || !hash_equals($action_id, $idempotency_header)) {
            return new WP_Error('NR_IDEMPOTENCY_KEY_MISMATCH', 'The Idempotency-Key header must exactly match action_id.', array('status' => 400));
        }
        if ($fingerprint_header === '' || !hash_equals($fingerprint, $fingerprint_header)) {
            return new WP_Error('NR_ACTION_FINGERPRINT_HEADER_MISMATCH', 'The action fingerprint header must exactly match fingerprint_sha256.', array('status' => 400));
        }

        if ($action_type === 'guest_post') {
            if (!self::has_exact_keys($payload, array('room_slug', 'body'))) {
                return new WP_Error('NR_ACTION_PAYLOAD_INVALID', 'A Guest post payload must contain exactly room_slug and body.', array('status' => 400));
            }
            $room_slug = is_string($payload['room_slug']) ? $payload['room_slug'] : '';
            $body = is_string($payload['body']) ? $payload['body'] : '';
            if ($room_slug !== 'playground' && $room_slug !== 'builders-lab') {
                return new WP_Error('NR_ACTION_ROOM_INVALID', 'Guest posts are limited to the approved Guest rooms.', array('status' => 400));
            }
            if (!self::valid_text($body, 2, 600)) {
                return new WP_Error('NR_ACTION_BODY_INVALID', 'The Guest post body is invalid.', array('status' => 400));
            }
            $fingerprint_payload = array(
                'kind' => 'guest_post',
                'roomSlug' => $room_slug,
                'body' => $body,
            );
            $downstream = array('room_slug' => $room_slug, 'body' => $body);
        } else {
            if (!self::has_exact_keys($payload, array('post_id', 'body'))) {
                return new WP_Error('NR_ACTION_PAYLOAD_INVALID', 'A Guest comment payload must contain exactly post_id and body.', array('status' => 400));
            }
            $post_id = is_int($payload['post_id']) ? $payload['post_id'] : 0;
            $body = is_string($payload['body']) ? $payload['body'] : '';
            if ($post_id < 1 || !self::valid_text($body, 2, 400)) {
                return new WP_Error('NR_ACTION_PAYLOAD_INVALID', 'The Guest comment payload is invalid.', array('status' => 400));
            }
            $fingerprint_payload = array(
                'kind' => 'guest_comment',
                'postId' => $post_id,
                'body' => $body,
            );
            $downstream = array('post_id' => $post_id, 'body' => $body);
        }

        $calculated = hash('sha256', self::canonical_json($fingerprint_payload));
        if (!hash_equals($calculated, $fingerprint)) {
            return new WP_Error('IDEMPOTENCY_FINGERPRINT_MISMATCH', 'The fingerprint does not match the immutable canonical action payload.', array('status' => 409));
        }

        return array(
            'action_id' => $action_id,
            'action_type' => $action_type,
            'fingerprint_sha256' => $fingerprint,
            'downstream_payload' => $downstream,
        );
    }

    public static function guest_context_from_data($data)
    {
        if (!is_array($data) || empty($data['ok'])) {
            return new WP_Error('NR_GUEST_AUTH_INVALID', 'NodeRooms Guest authentication failed.', array('status' => 401));
        }
        $candidate = $data;
        if (isset($data['guest']) && is_array($data['guest'])) {
            $candidate = array_merge($data, $data['guest']);
        }
        $guest_id = isset($candidate['guest_id']) && is_string($candidate['guest_id']) ? $candidate['guest_id'] : '';
        $agent_id = isset($candidate['agent_id']) && is_numeric($candidate['agent_id']) ? (int) $candidate['agent_id'] : 0;
        $agent_slug = isset($candidate['agent_slug']) && is_string($candidate['agent_slug']) ? $candidate['agent_slug'] : '';
        if (!preg_match(self::GUEST_ID_PATTERN, $guest_id) || $agent_id < 1) {
            return new WP_Error('NR_GUEST_AUTH_INVALID', 'NodeRooms did not return a complete authenticated Guest identity.', array('status' => 401));
        }
        return array(
            'guest_id' => $guest_id,
            'guest_key' => hash('sha256', $guest_id . ':' . $agent_id),
            'agent_id' => $agent_id,
            'agent_slug' => sanitize_title($agent_slug),
        );
    }

    public static function receipt(array $row, $idempotency_status)
    {
        $stored_state = isset($row['state']) ? (string) $row['state'] : 'unknown';
        $state = $stored_state;
        if ($state === 'reserved' || $state === 'processing') {
            $state = 'processing';
        }
        if (!in_array($state, array('committed', 'failed', 'processing', 'unknown'), true)) {
            $state = 'unknown';
        }
        $object_id = isset($row['object_id']) ? (int) $row['object_id'] : 0;
        $public_url = isset($row['public_url']) ? self::pinned_public_url($row['public_url']) : '';
        $public_write_attempted = !empty($row['public_write_attempted']);
        $dispatch_count = isset($row['dispatch_count']) ? (int) $row['dispatch_count'] : 0;
        $replay_blocked = $stored_state !== 'reserved';

        return array(
            'ok' => $state === 'committed',
            'protocol_version' => NR_AIG_PROTOCOL_VERSION,
            'action_id' => (string) $row['action_id'],
            'receipt_id' => (string) $row['receipt_id'],
            'action_type' => (string) $row['action_type'],
            'action_status' => $state,
            'idempotency_status' => $idempotency_status === 'created' ? 'created' : 'replayed',
            'fingerprint_sha256' => (string) $row['fingerprint_sha256'],
            'server_idempotency_enforced' => true,
            'duplicate_write_prevented' => true,
            'unknown_outcome_replay_blocked' => true,
            'replay_blocked' => $replay_blocked,
            'public_write_attempted' => $public_write_attempted,
            'dispatch_count' => $dispatch_count,
            'exactly_once_effect' => false,
            'object_id' => $object_id > 0 ? $object_id : null,
            'public_url' => $public_url !== '' ? $public_url : null,
            'error_code' => !empty($row['error_code']) ? (string) $row['error_code'] : null,
            'error_message' => !empty($row['error_message']) ? (string) $row['error_message'] : null,
            'created_at' => self::mysql_utc_to_iso((string) $row['created_at']),
            'updated_at' => self::mysql_utc_to_iso((string) $row['updated_at']),
            'expires_at' => !empty($row['expires_at']) ? self::mysql_utc_to_iso((string) $row['expires_at']) : null,
            'committed_at' => !empty($row['committed_at']) ? self::mysql_utc_to_iso((string) $row['committed_at']) : null,
        );
    }

    public static function public_receipt(array $row)
    {
        $receipt = self::receipt($row, 'replayed');
        unset($receipt['error_message']);
        return $receipt;
    }

    public static function canonical_json($value)
    {
        if (is_array($value)) {
            if (self::is_list($value)) {
                $parts = array();
                foreach ($value as $entry) {
                    $parts[] = self::canonical_json($entry);
                }
                return '[' . implode(',', $parts) . ']';
            }
            $keys = array_keys($value);
            sort($keys, SORT_STRING);
            $parts = array();
            foreach ($keys as $key) {
                $parts[] = wp_json_encode((string) $key, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
                    . ':' . self::canonical_json($value[$key]);
            }
            return '{' . implode(',', $parts) . '}';
        }
        return wp_json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public static function safe_error_message($message)
    {
        $message = wp_strip_all_tags((string) $message, true);
        $message = preg_replace('/[\r\n\t]+/', ' ', $message);
        $message = preg_replace('/nrguest_[a-f0-9]{64}/i', '[REDACTED_GUEST_PASS]', $message);
        $message = preg_replace('/Bearer\s+[A-Za-z0-9._~-]{20,}/i', 'Bearer [REDACTED]', $message);
        return self::utf8_substr(trim($message), 0, 400);
    }

    public static function pinned_public_url($value)
    {
        $url = esc_url_raw((string) $value, array('https'));
        if ($url === '') {
            return '';
        }
        $parts = wp_parse_url($url);
        if (!is_array($parts)
            || strtolower((string) (isset($parts['scheme']) ? $parts['scheme'] : '')) !== 'https'
            || strtolower((string) (isset($parts['host']) ? $parts['host'] : '')) !== 'noderooms.com'
            || !empty($parts['user'])
            || !empty($parts['pass'])
            || (isset($parts['port']) && (int) $parts['port'] !== 443)) {
            return '';
        }
        return $url;
    }

    private static function header($request, $name)
    {
        if (!is_object($request) || !method_exists($request, 'get_header')) {
            return '';
        }
        $value = $request->get_header($name);
        return is_string($value) ? trim($value) : '';
    }

    private static function has_exact_keys(array $payload, array $allowed)
    {
        $keys = array_keys($payload);
        sort($keys, SORT_STRING);
        sort($allowed, SORT_STRING);
        return $keys === $allowed;
    }

    private static function valid_text($value, $minimum, $maximum)
    {
        if (!is_string($value) || !self::valid_utf8($value)) {
            return false;
        }
        $length = self::utf8_length($value);
        return $length >= $minimum && $length <= $maximum;
    }

    private static function mysql_utc_to_iso($value)
    {
        $time = strtotime($value . ' UTC');
        return $time ? gmdate('c', $time) : gmdate('c', 0);
    }

    private static function is_list(array $value)
    {
        $index = 0;
        foreach ($value as $key => $_entry) {
            if ($key !== $index) {
                return false;
            }
            $index++;
        }
        return true;
    }

    private static function valid_utf8($value)
    {
        return preg_match('//u', (string) $value) === 1;
    }

    private static function utf8_length($value)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($value, 'UTF-8');
        }
        if (function_exists('iconv_strlen')) {
            $length = iconv_strlen($value, 'UTF-8');
            if ($length !== false) {
                return $length;
            }
        }
        $matched = preg_match_all('/./us', $value, $matches);
        return $matched === false ? strlen($value) : $matched;
    }

    private static function utf8_substr($value, $start, $length)
    {
        if (function_exists('mb_substr')) {
            return mb_substr($value, $start, $length, 'UTF-8');
        }
        if (function_exists('iconv_substr')) {
            $result = iconv_substr($value, $start, $length, 'UTF-8');
            if ($result !== false) {
                return $result;
            }
        }
        preg_match_all('/./us', $value, $matches);
        return implode('', array_slice($matches[0], $start, $length));
    }
}
