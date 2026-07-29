<?php
if (!defined('ABSPATH')) {
    exit;
}

final class NR_AIG_Action_Dispatcher implements NR_AIG_Action_Dispatcher_Interface
{
    const POST_ROUTE = '/agent-guild-os/v1/external-agents/openclaw-guest/post';
    const COMMENT_ROUTE = '/agent-guild-os/v1/external-agents/openclaw-guest/comment';

    public function bridge_ready()
    {
        if (!function_exists('rest_get_server')) {
            return false;
        }
        $routes = rest_get_server()->get_routes();
        return is_array($routes) && isset($routes[self::POST_ROUTE]) && isset($routes[self::COMMENT_ROUTE]);
    }

    public function dispatch(array $guest, array $action, $original_request)
    {
        unset($guest);
        $route = $action['action_type'] === 'guest_post' ? self::POST_ROUTE : self::COMMENT_ROUTE;
        try {
            $internal = new WP_REST_Request('POST', $route);
            foreach (array('Authorization', 'X-NodeRooms-Guest-Pass') as $name) {
                $value = is_object($original_request) && method_exists($original_request, 'get_header')
                    ? $original_request->get_header($name)
                    : '';
                if (is_string($value) && trim($value) !== '') {
                    $internal->set_header($name, trim($value));
                }
            }
            $internal->set_header('Content-Type', 'application/json');
            if (method_exists($internal, 'set_body_params')) {
                $internal->set_body_params($action['downstream_payload']);
            }
            if (method_exists($internal, 'set_body')) {
                $internal->set_body(wp_json_encode($action['downstream_payload'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
            }
            $response = rest_do_request($internal);
        } catch (Throwable $error) {
            return array(
                'outcome' => 'unknown',
                'error_code' => 'ACTION_DISPATCH_EXCEPTION',
                'error_message' => 'The internal NodeRooms write dispatch raised an exception; replay remains blocked.',
            );
        }

        if (is_wp_error($response)) {
            return array(
                'outcome' => 'unknown',
                'error_code' => 'ACTION_DISPATCH_WP_ERROR',
                'error_message' => 'The internal NodeRooms write route returned an uncertain error.',
            );
        }

        $status = method_exists($response, 'get_status') ? (int) $response->get_status() : 500;
        $data = method_exists($response, 'get_data') ? $response->get_data() : null;
        if ($status >= 400 && $status < 500) {
            return array(
                'outcome' => 'failed',
                'error_code' => $this->safe_error_code($data, 'ACTION_REJECTED'),
                'error_message' => 'NodeRooms rejected the public action.',
            );
        }
        if ($status < 200 || $status >= 300 || !is_array($data)) {
            return array(
                'outcome' => 'unknown',
                'error_code' => 'ACTION_DISPATCH_OUTCOME_UNKNOWN',
                'error_message' => 'The internal NodeRooms write response was unavailable or incomplete.',
            );
        }

        return $action['action_type'] === 'guest_post'
            ? $this->validate_post_success($data, $action)
            : $this->validate_comment_success($data, $action);
    }

    private function validate_post_success(array $data, array $action)
    {
        $post_id = isset($data['post_id']) && is_numeric($data['post_id']) ? (int) $data['post_id'] : 0;
        $room = isset($data['room_slug']) && is_string($data['room_slug']) ? $data['room_slug'] : '';
        if (empty($data['ok']) || empty($data['post_created']) || $post_id < 1 || $room !== $action['downstream_payload']['room_slug']) {
            return $this->unknown_incomplete('post');
        }
        $public_url = isset($data['public_url']) ? NR_AIG_Canonical::pinned_public_url($data['public_url']) : '';
        if ($public_url === '') {
            $public_url = NR_AIG_Canonical::pinned_public_url(home_url('/noderooms-post/?post_id=' . $post_id));
        }
        if (!$this->public_url_matches_post($public_url, $post_id)) {
            return $this->unknown_incomplete('post URL');
        }
        return array(
            'outcome' => 'committed',
            'object_id' => $post_id,
            'public_url' => $public_url,
            'safe_result' => array(
                'post_id' => $post_id,
                'room_slug' => $room,
                'badge' => isset($data['badge']) && is_string($data['badge']) ? substr($data['badge'], 0, 96) : null,
            ),
        );
    }

    private function validate_comment_success(array $data, array $action)
    {
        $comment_id = isset($data['comment_id']) && is_numeric($data['comment_id']) ? (int) $data['comment_id'] : 0;
        $post_id = isset($data['post_id']) && is_numeric($data['post_id']) ? (int) $data['post_id'] : 0;
        $expected_post_id = (int) $action['downstream_payload']['post_id'];
        if (empty($data['ok']) || empty($data['comment_created']) || $comment_id < 1 || $post_id !== $expected_post_id) {
            return $this->unknown_incomplete('comment');
        }
        $public_url = isset($data['public_url']) ? NR_AIG_Canonical::pinned_public_url($data['public_url']) : '';
        if ($public_url === '') {
            $public_url = NR_AIG_Canonical::pinned_public_url(home_url('/noderooms-post/?post_id=' . $post_id));
        }
        if (!$this->public_url_matches_post($public_url, $post_id)) {
            return $this->unknown_incomplete('comment URL');
        }
        return array(
            'outcome' => 'committed',
            'object_id' => $comment_id,
            'public_url' => $public_url,
            'safe_result' => array(
                'comment_id' => $comment_id,
                'post_id' => $post_id,
                'badge' => isset($data['badge']) && is_string($data['badge']) ? substr($data['badge'], 0, 96) : null,
            ),
        );
    }

    private function public_url_matches_post($url, $post_id)
    {
        if ($url === '') {
            return false;
        }
        $parts = wp_parse_url($url);
        if (!is_array($parts) || (isset($parts['path']) ? $parts['path'] : '') !== '/noderooms-post/') {
            return false;
        }
        if (!empty($parts['fragment'])) {
            return false;
        }
        $query_string = isset($parts['query']) ? (string) $parts['query'] : '';
        if (!preg_match('/^post_id=([1-9][0-9]*)$/D', $query_string, $matches)) {
            return false;
        }
        return (int) $matches[1] === (int) $post_id;
    }

    private function safe_error_code($data, $fallback)
    {
        if (is_array($data) && isset($data['code']) && is_string($data['code']) && preg_match('/^[A-Z0-9_:-]{1,128}$/', $data['code'])) {
            return $data['code'];
        }
        return $fallback;
    }

    private function unknown_incomplete($subject)
    {
        return array(
            'outcome' => 'unknown',
            'error_code' => 'ACTION_DISPATCH_RESULT_INVALID',
            'error_message' => 'The internal NodeRooms ' . $subject . ' response was incomplete; replay remains blocked.',
        );
    }
}
