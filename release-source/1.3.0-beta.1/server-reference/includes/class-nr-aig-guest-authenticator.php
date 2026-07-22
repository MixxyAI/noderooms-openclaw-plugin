<?php
if (!defined('ABSPATH')) {
    exit;
}

final class NR_AIG_Guest_Authenticator implements NR_AIG_Guest_Authenticator_Interface
{
    const ME_ROUTE = '/agent-guild-os/v1/external-agents/openclaw-guest/me';
    private $cache = array();

    public function permission($request)
    {
        $context = $this->context($request);
        return is_wp_error($context) ? $context : true;
    }

    public function context($request)
    {
        $cache_key = is_object($request) ? spl_object_hash($request) : 'default';
        if (array_key_exists($cache_key, $this->cache)) {
            return $this->cache[$cache_key];
        }

        if (!$this->bridge_ready()) {
            $error = new WP_Error('NR_GUEST_AUTH_BRIDGE_UNAVAILABLE', 'The NodeRooms Guest authentication bridge is unavailable.', array('status' => 503));
            $this->cache[$cache_key] = $error;
            return $error;
        }

        try {
            $internal = new WP_REST_Request('GET', self::ME_ROUTE);
            $this->copy_auth_headers($request, $internal);
            $response = rest_do_request($internal);
        } catch (Throwable $error) {
            unset($error);
            $result = new WP_Error('NR_GUEST_AUTH_UNAVAILABLE', 'NodeRooms Guest authentication could not be completed.', array('status' => 401));
            $this->cache[$cache_key] = $result;
            return $result;
        }

        if (is_wp_error($response)) {
            $result = new WP_Error('NR_GUEST_AUTH_INVALID', 'NodeRooms Guest authentication failed.', array('status' => 401));
            $this->cache[$cache_key] = $result;
            return $result;
        }
        $status = method_exists($response, 'get_status') ? (int) $response->get_status() : 500;
        $data = method_exists($response, 'get_data') ? $response->get_data() : null;
        if ($status < 200 || $status >= 300) {
            $result = new WP_Error('NR_GUEST_AUTH_INVALID', 'NodeRooms Guest authentication failed.', array('status' => 401));
            $this->cache[$cache_key] = $result;
            return $result;
        }

        $result = NR_AIG_Canonical::guest_context_from_data($data);
        $this->cache[$cache_key] = $result;
        return $result;
    }

    public function bridge_ready()
    {
        if (!function_exists('rest_get_server')) {
            return false;
        }
        $routes = rest_get_server()->get_routes();
        return is_array($routes) && isset($routes[self::ME_ROUTE]);
    }

    private function copy_auth_headers($source, $target)
    {
        foreach (array('Authorization', 'X-NodeRooms-Guest-Pass') as $name) {
            $value = is_object($source) && method_exists($source, 'get_header') ? $source->get_header($name) : '';
            if (is_string($value) && trim($value) !== '') {
                $target->set_header($name, trim($value));
            }
        }
    }
}
