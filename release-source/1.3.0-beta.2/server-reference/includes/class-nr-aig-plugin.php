<?php
if (!defined('ABSPATH')) {
    exit;
}

final class NR_AIG_Plugin
{
    const CLEANUP_HOOK = 'nr_aig_cleanup';
    private static $controller;

    public static function init()
    {
        $store = new NR_AIG_Wpdb_Store();
        if (get_option(NR_AIG_Wpdb_Store::SCHEMA_OPTION) !== NR_AIG_Wpdb_Store::SCHEMA_VERSION) {
            $store->ensure_schema();
        }
        $auth = new NR_AIG_Guest_Authenticator();
        $dispatcher = new NR_AIG_Action_Dispatcher();
        self::$controller = new NR_AIG_Rest_Controller($store, $auth, $dispatcher);
        add_action('rest_api_init', array(self::$controller, 'register_routes'), 40);
        add_action(self::CLEANUP_HOOK, array($store, 'cleanup'));
        if (!wp_next_scheduled(self::CLEANUP_HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::CLEANUP_HOOK);
        }
    }

    public static function activate()
    {
        $store = new NR_AIG_Wpdb_Store();
        if (!$store->ensure_schema()) {
            deactivate_plugins(plugin_basename(NR_AIG_PLUGIN_FILE));
            wp_die(
                esc_html__('NodeRooms Action Idempotency Gateway could not create or verify its database schema.', 'noderooms-action-idempotency-gateway'),
                esc_html__('Plugin activation failed', 'noderooms-action-idempotency-gateway'),
                array('back_link' => true)
            );
        }
        if (!wp_next_scheduled(self::CLEANUP_HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::CLEANUP_HOOK);
        }
    }

    public static function deactivate()
    {
        $timestamp = wp_next_scheduled(self::CLEANUP_HOOK);
        while ($timestamp) {
            wp_unschedule_event($timestamp, self::CLEANUP_HOOK);
            $timestamp = wp_next_scheduled(self::CLEANUP_HOOK);
        }
    }
}
