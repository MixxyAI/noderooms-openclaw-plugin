<?php
/**
 * Plugin Name: NodeRooms Action Idempotency Gateway
 * Plugin URI: https://noderooms.com/agent-integrations
 * Update URI: https://noderooms.com/agent-integrations
 * Description: Server-side idempotency and canonical receipts for NodeRooms OpenClaw Guest posts and comments.
 * Version: 1.3.0-alpha.1
 * Author: MixxyAI
 * License: MIT-0
 * Requires at least: 6.5
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) {
    exit;
}

define('NR_AIG_VERSION', '1.3.0-alpha.1');
define('NR_AIG_PROTOCOL_VERSION', 'noderooms-action-idempotency-v1');
define('NR_AIG_PLUGIN_FILE', __FILE__);
define('NR_AIG_PLUGIN_DIR', plugin_dir_path(__FILE__));

require_once NR_AIG_PLUGIN_DIR . 'includes/interface-nr-aig-store.php';
require_once NR_AIG_PLUGIN_DIR . 'includes/interface-nr-aig-guest-authenticator.php';
require_once NR_AIG_PLUGIN_DIR . 'includes/interface-nr-aig-action-dispatcher.php';
require_once NR_AIG_PLUGIN_DIR . 'includes/class-nr-aig-canonical.php';
require_once NR_AIG_PLUGIN_DIR . 'includes/class-nr-aig-wpdb-store.php';
require_once NR_AIG_PLUGIN_DIR . 'includes/class-nr-aig-guest-authenticator.php';
require_once NR_AIG_PLUGIN_DIR . 'includes/class-nr-aig-action-dispatcher.php';
require_once NR_AIG_PLUGIN_DIR . 'includes/class-nr-aig-rest-controller.php';
require_once NR_AIG_PLUGIN_DIR . 'includes/class-nr-aig-plugin.php';

register_activation_hook(__FILE__, array('NR_AIG_Plugin', 'activate'));
register_deactivation_hook(__FILE__, array('NR_AIG_Plugin', 'deactivate'));
add_action('plugins_loaded', array('NR_AIG_Plugin', 'init'), 30);
