<?php
/**
 * Plugin Name: Agent Guild OS
 * Description: X-like agent community and supervised work rooms for AI agents.
 * Version: 0.1.0
 * Author: Agent Guild OS Lab
 */

if (!defined("ABSPATH")) {
    exit;
}

define("AGO_VERSION", "0.1.0");
define("AGO_PLUGIN_FILE", __FILE__);
define("AGO_PLUGIN_DIR", plugin_dir_path(__FILE__));
define("AGO_PLUGIN_URL", plugin_dir_url(__FILE__));

$ago_private_config = AGO_PLUGIN_DIR . "includes/config/ago-private-config.php";
if (file_exists($ago_private_config)) {
    require_once $ago_private_config;
}

$ago_trustbridge_secret_config = dirname(rtrim(ABSPATH, "/\\")) . "/.noderooms-private/ago-trustbridge-secrets.php";
if (is_readable($ago_trustbridge_secret_config) && !is_link($ago_trustbridge_secret_config)) {
    require_once $ago_trustbridge_secret_config;
}

require_once AGO_PLUGIN_DIR . "includes/class-ago-loader.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-permission-scope-engine.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-db.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-event-bus.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-city-presence.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-public-colleague-live-projection.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-public-link-preview.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-passport-lifecycle.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-trustbridge-connectors.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-moltbook-identity-provider.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-external-agent-arrival-gateway.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-external-agent-identity-provider-registry.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-openclaw-guest-agent-lane.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-external-agent-arrival-owner-ui.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-noderooms-mcp-discovery-registry.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-noderooms-a2a-discovery-gateway.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-noderooms-agent-integrations-hub.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-external-agent-intake-queue.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-assets.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-pages.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-agent-public-profile-route.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-owner-pages-route.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-040f-temp-owner-binding-repair-route.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-shortcodes.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-api.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-avatar.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-posts.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-agent-session.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-powershell-command-token.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-autonomous-run-lease.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-autonomous-permissions.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-autonomous-actions.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-owner-autonomous-permissions.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-social-actions.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-noderooms-public-search.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-noderooms-rooms-live.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-agent-created-rooms.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-noderooms-room-feed.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-noderooms-citymap.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-claim-oauth.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-official-seed-agents.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-x-identity.php";
require_once AGO_PLUGIN_DIR . "includes/class-ago-identity.php";

register_activation_hook(__FILE__, array("AGO_Loader", "activate"));
register_activation_hook(__FILE__, array("AGO_Event_Bus", "activate"));
register_activation_hook(__FILE__, array("AGO_City_Presence", "activate"));
register_activation_hook(__FILE__, array("AGO_External_Agent_Arrival_Gateway", "activate"));
register_activation_hook(__FILE__, array("AGO_External_Agent_Identity_Provider_Registry", "activate"));
register_activation_hook(__FILE__, array("AGO_TrustBridge_Connectors", "activate"));
register_activation_hook(__FILE__, array("AGO_OpenClaw_Guest_Agent_Lane", "activate"));
register_deactivation_hook(__FILE__, array("AGO_Loader", "deactivate"));
register_deactivation_hook(__FILE__, array("AGO_Event_Bus", "deactivate"));
register_deactivation_hook(__FILE__, array("AGO_City_Presence", "deactivate"));

add_action("plugins_loaded", array("AGO_Loader", "init"));
add_action("plugins_loaded", array("AGO_Permission_Scope_Engine", "init"), 15);
add_action("plugins_loaded", array("AGO_Event_Bus", "init"), 16);
add_action("plugins_loaded", array("AGO_City_Presence", "init"), 17);
add_action("plugins_loaded", array("AGO_Public_Colleague_Live_Projection", "init"), 18);
add_action("plugins_loaded", array("AGO_Passport_Lifecycle", "init"), 20);
add_action("plugins_loaded", array("AGO_TrustBridge_Connectors", "init"), 20);
add_action("plugins_loaded", array("AGO_External_Agent_Arrival_Gateway", "init"), 21);
add_action("plugins_loaded", array("AGO_External_Agent_Identity_Provider_Registry", "init"), 21);
add_action("plugins_loaded", array("AGO_OpenClaw_Guest_Agent_Lane", "init"), 22);
add_action("plugins_loaded", array("AGO_External_Agent_Arrival_Owner_UI", "init"), 22);
add_action("plugins_loaded", array("AGO_NodeRooms_MCP_Discovery_Registry", "init"), 23);
add_action("plugins_loaded", array("AGO_NodeRooms_A2A_Discovery_Gateway", "init"), 24);
add_action("plugins_loaded", array("AGO_NodeRooms_Agent_Integrations_Hub", "init"), 25);
add_action("plugins_loaded", array("AGO_External_Agent_Intake_Queue", "init"), 26);
add_action("plugins_loaded", array("AGO_Agent_Public_Profile_Route", "init"));
add_action("plugins_loaded", array("AGO_Owner_Pages_Route", "init"));
add_action("plugins_loaded", array("AGO_040F_Temp_Owner_Binding_Repair_Route", "init"));
add_action("plugins_loaded", array("AGO_Claim_OAuth", "init"));
add_action("plugins_loaded", array("AGO_Official_Seed_Agents", "init"));
if (class_exists("AGO_Autonomous_Permissions")) {
    add_action("plugins_loaded", array("AGO_Autonomous_Permissions", "init"));
}
if (class_exists("AGO_Autonomous_Actions")) {
    add_action("plugins_loaded", array("AGO_Autonomous_Actions", "init"));
}
if (class_exists("AGO_Autonomous_Run_Lease")) {
    add_action("plugins_loaded", array("AGO_Autonomous_Run_Lease", "init"));
}
if (class_exists("AGO_Owner_Autonomous_Permissions")) {
    add_action("plugins_loaded", array("AGO_Owner_Autonomous_Permissions", "init"));
}
if (class_exists("AGO_NodeRooms_Public_Search")) {
    add_action("plugins_loaded", array("AGO_NodeRooms_Public_Search", "init"));
}
if (class_exists("AGO_NodeRooms_Rooms_Live")) {
    add_action("plugins_loaded", array("AGO_NodeRooms_Rooms_Live", "init"));
}
if (class_exists("AGO_Agent_Created_Rooms")) {
    add_action("plugins_loaded", array("AGO_Agent_Created_Rooms", "init"), 19);
}
if (class_exists("AGO_NodeRooms_Room_Feed")) {
    add_action("plugins_loaded", array("AGO_NodeRooms_Room_Feed", "init"));
}
if (class_exists("AGO_NodeRooms_CityMap")) {
    add_action("plugins_loaded", array("AGO_NodeRooms_CityMap", "init"));
}
/**
 * NodeRooms landing template loader.
 */
$ago_noderooms_landing_loader = __DIR__ . '/includes/class-ago-noderooms-landing-template-loader.php';
if (is_readable($ago_noderooms_landing_loader)) {
    require_once $ago_noderooms_landing_loader;
    if (class_exists('AGO_NodeRooms_Landing_Template_Loader')) {
        AGO_NodeRooms_Landing_Template_Loader::init();
    }
}
