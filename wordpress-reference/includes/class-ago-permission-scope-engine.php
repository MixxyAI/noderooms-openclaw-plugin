<?php
if (!defined("ABSPATH")) {
    exit;
}

/**
 * Canonical NodeRooms permission and scope registry.
 *
 * This class is intentionally DB-free. It provides one fail-closed vocabulary
 * for Developer Credentials, Autonomous Permissions, Run Leases, API Travel,
 * Swarm, Memory and future reserved capabilities.
 */
class AGO_Permission_Scope_Engine
{
    const VERSION = "1.3.0-trustbridge-connectors";
    const REST_NAMESPACE = "agent-guild-os/v1";

    public static function init()
    {
        add_action("rest_api_init", array(__CLASS__, "register_routes"));
    }

    public static function register_routes()
    {
        register_rest_route(self::REST_NAMESPACE, "/permission-scopes/status", array(
            "methods" => "GET",
            "callback" => array(__CLASS__, "status"),
            "permission_callback" => "__return_true"
        ));
    }

    public static function status()
    {
        $catalog = self::catalog();
        $developer = self::developer_catalog();
        $reserved = self::reserved_scopes();

        return rest_ensure_response(array(
            "ok" => true,
            "module" => "AGO_Permission_Scope_Engine",
            "version" => self::VERSION,
            "canonical_scope_engine_ready" => true,
            "canonical_scope_count" => count($catalog),
            "developer_visible_scope_count" => count($developer),
            "credential_issuable_scope_count" => count(self::developer_credential_scopes()),
            "legacy_permission_key_count" => count(self::legacy_permission_keys()),
            "action_alias_count" => count(self::action_alias_map()),
            "reserved_scope_count" => count($reserved),
            "reserved_scopes" => $reserved,
            "owner_token_role" => "initial_owner_approval_only",
            "run_secret_role" => "bounded_internal_run_lease_only",
            "developer_credential_role" => "declared_developer_api_scopes_only",
            "api_travel_role" => "reviewed_destination_action_plus_agent.api_travel.write",
            "unknown_scopes_fail_closed" => true,
            "reserved_scopes_runtime_enabled" => false,
            "public_write_unlocked" => false,
            "public_posting_unlocked" => false,
            "db_write_performed" => false,
            "schema_change_performed" => false,
            "status" => "UNIFIED_PERMISSION_SCOPE_ENGINE_READY_PHASE1_2"
        ));
    }

    public static function catalog()
    {
        return array(
            "agent.identity.read" => self::scope_meta("Read Agent identity", "read", "runtime_enabled", "Read public-safe Agent identity metadata for external verification.", true, true, array("developer_api")),
            "agent.profile.read" => self::scope_meta("Read Agent profile", "read", "runtime_enabled", "Read public-safe Agent profile information and external links.", true, true, array("developer_api")),
            "agent.reputation.read" => self::scope_meta("Read Agent reputation", "read", "declared", "Read public-safe Agent reputation and badge signals.", true, true, array("developer_api")),
            "agent.feed.read" => self::scope_meta("Read Agent feed", "read", "runtime_enabled", "Read public-safe Agent feed, room feed, and single public post entries.", true, true, array("developer_api")),
            "agent.rooms.read" => self::scope_meta("Read NodeRooms catalog", "read", "runtime_enabled", "Read public-safe NodeRooms room catalog metadata.", true, true, array("developer_api")),
            "agent.citymap.read" => self::scope_meta("Read NodeRooms CityMap counts", "read", "runtime_enabled", "Read public-safe CityMap public activity counts by room.", true, true, array("developer_api")),
            "agent.swarm.read" => self::scope_meta("Read controlled Swarm Groups", "read", "runtime_enabled", "Read owner-bound Swarm Group status, members, tasks, and public-safe activity logs.", true, true, array("developer_api", "swarm")),

            "connector.gmail.account.connect" => self::scope_meta("Connect the Agent Gmail account", "control", "runtime_enabled", "Owner-only NodeRooms control for connecting Gmail to the exact owner-bound active Passport Agent.", false, false, array("trustbridge_connector", "run_lease")),
            "connector.gmail.account.disconnect" => self::scope_meta("Disconnect the Agent Gmail account", "control", "runtime_enabled", "Owner-only NodeRooms control for immediately revoking Gmail access from the exact Agent.", false, false, array("trustbridge_connector", "run_lease")),
            "connector.gmail.message.search" => self::scope_meta("Search Gmail messages", "read", "runtime_enabled", "Search the connected Gmail account through a one-action Agent-bound TrustBridge lease.", false, false, array("trustbridge_connector", "run_lease")),
            "connector.gmail.thread.read" => self::scope_meta("Read Gmail threads", "read", "runtime_enabled", "Read one exact Gmail thread through a one-action Agent-bound TrustBridge lease; remote content remains untrusted data.", false, false, array("trustbridge_connector", "run_lease")),
            "connector.gmail.draft.create" => self::scope_meta("Create Gmail drafts", "draft", "runtime_enabled", "Create an unsent draft through an Owner-approved purpose-bound capability and one-action run lease.", false, false, array("trustbridge_connector", "run_lease")),
            "connector.gmail.draft.send" => self::scope_meta("Send one exact Gmail draft", "write", "runtime_enabled", "Send only one exact draft under a verified human Owner allow-once receipt, a one-attempt reservation, and no automatic retry.", false, false, array("trustbridge_connector", "run_lease", "owner_allow_once")),
            "connector.gmail.message.delete" => self::scope_meta("Delete or Trash Gmail messages", "prohibited", "permanently_denied", "Permanently denied. No delete or Trash provider route exists.", false, false, array("forbidden", "trustbridge_connector")),

            "agent.post.write" => self::scope_meta("Create Agent posts", "write", "runtime_enabled", "Create public-safe Agent posts through an owner-bound permission or bounded lease.", true, true, array("developer_api", "autonomous_permission", "run_lease"), "autonomous_posting", "max_posts_per_hour"),
            "agent.comment.write" => self::scope_meta("Create Agent comments and replies", "write", "runtime_enabled", "Create public-safe Agent comments and replies through an owner-bound permission or bounded lease.", true, true, array("developer_api", "autonomous_permission", "run_lease"), "autonomous_commenting", "max_comments_per_hour"),
            "agent.like.write" => self::scope_meta("Create Agent likes", "write", "runtime_enabled", "Like public-safe posts through an owner-bound permission or bounded lease.", true, true, array("developer_api", "autonomous_permission", "run_lease"), "autonomous_like", "max_likes_per_hour"),
            "agent.bookmark.write" => self::scope_meta("Create Agent bookmarks", "write", "runtime_enabled", "Bookmark public-safe posts through an owner-bound developer credential or bounded run lease.", true, true, array("developer_api", "run_lease")),
            "agent.repost.write" => self::scope_meta("Create Agent reposts", "write", "runtime_enabled", "Repost public-safe posts through an owner-bound permission or bounded lease.", true, true, array("developer_api", "autonomous_permission", "run_lease"), "autonomous_repost", "max_reposts_per_hour"),
            "agent.follow.write" => self::scope_meta("Create Agent follows", "write", "runtime_enabled", "Follow verified active Agents through an owner-bound developer credential or bounded run lease.", true, true, array("developer_api", "run_lease")),
            "agent.pin.write" => self::scope_meta("Pin Agent posts", "write", "runtime_enabled", "Pin public-safe posts for an Agent through an owner-bound developer credential or bounded run lease.", true, true, array("developer_api", "run_lease")),
            "agent.room.move" => self::scope_meta("Move Agent between Rooms", "write", "runtime_enabled", "Move an Agent only between Owner-approved Rooms under room policy and rate limits.", false, false, array("autonomous_permission"), "autonomous_room_movement", "max_room_moves_per_hour"),
            "agent.memory.write" => self::scope_meta("Write private revalidation-required Agent memory", "write", "runtime_enabled", "Create bounded private Agent memory under a valid run lease; never training-ready by default.", false, false, array("run_lease", "memory")),
            "agent.profile.media.write" => self::scope_meta("Update Agent profile media", "write", "runtime_enabled", "Set public-safe Agent avatar and canvas URLs through an owner-bound developer credential.", true, true, array("developer_api", "profile_media")),
            "agent.profile.media.generate" => self::scope_meta("Generate Agent profile media", "write", "runtime_enabled", "Generate and save public-safe Agent media only through a separate Owner-approved one-use media lease.", true, false, array("profile_media_lease")),
            "agent.api_travel.write" => self::scope_meta("Call reviewed external API destinations", "write", "runtime_enabled", "Call reviewed API destinations through an owner-bound developer credential and scoped API Travel lease.", true, true, array("developer_api", "api_travel")),
            "agent.swarm.write" => self::scope_meta("Manage controlled Swarm Groups", "write", "runtime_enabled", "Create and manage Owner-approved Swarm Groups while preserving per-Agent identity and leases.", true, true, array("developer_api", "swarm")),
            "agent.instruction.write" => self::scope_meta("Send external Agent instructions", "write", "declared_next", "Reserved Owner-approved external instruction scope for API Travel and WorldMap workflows.", true, true, array("developer_api")),

            "agent.run.ping" => self::scope_meta("Ping an active Agent run", "control", "runtime_enabled", "Refresh a valid bounded run lease without using the Owner Command Token.", false, false, array("run_lease")),
            "agent.run.report" => self::scope_meta("Read an Agent run report", "control", "runtime_enabled", "Read the safe report of a secret-bound run lease.", false, false, array("run_lease")),
            "agent.run.stop" => self::scope_meta("Stop an Agent run", "control", "runtime_enabled", "Stop a secret-bound run lease and permit final safe checkpoint handling.", false, false, array("run_lease")),

            "agent.room.create" => self::scope_meta("Propose an Agent-created NodeRooms Room", "write", "runtime_enabled", "Propose one owner-reviewable Agent-created Room through an explicit positive run-lease proposal budget. The Agent chooses the topic; NodeRooms canonicalizes and gates activation.", false, false, array("run_lease", "agent_created_rooms")),
            "agent.import.create" => self::scope_meta("Import an external Agent", "write", "reserved_not_runtime_enabled", "Reserved for framework-independent Agent import and normalization.", false, false, array("future")),
            "agent.memory.import" => self::scope_meta("Import Agent memory", "write", "reserved_not_runtime_enabled", "Reserved for reviewed memory mapping during Agent import.", false, false, array("future")),
            "agent.memory.export" => self::scope_meta("Export Agent memory", "read", "reserved_not_runtime_enabled", "Reserved for Owner-approved portable memory export.", false, false, array("future")),
            "agent.discord.link" => self::scope_meta("Link verified Owner community access", "write", "reserved_not_runtime_enabled", "Reserved for a community-only Discord verification link; never a control-plane credential.", false, false, array("future"))
        );
    }

    public static function developer_catalog()
    {
        $out = array();
        foreach (self::catalog() as $scope => $meta) {
            if (!empty($meta["developer_visible"])) {
                $public = $meta;
                unset($public["developer_visible"], $public["legacy_permission"], $public["rate_limit_key"]);
                $out[$scope] = $public;
            }
        }
        return $out;
    }

    public static function default_developer_read_scopes()
    {
        return array(
            "agent.identity.read",
            "agent.profile.read",
            "agent.reputation.read",
            "agent.feed.read",
            "agent.rooms.read",
            "agent.citymap.read",
            "agent.swarm.read"
        );
    }

    public static function developer_write_scopes()
    {
        $out = array();
        foreach (self::catalog() as $scope => $meta) {
            if (!empty($meta["developer_visible"]) && (string) ($meta["access"] ?? "") === "write") {
                $out[] = $scope;
            }
        }
        return $out;
    }

    public static function developer_credential_scopes()
    {
        $out = array();
        foreach (self::catalog() as $scope => $meta) {
            if (!empty($meta["credential_issuable"])) {
                $out[] = $scope;
            }
        }
        return $out;
    }

    public static function reserved_scopes()
    {
        $out = array();
        foreach (self::catalog() as $scope => $meta) {
            if ((string) ($meta["status"] ?? "") === "reserved_not_runtime_enabled") {
                $out[] = $scope;
            }
        }
        return $out;
    }

    public static function normalize_scope($scope)
    {
        $scope = strtolower(trim((string) $scope));
        $scope = preg_replace('/[^a-z0-9._-]/', '', $scope);
        return is_string($scope) ? $scope : "";
    }

    public static function normalize_scopes($scopes, $known_only = true, $credential_only = false)
    {
        if (is_string($scopes)) {
            $decoded = json_decode($scopes, true);
            if (is_array($decoded)) {
                $scopes = $decoded;
            } else {
                $scopes = preg_split('/[\s,]+/', $scopes);
            }
        }

        if (!is_array($scopes)) {
            return array();
        }

        $catalog = self::catalog();
        $credential = array_flip(self::developer_credential_scopes());
        $out = array();

        foreach ($scopes as $scope) {
            $scope = self::normalize_scope($scope);
            if ($scope === "") {
                continue;
            }
            if ($known_only && !isset($catalog[$scope])) {
                continue;
            }
            if ($credential_only && !isset($credential[$scope])) {
                continue;
            }
            if (!in_array($scope, $out, true)) {
                $out[] = $scope;
            }
        }

        return $out;
    }

    public static function scope_exists($scope)
    {
        $scope = self::normalize_scope($scope);
        $catalog = self::catalog();
        return $scope !== "" && isset($catalog[$scope]);
    }

    public static function scope_runtime_enabled($scope)
    {
        $scope = self::normalize_scope($scope);
        $catalog = self::catalog();
        if ($scope === "" || !isset($catalog[$scope])) {
            return false;
        }
        return in_array((string) ($catalog[$scope]["status"] ?? ""), array("runtime_enabled", "declared"), true);
    }

    public static function legacy_permission_keys()
    {
        return array_keys(self::legacy_permission_to_scope_map());
    }

    public static function legacy_permission_to_scope_map()
    {
        return array(
            "autonomous_posting" => "agent.post.write",
            "autonomous_commenting" => "agent.comment.write",
            "autonomous_like" => "agent.like.write",
            "autonomous_repost" => "agent.repost.write",
            "autonomous_room_movement" => "agent.room.move"
        );
    }

    public static function legacy_permission_rate_limit_map()
    {
        return array(
            "autonomous_posting" => "max_posts_per_hour",
            "autonomous_commenting" => "max_comments_per_hour",
            "autonomous_like" => "max_likes_per_hour",
            "autonomous_repost" => "max_reposts_per_hour",
            "autonomous_room_movement" => "max_room_moves_per_hour"
        );
    }

    public static function scope_for_legacy_permission($permission_key)
    {
        $permission_key = sanitize_key((string) $permission_key);
        $map = self::legacy_permission_to_scope_map();
        return isset($map[$permission_key]) ? $map[$permission_key] : "";
    }

    public static function legacy_permission_for_scope($scope)
    {
        $scope = self::normalize_scope($scope);
        $map = array_flip(self::legacy_permission_to_scope_map());
        return isset($map[$scope]) ? $map[$scope] : "";
    }

    public static function legacy_permission_map_to_scopes($permission_map)
    {
        if (!is_array($permission_map)) {
            return array();
        }

        $out = array();
        foreach (self::legacy_permission_to_scope_map() as $permission => $scope) {
            if (!empty($permission_map[$permission])) {
                $out[] = $scope;
            }
        }
        return $out;
    }

    public static function scopes_to_legacy_permission_map($scopes, $default = false)
    {
        $out = array();
        foreach (self::legacy_permission_keys() as $permission) {
            $out[$permission] = (bool) $default;
        }

        foreach (self::normalize_scopes($scopes, true, false) as $scope) {
            $permission = self::legacy_permission_for_scope($scope);
            if ($permission !== "") {
                $out[$permission] = true;
            }
        }
        return $out;
    }

    public static function action_contract($action)
    {
        $action = self::normalize_action($action);
        $aliases = self::action_alias_map();
        if ($action === "" || !isset($aliases[$action])) {
            return array();
        }

        $canonical = $aliases[$action];
        $contracts = self::canonical_action_contracts();
        if (!isset($contracts[$canonical])) {
            return array();
        }

        return array_merge($contracts[$canonical], array(
            "requested_action" => $action,
            "canonical_action" => $canonical
        ));
    }

    public static function scope_for_action($action)
    {
        $contract = self::action_contract($action);
        return (string) ($contract["scope"] ?? "");
    }

    public static function legacy_permission_for_action($action)
    {
        $contract = self::action_contract($action);
        return (string) ($contract["legacy_permission"] ?? "");
    }

    public static function rate_limit_key_for_action($action)
    {
        $contract = self::action_contract($action);
        return (string) ($contract["rate_limit_key"] ?? "");
    }

    public static function run_limit_columns_for_action($action)
    {
        $contract = self::action_contract($action);
        $max = (string) ($contract["run_max_column"] ?? "");
        $used = (string) ($contract["run_used_column"] ?? "");
        if ($max === "" || $used === "") {
            return array();
        }
        return array("max" => $max, "used" => $used);
    }

    public static function run_lease_scope_decision($lease, $scope, $action = "")
    {
        $scope = self::normalize_scope($scope);
        $action = self::normalize_action($action);

        $base = array(
            "ok" => false,
            "allowed" => false,
            "scope_checked" => true,
            "scope" => $scope,
            "action" => $action,
            "engine_version" => self::VERSION,
            "public_write_unlocked" => false,
            "public_posting_unlocked" => false
        );

        if (!is_array($lease) || $scope === "" || !self::scope_exists($scope)) {
            $base["reason"] = "UNKNOWN_OR_INVALID_SCOPE";
            return $base;
        }

        if (!self::scope_runtime_enabled($scope)) {
            $base["reason"] = "SCOPE_NOT_RUNTIME_ENABLED";
            return $base;
        }

        /* NR-EAAG-005_SCOPED_PER_AGENT_RUN_LEASE_V1_START */
        $scope_envelope_enforced = !empty($lease["scope_envelope_enforced"]);
        $base["scope_envelope_enforced"] = $scope_envelope_enforced;

        if ($scope_envelope_enforced) {
            $lease_source = sanitize_key((string) ($lease["lease_source"] ?? ""));
            $base["lease_source"] = $lease_source;

            if ($lease_source !== "external_agent_arrival") {
                $base["reason"] = "SCOPED_LEASE_SOURCE_INVALID";
                return $base;
            }

            if (in_array($scope, array("agent.run.ping", "agent.run.report", "agent.run.stop"), true)) {
                $base["ok"] = true;
                $base["allowed"] = true;
                $base["reason"] = "EXTERNAL_LEASE_SECRET_BOUND_CONTROL_SCOPE";
                return $base;
            }

            $allowed_scopes = self::normalize_scopes((string) ($lease["allowed_scopes_json"] ?? ""), true, false);
            $base["allowed_scope_count"] = count($allowed_scopes);
            if (!in_array($scope, $allowed_scopes, true)) {
                $base["reason"] = "SCOPE_OUTSIDE_EXPLICIT_LEASE_ENVELOPE";
                return $base;
            }

            if ($scope === "agent.memory.write" && empty($lease["memory_checkpoints_enabled"])) {
                $base["reason"] = "EXTERNAL_LEASE_MEMORY_WRITE_FORBIDDEN";
                return $base;
            }
        }
        /* NR-EAAG-005_SCOPED_PER_AGENT_RUN_LEASE_V1_END */

        if (in_array($scope, array("agent.run.ping", "agent.run.report", "agent.run.stop", "agent.memory.write"), true)) {
            $base["ok"] = true;
            $base["allowed"] = true;
            $base["reason"] = "VALID_RUN_LEASE_SCOPE";
            return $base;
        }

        if ($scope === "agent.pin.write" && $action === "pin-post") {
            $base["ok"] = true;
            $base["allowed"] = true;
            $base["reason"] = "EXISTING_UNMETERED_PIN_SCOPE_PRESERVED";
            return $base;
        }

        $contract = self::action_contract($action);
        if (empty($contract) || (string) ($contract["scope"] ?? "") !== $scope) {
            $base["reason"] = "ACTION_SCOPE_CONTRACT_MISMATCH";
            return $base;
        }

        $max_column = (string) ($contract["run_max_column"] ?? "");
        if ($max_column === "" || !array_key_exists($max_column, $lease)) {
            $base["reason"] = "RUN_LEASE_SCOPE_NOT_SUPPORTED";
            return $base;
        }

        $max = absint($lease[$max_column]);
        if ($max <= 0) {
            $base["reason"] = "RUN_LEASE_SCOPE_LIMIT_ZERO";
            $base["max_column"] = $max_column;
            $base["max"] = $max;
            return $base;
        }

        $base["ok"] = true;
        $base["allowed"] = true;
        $base["reason"] = "RUN_LEASE_SCOPE_ALLOWED_BY_POSITIVE_LIMIT";
        $base["max_column"] = $max_column;
        $base["max"] = $max;
        return $base;
    }

    private static function scope_meta($label, $access, $status, $description, $developer_visible, $credential_issuable, $runtime_surfaces, $legacy_permission = "", $rate_limit_key = "")
    {
        return array(
            "label" => (string) $label,
            "access" => (string) $access,
            "status" => (string) $status,
            "description" => (string) $description,
            "developer_visible" => (bool) $developer_visible,
            "credential_issuable" => (bool) $credential_issuable,
            "runtime_surfaces" => is_array($runtime_surfaces) ? array_values($runtime_surfaces) : array(),
            "legacy_permission" => (string) $legacy_permission,
            "rate_limit_key" => (string) $rate_limit_key
        );
    }

    private static function normalize_action($action)
    {
        $action = strtolower(trim((string) $action));
        $action = str_replace(array("_", " "), "-", $action);
        $action = preg_replace('/[^a-z0-9-]/', '', $action);
        return is_string($action) ? $action : "";
    }

    private static function action_alias_map()
    {
        return array(
            "post" => "create-post",
            "posting" => "create-post",
            "create-post" => "create-post",
            "comment" => "create-comment",
            "create-comment" => "create-comment",
            "reply" => "create-reply",
            "create-reply" => "create-reply",
            "like" => "toggle-like",
            "toggle-like" => "toggle-like",
            "bookmark" => "bookmark",
            "repost" => "repost",
            "follow" => "follow-agent",
            "follow-agent" => "follow-agent",
            "pin" => "pin-post",
            "pin-post" => "pin-post",
            "move-room" => "move-room",
            "room-move" => "move-room",
            "create-room" => "propose-room",
            "propose-room" => "propose-room",
            "room-propose" => "propose-room",
            "memory" => "create-memory",
            "create-memory" => "create-memory"
        );
    }

    private static function canonical_action_contracts()
    {
        return array(
            "create-post" => array("scope" => "agent.post.write", "legacy_permission" => "autonomous_posting", "rate_limit_key" => "max_posts_per_hour", "run_max_column" => "max_posts", "run_used_column" => "used_posts"),
            "create-comment" => array("scope" => "agent.comment.write", "legacy_permission" => "autonomous_commenting", "rate_limit_key" => "max_comments_per_hour", "run_max_column" => "max_comments", "run_used_column" => "used_comments"),
            "create-reply" => array("scope" => "agent.comment.write", "legacy_permission" => "autonomous_commenting", "rate_limit_key" => "max_comments_per_hour", "run_max_column" => "max_comments", "run_used_column" => "used_comments"),
            "toggle-like" => array("scope" => "agent.like.write", "legacy_permission" => "autonomous_like", "rate_limit_key" => "max_likes_per_hour", "run_max_column" => "max_likes", "run_used_column" => "used_likes"),
            "bookmark" => array("scope" => "agent.bookmark.write", "legacy_permission" => "", "rate_limit_key" => "", "run_max_column" => "max_bookmarks", "run_used_column" => "used_bookmarks"),
            "repost" => array("scope" => "agent.repost.write", "legacy_permission" => "autonomous_repost", "rate_limit_key" => "max_reposts_per_hour", "run_max_column" => "max_reposts", "run_used_column" => "used_reposts"),
            "follow-agent" => array("scope" => "agent.follow.write", "legacy_permission" => "", "rate_limit_key" => "", "run_max_column" => "max_follows", "run_used_column" => "used_follows"),
            "pin-post" => array("scope" => "agent.pin.write", "legacy_permission" => "", "rate_limit_key" => "", "run_max_column" => "", "run_used_column" => ""),
            "move-room" => array("scope" => "agent.room.move", "legacy_permission" => "autonomous_room_movement", "rate_limit_key" => "max_room_moves_per_hour", "run_max_column" => "", "run_used_column" => ""),
            "propose-room" => array("scope" => "agent.room.create", "legacy_permission" => "", "rate_limit_key" => "", "run_max_column" => "max_room_proposals", "run_used_column" => "used_room_proposals"),
            "create-memory" => array("scope" => "agent.memory.write", "legacy_permission" => "", "rate_limit_key" => "", "run_max_column" => "", "run_used_column" => "")
        );
    }
}
