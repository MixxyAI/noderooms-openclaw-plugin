<?php
if (!defined("ABSPATH")) {
    exit;
}

/**
 * NodeRooms-owned connector control plane.
 *
 * Owners use only the NodeRooms dashboard. Provider refresh tokens never enter
 * WordPress: an authenticated background worker stores them in an Agent-
 * isolated encrypted keyring and polls this class for signed, one-use jobs.
 */
class AGO_TrustBridge_Connectors
{
    const VERSION = "1.4.0-alpha.6-dev.2";
    const SCHEMA_VERSION = "3";
    const SCHEMA_OPTION = "ago_trustbridge_connectors_schema_version";
    const REST_NAMESPACE = "agent-guild-os/v1";
    const JOB_CONTRACT = "noderooms-trustbridge-job.v2";
    const WORKER_CONTRACT = "noderooms-trustbridge-worker.v2";
    const REQUIRED_WORKER_VERSION = "1.4.0-alpha.6-dev.2";
    const PAIR_CONTRACT = "noderooms-gmail-worker-pair.v1";
    const AUTHORITY_CONTRACT = "noderooms-connector-job-authority.v1";
    const CALLBACK_URI = "https://noderooms.com/wp-json/agent-guild-os/v1/trustbridge/gmail/oauth/callback";
    const RUNTIME_ENABLED_CONSTANT = "NODEROOMS_TRUSTBRIDGE_RUNTIME_ENABLED";
    const STORAGE_KEY_CONSTANT = "NODEROOMS_TRUSTBRIDGE_STORAGE_KEY";
    const RECEIPT_KEY_CONSTANT = "NODEROOMS_TRUSTBRIDGE_RECEIPT_KEY";
    const OWNER_NONCE_ACTION_PREFIX = "noderooms_trustbridge_owner_";
    const PAIRING_CLI_APPROVED_CONSTANT = "NODEROOMS_TRUSTBRIDGE_PAIRING_CLI_APPROVED";
    const WORKER_CLOCK_SKEW_SECONDS = 300;
    const OAUTH_JOB_TTL_SECONDS = 900;
    const READ_JOB_TTL_SECONDS = 300;
    const WRITE_JOB_TTL_SECONDS = 300;
    const CAPABILITY_TTL_SECONDS = 2592000;
    const CLAIM_LEASE_TTL_SECONDS = 180;
    const MAX_RESULT_BYTES = 2097152;
    const MAX_WORKER_REQUEST_BYTES = 2162688;

    private static $allowed_agent_scopes = array(
        "connector.gmail.message.search",
        "connector.gmail.thread.read",
        "connector.gmail.draft.create",
    );

    private static $supported_worker_jobs = array(
        "gmail_oauth_start",
        "gmail_oauth_complete",
        "gmail_search",
        "gmail_thread_read",
        "gmail_draft_create",
        "gmail_send_approved_draft",
        "gmail_disconnect",
    );

    public static function init()
    {
        add_action("rest_api_init", array(__CLASS__, "register_routes"));
    }

    public static function activate()
    {
        return;
    }

    public static function migrate_schema_for_cli()
    {
        if (!self::migration_cli_approved()) {
            return false;
        }
        self::install_schema();
        return self::schema_is_ready();
    }

    public static function rollback_empty_schema_for_cli()
    {
        if (!self::migration_cli_approved()) {
            return false;
        }

        global $wpdb;
        $tables = self::schema_tables();
        foreach ($tables as $table) {
            if (self::table_exists($table) && absint($wpdb->get_var("SELECT COUNT(*) FROM {$table}")) !== 0) {
                return false;
            }
        }
        foreach (array_reverse($tables) as $table) {
            if (self::table_exists($table) && $wpdb->query("DROP TABLE {$table}") === false) {
                return false;
            }
        }
        delete_option(self::SCHEMA_OPTION);
        return !self::any_schema_table_exists();
    }

    public static function register_routes()
    {
        register_rest_route(self::REST_NAMESPACE, "/owner/connectors/gmail/status", array(
            "methods" => "GET",
            "callback" => array(__CLASS__, "owner_status"),
            "permission_callback" => "__return_true",
        ));

        register_rest_route(self::REST_NAMESPACE, "/owner/connectors/gmail/connect/start", array(
            "methods" => "POST",
            "callback" => array(__CLASS__, "owner_connect_start"),
            "permission_callback" => "__return_true",
        ));

        register_rest_route(self::REST_NAMESPACE, "/owner/connectors/gmail/capabilities", array(
            "methods" => "POST",
            "callback" => array(__CLASS__, "owner_capabilities"),
            "permission_callback" => "__return_true",
        ));

        register_rest_route(self::REST_NAMESPACE, "/owner/connectors/gmail/jobs", array(
            "methods" => "POST",
            "callback" => array(__CLASS__, "owner_job_create"),
            "permission_callback" => "__return_true",
        ));

        register_rest_route(self::REST_NAMESPACE, "/owner/connectors/gmail/jobs/(?P<job_id>nrtbj_[a-f0-9]{32})", array(
            "methods" => "GET",
            "callback" => array(__CLASS__, "owner_job_status"),
            "permission_callback" => "__return_true",
        ));

        register_rest_route(self::REST_NAMESPACE, "/owner/connectors/gmail/revoke", array(
            "methods" => "POST",
            "callback" => array(__CLASS__, "owner_revoke"),
            "permission_callback" => "__return_true",
        ));

        register_rest_route(self::REST_NAMESPACE, "/trustbridge/gmail/oauth/callback", array(
            "methods" => "GET",
            "callback" => array(__CLASS__, "gmail_oauth_callback"),
            "permission_callback" => "__return_true",
        ));

        register_rest_route(self::REST_NAMESPACE, "/trustbridge/worker/pairing/complete", array(
            "methods" => "POST",
            "callback" => array(__CLASS__, "worker_pairing_complete"),
            "permission_callback" => "__return_true",
        ));

        register_rest_route(self::REST_NAMESPACE, "/trustbridge/worker/jobs/claim", array(
            "methods" => "POST",
            "callback" => array(__CLASS__, "worker_claim"),
            "permission_callback" => "__return_true",
        ));

        register_rest_route(self::REST_NAMESPACE, "/trustbridge/worker/jobs/(?P<job_id>nrtbj_[a-f0-9]{32})/complete", array(
            "methods" => "POST",
            "callback" => array(__CLASS__, "worker_complete"),
            "permission_callback" => "__return_true",
        ));
    }

    public static function owner_dashboard_bootstrap()
    {
        $runtime = self::runtime_guard();
        if (empty($runtime["ok"])) {
            return array(
                "active" => false,
                "status" => (string) ($runtime["reason"] ?? "GMAIL_TRUSTBRIDGE_NOT_READY"),
            );
        }
        $owner = self::current_owner_context();
        if (empty($owner["ok"])) {
            return array(
                "active" => false,
                "status" => (string) ($owner["reason"] ?? "OWNER_SESSION_REQUIRED"),
            );
        }
        $worker = self::active_worker_for_agent($owner);
        if (!$worker
            || (string) ($worker["passport_public_id"] ?? "") !== (string) ($owner["passport_public_id"] ?? "")
            || !hash_equals((string) ($worker["owner_binding_sha256"] ?? ""), (string) ($owner["owner_binding_sha256"] ?? ""))) {
            return array(
                "active" => false,
                "status" => "GMAIL_BACKGROUND_INFRASTRUCTURE_NOT_READY",
            );
        }

        return array(
            "active" => true,
            "agent_id" => absint($owner["agent_id"] ?? 0),
            "agent_slug" => sanitize_title((string) ($owner["agent_slug"] ?? "")),
            "agent_name" => sanitize_text_field((string) ($owner["agent_name"] ?? "")),
            "passport_public_id" => sanitize_text_field((string) ($owner["passport_public_id"] ?? "")),
            "owner_nonce" => wp_create_nonce(self::OWNER_NONCE_ACTION_PREFIX . (string) $owner["owner_binding_sha256"]),
            "status" => "NODEROOMS_TRUSTBRIDGE_OWNER_READY",
        );
    }

    public static function owner_status($request)
    {
        $owner = self::owner_guard($request);
        if (empty($owner["ok"])) {
            return self::rest_blocked($owner);
        }

        $connection = self::latest_connection_for_owner($owner);
        if (is_array($connection)
            && !in_array((string) ($connection["status"] ?? ""), array("FAILED", "REVOKED_ACCESS_BLOCKED", "REVOKED"), true)
            && (string) ($connection["passport_public_id"] ?? "") !== (string) ($owner["passport_public_id"] ?? "")) {
            return self::blocked_response("GMAIL_CONNECTION_PASSPORT_DRIFT", 403);
        }
        return rest_ensure_response(array(
            "ok" => true,
            "connector" => "gmail",
            "product_surface" => "noderooms",
            "agent" => self::public_agent($owner),
            "connection" => $connection ? self::public_connection($connection, true) : null,
            "capability_catalog" => self::gmail_capability_catalog(),
            "drafts_live" => true,
            "owner_approved_send_live" => true,
            "direct_send_live" => false,
            "delete_allowed" => false,
            "provider_token_stored_by_noderooms" => false,
            "status" => $connection ? "NODEROOMS_GMAIL_CONNECTION_STATUS_READY" : "NODEROOMS_GMAIL_NOT_CONNECTED",
        ));
    }

    public static function owner_connect_start($request)
    {
        $owner = self::owner_guard($request);
        if (empty($owner["ok"])) {
            return self::rest_blocked($owner);
        }

        $account_email = self::normalize_email(self::request_string($request, "account_email"));
        if ($account_email === "") {
            return self::blocked_response("GMAIL_ACCOUNT_EMAIL_REQUIRED", 400);
        }

        $passport = self::passport_guard($owner, "trustbridge_gmail_connect_start");
        if (empty($passport["ok"])) {
            return self::rest_blocked($passport);
        }
        $worker = self::active_worker_for_agent($owner);
        if (!$worker
            || (string) $worker["passport_public_id"] !== (string) $passport["passport_public_id"]
            || !hash_equals((string) $worker["owner_binding_sha256"], (string) $owner["owner_binding_sha256"])) {
            return self::blocked_response("GMAIL_BACKGROUND_INFRASTRUCTURE_NOT_READY", 503);
        }
        $existing_connection = self::latest_connection_for_owner($owner);
        if (is_array($existing_connection)
            && !in_array((string) ($existing_connection["status"] ?? ""), array("FAILED", "REVOKED_ACCESS_BLOCKED", "REVOKED"), true)
            && (string) ($existing_connection["passport_public_id"] ?? "") !== (string) ($passport["passport_public_id"] ?? "")) {
            return self::blocked_response("GMAIL_CONNECTION_PASSPORT_DRIFT", 403);
        }
        if (is_array($existing_connection)
            && in_array((string) ($existing_connection["status"] ?? ""), array(
                "QUEUED_OAUTH_START", "AWAITING_OWNER_CONSENT",
                "OAUTH_CALLBACK_RECEIVED", "CONNECTED_READ_COMPOSE",
            ), true)) {
            return self::blocked_response("GMAIL_CONNECTION_ALREADY_ACTIVE_OR_PENDING", 409);
        }

        $sealed_email = self::seal($account_email);
        if ($sealed_email === "") {
            return self::blocked_response("TRUSTBRIDGE_STORAGE_ENCRYPTION_REQUIRED", 503);
        }

        global $wpdb;
        $now = current_time("mysql", true);
        $connection_id = self::public_id("nrtbc_");
        $inserted = $wpdb->insert(self::connections_table(), array(
            "connection_public_id" => $connection_id,
            "provider" => "gmail",
            "owner_binding_sha256" => (string) $owner["owner_binding_sha256"],
            "owner_user_id" => absint($owner["owner_user_id"] ?? 0),
            "owner_session_type" => sanitize_key((string) $owner["owner_session_type"]),
            "verification_id" => absint($owner["verification_id"] ?? 0),
            "agent_id" => absint($owner["agent_id"]),
            "agent_slug" => sanitize_title((string) $owner["agent_slug"]),
            "passport_public_id" => sanitize_text_field((string) $passport["passport_public_id"]),
            "account_email_ciphertext" => $sealed_email,
            "account_email_sha256" => self::fingerprint($account_email),
            "account_email_masked" => self::mask_email($account_email),
            "status" => "QUEUED_OAUTH_START",
            "capabilities_json" => "[]",
            "created_at" => $now,
            "updated_at" => $now,
        ));

        if ($inserted !== 1) {
            return self::blocked_response("GMAIL_CONNECTION_CREATE_FAILED", 500);
        }

        $connection = self::connection_by_public_id($connection_id);
        $job = self::create_job($connection, "gmail_oauth_start", array(
            "account_email" => $account_email,
            "callback_uri" => self::CALLBACK_URI,
            "oauth_scopes" => self::gmail_oauth_scopes(),
        ), self::OAUTH_JOB_TTL_SECONDS);

        if (empty($job["ok"])) {
            $wpdb->update(self::connections_table(), array(
                "status" => "FAILED",
                "last_error_code" => sanitize_key((string) ($job["reason"] ?? "OAUTH_START_JOB_CREATE_FAILED")),
                "updated_at" => current_time("mysql", true),
            ), array("connection_public_id" => $connection_id));
            return self::rest_blocked($job);
        }

        return rest_ensure_response(array(
            "ok" => true,
            "connector" => "gmail",
            "product_flow" => "noderooms_owner_connects_gmail_for_passport_agent",
            "connection" => self::public_connection(self::connection_by_public_id($connection_id), false),
            "job" => self::public_job(self::job_by_public_id((string) $job["job_id"]), false),
            "next_step" => "NodeRooms is preparing the Google consent link.",
            "provider_token_stored_by_noderooms" => false,
            "status" => "NODEROOMS_GMAIL_CONNECT_QUEUED",
        ));
    }

    public static function owner_capabilities($request)
    {
        $owner = self::owner_guard($request);
        if (empty($owner["ok"])) {
            return self::rest_blocked($owner);
        }

        $connection = self::owner_connection_from_request($request, $owner);
        if (empty($connection["ok"])) {
            return self::rest_blocked($connection);
        }
        $record = $connection["connection"];
        if ((string) $record["status"] !== "CONNECTED_READ_COMPOSE") {
            return self::blocked_response("GMAIL_CONNECTION_NOT_READY", 409);
        }

        $passport = self::passport_guard($owner, "trustbridge_gmail_capability_grant");
        if (empty($passport["ok"])) {
            return self::rest_blocked($passport);
        }
        if ((string) $passport["passport_public_id"] !== (string) $record["passport_public_id"]) {
            return self::blocked_response("GMAIL_CONNECTION_PASSPORT_DRIFT", 403);
        }

        $body = self::request_json($request);
        $requested = isset($body["scopes"]) && is_array($body["scopes"]) ? $body["scopes"] : array();
        $scopes = array();
        foreach ($requested as $scope) {
            $scope = strtolower(trim((string) $scope));
            if (!in_array($scope, self::$allowed_agent_scopes, true)) {
                return self::blocked_response("GMAIL_CAPABILITY_SCOPE_NOT_ALLOWED", 400);
            }
            if (!in_array($scope, $scopes, true)) {
                $scopes[] = $scope;
            }
        }
        sort($scopes, SORT_STRING);

        $purpose = trim(self::request_string($request, "purpose"));
        if ($purpose === "" || strlen($purpose) > 500) {
            return self::blocked_response("GMAIL_CAPABILITY_PURPOSE_REQUIRED", 400);
        }
        $capability_bundle_id = self::public_id("nrtbcap_");
        $capability_expires_at = gmdate("Y-m-d H:i:s", time() + self::CAPABILITY_TTL_SECONDS);

        global $wpdb;
        $updated = $wpdb->update(self::connections_table(), array(
            "capabilities_json" => wp_json_encode($scopes),
            "capabilities_granted_at" => current_time("mysql", true),
            "capability_bundle_public_id" => $capability_bundle_id,
            "capability_purpose" => $purpose,
            "capability_purpose_sha256" => self::fingerprint($purpose),
            "capability_expires_at" => $capability_expires_at,
            "updated_at" => current_time("mysql", true),
        ), array("id" => absint($record["id"])));
        if ($updated === false) {
            return self::blocked_response("GMAIL_CAPABILITY_SAVE_FAILED", 500);
        }

        return rest_ensure_response(array(
            "ok" => true,
            "connector" => "gmail",
            "agent" => self::public_agent($owner),
            "connection_id" => (string) $record["connection_public_id"],
            "granted_scopes" => $scopes,
            "capability_bundle_id" => $capability_bundle_id,
            "purpose_bound" => true,
            "expires_at" => self::mysql_to_iso($capability_expires_at),
            "draft_creation_granted" => in_array("connector.gmail.draft.create", $scopes, true),
            "send_requires_exact_allow_once" => true,
            "direct_send_granted" => false,
            "delete_allowed" => false,
            "status" => "NODEROOMS_GMAIL_AGENT_CAPABILITIES_SAVED",
        ));
    }

    public static function owner_job_create($request)
    {
        $owner = self::owner_guard($request);
        if (empty($owner["ok"])) {
            return self::rest_blocked($owner);
        }
        $connection = self::owner_connection_from_request($request, $owner);
        if (empty($connection["ok"])) {
            return self::rest_blocked($connection);
        }
        $record = $connection["connection"];
        if ((string) $record["status"] !== "CONNECTED_READ_COMPOSE") {
            return self::blocked_response("GMAIL_CONNECTION_NOT_READY", 409);
        }

        $passport = self::passport_guard($owner, "trustbridge_gmail_job_create");
        if (empty($passport["ok"])) {
            return self::rest_blocked($passport);
        }
        if ((string) $passport["passport_public_id"] !== (string) $record["passport_public_id"]) {
            return self::blocked_response("GMAIL_CONNECTION_PASSPORT_DRIFT", 403);
        }

        $action = sanitize_key(self::request_string($request, "action"));
        $capabilities = self::decode_string_array((string) ($record["capabilities_json"] ?? "[]"));
        $capability_expires_at = strtotime((string) ($record["capability_expires_at"] ?? "") . " UTC");
        $capability_purpose = trim((string) ($record["capability_purpose"] ?? ""));
        $account_email = self::normalize_email(self::open((string) $record["account_email_ciphertext"]));
        if ($account_email === "") {
            return self::blocked_response("GMAIL_ACCOUNT_BINDING_UNAVAILABLE", 503);
        }
        if ($action !== "send_approved_draft"
            && (empty($record["capability_bundle_public_id"])
                || $capability_purpose === ""
                || $capability_expires_at === false
                || $capability_expires_at <= time())) {
            return self::blocked_response("GMAIL_PURPOSE_BOUND_CAPABILITY_REQUIRED", 403);
        }

        if ($action === "search") {
            $scope = "connector.gmail.message.search";
            if (!in_array($scope, $capabilities, true)) {
                return self::blocked_response("GMAIL_SEARCH_CAPABILITY_REQUIRED", 403);
            }
            $query = trim(self::request_string($request, "query"));
            if ($query === "" || strlen($query) > 500) {
                return self::blocked_response("GMAIL_SEARCH_QUERY_INVALID", 400);
            }
            $max_results = absint(self::request_value($request, "max_results", 10));
            $max_results = max(1, min(10, $max_results));
            $job = self::create_job($record, "gmail_search", array(
                "account_email" => $account_email,
                "query" => $query,
                "max_results" => $max_results,
            ), self::READ_JOB_TTL_SECONDS);
        } elseif ($action === "thread_read") {
            $scope = "connector.gmail.thread.read";
            if (!in_array($scope, $capabilities, true)) {
                return self::blocked_response("GMAIL_THREAD_READ_CAPABILITY_REQUIRED", 403);
            }
            $thread_id = trim(self::request_string($request, "thread_id"));
            if (!preg_match('/^[A-Za-z0-9_-]{1,256}$/', $thread_id)) {
                return self::blocked_response("GMAIL_THREAD_ID_INVALID", 400);
            }
            $job = self::create_job($record, "gmail_thread_read", array(
                "account_email" => $account_email,
                "thread_id" => $thread_id,
            ), self::READ_JOB_TTL_SECONDS);
        } elseif ($action === "draft_create") {
            $scope = "connector.gmail.draft.create";
            if (!in_array($scope, $capabilities, true)) {
                return self::blocked_response("GMAIL_DRAFT_CAPABILITY_REQUIRED", 403);
            }
            $body = self::request_json($request);
            $to = self::normalize_email(isset($body["to"]) && is_string($body["to"]) ? $body["to"] : "");
            $subject = isset($body["subject"]) && is_string($body["subject"]) ? trim($body["subject"]) : "";
            $message_body = isset($body["body"]) && is_string($body["body"]) ? $body["body"] : "";
            $reply_message_id = isset($body["reply_message_id"]) && is_string($body["reply_message_id"])
                ? trim($body["reply_message_id"])
                : "";
            if ($to === "" || $subject === "" || strlen($subject) > 998 || preg_match('/[\r\n\x00]/', $subject)
                || $message_body === "" || strlen($message_body) > 50000 || strpos($message_body, "\0") !== false
                || ($reply_message_id !== "" && !preg_match('/^[A-Za-z0-9_-]{1,256}$/', $reply_message_id))) {
                return self::blocked_response("GMAIL_DRAFT_INPUT_INVALID", 400);
            }
            $payload = array(
                "account_email" => $account_email,
                "to" => $to,
                "subject" => $subject,
                "body" => $message_body,
            );
            if ($reply_message_id !== "") {
                $payload["reply_message_id"] = $reply_message_id;
            }
            $job = self::create_job($record, "gmail_draft_create", $payload, self::WRITE_JOB_TTL_SECONDS);
        } elseif ($action === "send_approved_draft") {
            $body = self::request_json($request);
            $draft_id = isset($body["draft_id"]) && is_string($body["draft_id"]) ? trim($body["draft_id"]) : "";
            $approval_policy = isset($body["approval_policy"]) && is_string($body["approval_policy"])
                ? sanitize_key($body["approval_policy"])
                : "";
            $confirm_exact_draft = array_key_exists("confirm_exact_draft", $body) && $body["confirm_exact_draft"] === true;
            $send_purpose = isset($body["purpose"]) && is_string($body["purpose"]) ? trim($body["purpose"]) : "";
            if (!preg_match('/^[A-Za-z0-9_-]{1,256}$/', $draft_id)
                || $approval_policy !== "allow_once"
                || !$confirm_exact_draft
                || $send_purpose === ""
                || strlen($send_purpose) > 500) {
                return self::blocked_response("GMAIL_EXACT_DRAFT_OWNER_APPROVAL_REQUIRED", 403);
            }
            if (!self::owner_has_exact_unsent_draft($record, $draft_id)) {
                return self::blocked_response("GMAIL_APPROVED_DRAFT_NOT_FOUND", 404);
            }
            $job = self::create_job(
                $record,
                "gmail_send_approved_draft",
                array(
                    "account_email" => $account_email,
                    "draft_id" => $draft_id,
                ),
                self::WRITE_JOB_TTL_SECONDS,
                array(
                    "policy" => "allow_once",
                    "decision_source" => "verified_human_owner",
                    "automated" => false,
                    "owner_binding_id" => (string) $owner["owner_binding_sha256"],
                    "purpose" => $send_purpose,
                    "draft_id" => $draft_id,
                )
            );
        } else {
            return self::blocked_response("GMAIL_ACTION_NOT_ALLOWED", 400);
        }

        if (empty($job["ok"])) {
            return self::rest_blocked($job);
        }

        return rest_ensure_response(array(
            "ok" => true,
            "connector" => "gmail",
            "agent" => self::public_agent($owner),
            "job" => self::public_job(self::job_by_public_id((string) $job["job_id"]), false),
            "one_action_run_lease" => true,
            "mailbox_write_performed" => false,
            "provider_attempt_max" => in_array($action, array("draft_create", "send_approved_draft"), true) ? 1 : 0,
            "automatic_retry_allowed" => false,
            "status" => "NODEROOMS_GMAIL_JOB_QUEUED",
        ));
    }

    public static function owner_job_status($request)
    {
        $owner = self::owner_guard($request);
        if (empty($owner["ok"])) {
            return self::rest_blocked($owner);
        }
        $job_id = sanitize_text_field((string) $request->get_param("job_id"));
        $job = self::job_by_public_id($job_id);
        if (!$job || !self::row_matches_owner($job, $owner)) {
            return self::blocked_response("GMAIL_JOB_NOT_FOUND", 404);
        }
        return rest_ensure_response(array(
            "ok" => true,
            "connector" => "gmail",
            "job" => self::public_job($job, true),
            "provider_token_exposed" => false,
            "status" => "NODEROOMS_GMAIL_JOB_STATUS_READY",
        ));
    }

    public static function owner_revoke($request)
    {
        $owner = self::owner_guard($request);
        if (empty($owner["ok"])) {
            return self::rest_blocked($owner);
        }
        $connection = self::owner_connection_from_request($request, $owner);
        if (empty($connection["ok"])) {
            return self::rest_blocked($connection);
        }
        $record = $connection["connection"];
        if (in_array((string) $record["status"], array("REVOKE_QUEUED", "REVOKED_ACCESS_BLOCKED", "REVOKED"), true)) {
            return rest_ensure_response(array(
                "ok" => true,
                "connector" => "gmail",
                "connection_id" => (string) $record["connection_public_id"],
                "agent_access_revoked_immediately" => true,
                "provider_keyring_cleanup_queued" => (string) $record["status"] === "REVOKE_QUEUED",
                "granted_scopes" => array(),
                "status" => "NODEROOMS_GMAIL_ACCESS_ALREADY_REVOKED",
            ));
        }
        $account_email = self::normalize_email(self::open((string) $record["account_email_ciphertext"]));
        if ($account_email === "") {
            return self::blocked_response("GMAIL_ACCOUNT_BINDING_UNAVAILABLE", 503);
        }

        global $wpdb;
        if ($wpdb->query("START TRANSACTION") === false) {
            return self::blocked_response("GMAIL_REVOKE_TRANSACTION_START_FAILED", 503);
        }
        $updated = $wpdb->update(self::connections_table(), array(
            "status" => "REVOKE_QUEUED",
            "capabilities_json" => "[]",
            "capability_bundle_public_id" => null,
            "capability_purpose" => null,
            "capability_purpose_sha256" => null,
            "capability_expires_at" => null,
            "oauth_state_sha256" => null,
            "oauth_state_expires_at" => null,
            "authorization_url_ciphertext" => null,
            "revoked_at" => current_time("mysql", true),
            "updated_at" => current_time("mysql", true),
        ), array("id" => absint($record["id"]), "status" => (string) $record["status"]));
        if ($updated !== 1) {
            $wpdb->query("ROLLBACK");
            return self::blocked_response("GMAIL_REVOKE_CONNECTION_UPDATE_FAILED", 409);
        }
        $revoked_jobs = $wpdb->query($wpdb->prepare(
            "UPDATE " . self::jobs_table() . " SET status = 'REVOKED', completed_at = %s, error_code = 'CONNECTION_REVOKED', updated_at = %s WHERE connection_id = %d AND status = 'PENDING'",
            current_time("mysql", true),
            current_time("mysql", true),
            absint($record["id"])
        ));
        if ($revoked_jobs === false) {
            $wpdb->query("ROLLBACK");
            return self::blocked_response("GMAIL_REVOKE_PENDING_JOBS_FAILED", 503);
        }

        $record = self::connection_by_public_id((string) $record["connection_public_id"]);
        if (!is_array($record)) {
            $wpdb->query("ROLLBACK");
            return self::blocked_response("GMAIL_REVOKE_CONNECTION_RELOAD_FAILED", 503);
        }
        $job = self::create_job($record, "gmail_disconnect", array(
            "account_email" => $account_email,
        ), self::OAUTH_JOB_TTL_SECONDS);
        if (empty($job["ok"])) {
            $fallback = $wpdb->update(self::connections_table(), array(
                "status" => "REVOKED_ACCESS_BLOCKED",
                "revoked_at" => current_time("mysql", true),
                "last_error_code" => "KEYRING_CLEANUP_JOB_NOT_CREATED",
                "updated_at" => current_time("mysql", true),
            ), array("id" => absint($record["id"]), "status" => "REVOKE_QUEUED"));
            if ($fallback !== 1) {
                $wpdb->query("ROLLBACK");
                return self::blocked_response("GMAIL_REVOKE_FALLBACK_STATE_FAILED", 503);
            }
        }
        if ($wpdb->query("COMMIT") === false) {
            $wpdb->query("ROLLBACK");
            return self::blocked_response("GMAIL_REVOKE_ATOMIC_COMMIT_FAILED", 503);
        }

        return rest_ensure_response(array(
            "ok" => true,
            "connector" => "gmail",
            "connection_id" => (string) $record["connection_public_id"],
            "agent_access_revoked_immediately" => true,
            "provider_keyring_cleanup_queued" => !empty($job["ok"]),
            "granted_scopes" => array(),
            "status" => "NODEROOMS_GMAIL_ACCESS_REVOKED",
        ));
    }

    public static function gmail_oauth_callback($request)
    {
        $runtime = self::runtime_guard();
        if (empty($runtime["ok"])) {
            return self::oauth_redirect("connector_not_ready");
        }
        $state = trim(self::request_string($request, "state"));
        $code = trim(self::request_string($request, "code"));
        $provider_error = sanitize_key(self::request_string($request, "error"));
        if ($state === "" || strlen($state) > 2048) {
            return self::oauth_redirect("invalid_state");
        }

        global $wpdb;
        $connection = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM " . self::connections_table() . " WHERE oauth_state_sha256 = %s AND status = 'AWAITING_OWNER_CONSENT' LIMIT 1",
            hash("sha256", $state)
        ), ARRAY_A);
        if (!is_array($connection)) {
            return self::oauth_redirect("expired_or_replayed");
        }
        if (empty($connection["oauth_state_expires_at"]) || strtotime((string) $connection["oauth_state_expires_at"] . " UTC") <= time()) {
            $wpdb->update(self::connections_table(), array(
                "status" => "FAILED",
                "last_error_code" => "OAUTH_STATE_EXPIRED",
                "oauth_state_sha256" => null,
                "authorization_url_ciphertext" => null,
                "updated_at" => current_time("mysql", true),
            ), array("id" => absint($connection["id"])));
            return self::oauth_redirect("expired");
        }
        if ($provider_error !== "") {
            $wpdb->update(self::connections_table(), array(
                "status" => "FAILED",
                "last_error_code" => "GOOGLE_" . strtoupper($provider_error),
                "oauth_state_sha256" => null,
                "authorization_url_ciphertext" => null,
                "updated_at" => current_time("mysql", true),
            ), array("id" => absint($connection["id"])));
            return self::oauth_redirect("cancelled");
        }
        if ($code === "" || strlen($code) > 8192) {
            return self::oauth_redirect("code_missing");
        }

        $callback_url = self::CALLBACK_URI
            . "?state=" . rawurlencode($state)
            . "&code=" . rawurlencode($code);
        if (strlen($callback_url) > 16384) {
            return self::oauth_redirect("callback_too_large");
        }
        $account_email = self::normalize_email(self::open((string) $connection["account_email_ciphertext"]));
        if ($account_email === "") {
            return self::oauth_redirect("account_binding_unavailable");
        }

        if ($wpdb->query("START TRANSACTION") === false) {
            return self::oauth_redirect("storage_unavailable");
        }
        $updated = $wpdb->query($wpdb->prepare(
            "UPDATE " . self::connections_table() . " SET status = 'OAUTH_CALLBACK_RECEIVED', oauth_state_sha256 = NULL, authorization_url_ciphertext = NULL, updated_at = %s WHERE id = %d AND status = 'AWAITING_OWNER_CONSENT' AND oauth_state_sha256 = %s",
            current_time("mysql", true),
            absint($connection["id"]),
            hash("sha256", $state)
        ));
        if ($updated !== 1) {
            $wpdb->query("ROLLBACK");
            return self::oauth_redirect("expired_or_replayed");
        }

        $connection = self::connection_by_public_id((string) $connection["connection_public_id"]);
        $job = self::create_job($connection, "gmail_oauth_complete", array(
            "account_email" => $account_email,
            "callback_uri" => self::CALLBACK_URI,
            "callback_url" => $callback_url,
            "oauth_scopes" => self::gmail_oauth_scopes(),
        ), self::OAUTH_JOB_TTL_SECONDS);
        if (empty($job["ok"])) {
            $failed = $wpdb->update(self::connections_table(), array(
                "status" => "FAILED",
                "last_error_code" => "OAUTH_COMPLETE_JOB_CREATE_FAILED",
                "updated_at" => current_time("mysql", true),
            ), array("id" => absint($connection["id"]), "status" => "OAUTH_CALLBACK_RECEIVED"));
            if ($failed !== 1 || $wpdb->query("COMMIT") === false) {
                $wpdb->query("ROLLBACK");
                return self::oauth_redirect("storage_unavailable");
            }
            return self::oauth_redirect("completion_queue_failed");
        }
        if ($wpdb->query("COMMIT") === false) {
            $wpdb->query("ROLLBACK");
            return self::oauth_redirect("storage_unavailable");
        }
        return self::oauth_redirect("processing");
    }

    /**
     * Creates a one-use infrastructure pairing payload. This is deliberately
     * unavailable to browser users and is never rendered in the NodeRooms UI.
     */
    public static function provision_worker_pairing_for_infrastructure($agent_slug, $return_to = "")
    {
        if (PHP_SAPI !== "cli"
            || !defined("WP_CLI")
            || !WP_CLI
            || !defined(self::PAIRING_CLI_APPROVED_CONSTANT)
            || constant(self::PAIRING_CLI_APPROVED_CONSTANT) !== true) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_INFRASTRUCTURE_PAIRING_NOT_APPROVED");
        }
        if (!self::schema_is_ready() || !function_exists("sodium_crypto_sign_verify_detached")) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_PAIRING_RUNTIME_NOT_READY");
        }
        $binding = self::agent_binding_by_slug($agent_slug);
        if (empty($binding["ok"])) {
            return $binding;
        }
        $passport = self::passport_guard($binding, "trustbridge_worker_pairing");
        if (empty($passport["ok"])) {
            return $passport;
        }
        $binding["owner_binding_sha256"] = self::owner_binding_fingerprint($binding);
        $return_to = trim((string) $return_to);
        if ($return_to === "") {
            $return_to = home_url("/owner-dashboard/");
        }
        $return_parts = wp_parse_url($return_to);
        $site_parts = wp_parse_url(home_url("/"));
        if (!is_array($return_parts)
            || !is_array($site_parts)
            || strtolower((string) ($return_parts["scheme"] ?? "")) !== "https"
            || strtolower((string) ($return_parts["host"] ?? "")) !== strtolower((string) ($site_parts["host"] ?? ""))
            || isset($return_parts["user"])
            || isset($return_parts["pass"])) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_PAIRING_RETURN_URL_INVALID");
        }

        $challenge_id = self::public_id("nrtbp_");
        $challenge = self::base64url_encode(random_bytes(32));
        $expires_at = gmdate("Y-m-d H:i:s", time() + 600);
        global $wpdb;
        $inserted = $wpdb->insert(self::worker_pairings_table(), array(
            "pairing_public_id" => $challenge_id,
            "challenge_sha256" => self::fingerprint($challenge),
            "owner_binding_sha256" => (string) $binding["owner_binding_sha256"],
            "agent_id" => absint($binding["agent_id"]),
            "agent_slug" => sanitize_title((string) $binding["agent_slug"]),
            "passport_public_id" => sanitize_text_field((string) $passport["passport_public_id"]),
            "status" => "PENDING",
            "expires_at" => $expires_at,
            "created_at" => current_time("mysql", true),
        ));
        if ($inserted !== 1) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_PAIRING_CREATE_FAILED");
        }
        $payload = array(
            "contract_version" => self::PAIR_CONTRACT,
            "challenge_id" => $challenge_id,
            "challenge" => $challenge,
            "callback_url" => home_url("/wp-json/" . self::REST_NAMESPACE . "/trustbridge/worker/pairing/complete"),
            "site_origin" => untrailingslashit(home_url("/")),
            "agent_slug" => sanitize_title((string) $binding["agent_slug"]),
            "passport_public_id" => sanitize_text_field((string) $passport["passport_public_id"]),
            "expires_at" => gmdate("c", strtotime($expires_at . " UTC")),
            "return_to" => esc_url_raw($return_to),
        );
        $json = wp_json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_PAIRING_PAYLOAD_INVALID");
        }
        return array(
            "ok" => true,
            "pairing_url" => "http://127.0.0.1:45832/pair#" . self::base64url_encode($json),
            "challenge_id" => $challenge_id,
            "expires_at" => $payload["expires_at"],
            "user_visible" => false,
            "status" => "TRUSTBRIDGE_INFRASTRUCTURE_PAIRING_READY",
        );
    }

    public static function worker_pairing_complete($request)
    {
        $runtime = self::runtime_guard();
        if (empty($runtime["ok"])) {
            return self::rest_blocked($runtime);
        }
        $body = self::request_json($request);
        $challenge_id = sanitize_text_field((string) ($body["challenge_id"] ?? ""));
        $challenge = trim((string) ($body["challenge"] ?? ""));
        $worker_id = sanitize_text_field((string) ($body["worker_id"] ?? ""));
        $public_key_b64url = trim((string) ($body["public_key_b64url"] ?? ""));
        $infrastructure_agent_id = sanitize_text_field((string) ($body["openclaw_agent_id"] ?? ""));
        $worker_version = sanitize_text_field((string) ($body["worker_version"] ?? ""));
        $issued_at = absint($body["issued_at"] ?? 0);
        $signature_b64url = trim((string) ($body["signature_b64url"] ?? ""));
        $supported = isset($body["supported_job_types"]) && is_array($body["supported_job_types"])
            ? array_values(array_unique(array_map("sanitize_key", $body["supported_job_types"])))
            : array();
        sort($supported, SORT_STRING);
        $expected_supported = self::$supported_worker_jobs;
        sort($expected_supported, SORT_STRING);
        if ((string) ($body["contract_version"] ?? "") !== self::PAIR_CONTRACT
            || !preg_match('/^nrtbp_[a-f0-9]{32}$/', $challenge_id)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/', $challenge)
            || !preg_match('/^nrtbw_[a-f0-9]{32}$/', $worker_id)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/', $public_key_b64url)
            || !preg_match('/^[a-z0-9][a-z0-9_-]{0,63}$/', $infrastructure_agent_id)
            || $worker_version !== self::REQUIRED_WORKER_VERSION
            || abs(time() - $issued_at) > self::WORKER_CLOCK_SKEW_SECONDS
            || $supported !== $expected_supported) {
            return self::blocked_response("TRUSTBRIDGE_PAIRING_REQUEST_INVALID", 400);
        }
        $public_key = self::base64url_decode($public_key_b64url);
        $signature = self::base64url_decode($signature_b64url);
        if (!is_string($public_key) || strlen($public_key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            || !is_string($signature) || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return self::blocked_response("TRUSTBRIDGE_PAIRING_KEY_OR_SIGNATURE_INVALID", 400);
        }

        global $wpdb;
        $pairing = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM " . self::worker_pairings_table() . " WHERE pairing_public_id = %s LIMIT 1",
            $challenge_id
        ), ARRAY_A);
        if (!is_array($pairing)
            || !in_array((string) $pairing["status"], array("PENDING", "CONSUMED"), true)
            || strtotime((string) $pairing["expires_at"] . " UTC") <= time()
            || !hash_equals((string) $pairing["challenge_sha256"], self::fingerprint($challenge))) {
            return self::blocked_response("TRUSTBRIDGE_PAIRING_EXPIRED_OR_REPLAYED", 409);
        }
        $binding = self::agent_binding_by_slug((string) $pairing["agent_slug"]);
        if (empty($binding["ok"])
            || absint($binding["agent_id"] ?? 0) !== absint($pairing["agent_id"])
            || !hash_equals((string) $pairing["owner_binding_sha256"], self::owner_binding_fingerprint($binding))) {
            return self::blocked_response("TRUSTBRIDGE_PAIRING_OWNER_BINDING_INVALID", 403);
        }
        $passport = self::passport_guard($binding, "trustbridge_worker_pairing_complete");
        if (empty($passport["ok"]) || (string) $passport["passport_public_id"] !== (string) $pairing["passport_public_id"]) {
            return self::blocked_response("TRUSTBRIDGE_PAIRING_PASSPORT_INVALID", 403);
        }
        $canonical = implode("\n", array(
            self::PAIR_CONTRACT,
            $challenge_id,
            $challenge,
            $worker_id,
            $public_key_b64url,
            $infrastructure_agent_id,
            $worker_version,
            implode(",", $supported),
            (string) $issued_at,
        ));
        if (!sodium_crypto_sign_verify_detached($signature, $canonical, $public_key)) {
            return self::blocked_response("TRUSTBRIDGE_PAIRING_SIGNATURE_INVALID", 403);
        }

        if ((string) $pairing["status"] === "CONSUMED") {
            $existing_worker = self::worker_by_public_id($worker_id);
            if (!$existing_worker
                || (string) ($pairing["worker_public_id"] ?? "") !== $worker_id
                || (string) $existing_worker["public_key_b64url"] !== $public_key_b64url
                || (string) $existing_worker["agent_slug"] !== (string) $pairing["agent_slug"]
                || (string) $existing_worker["passport_public_id"] !== (string) $pairing["passport_public_id"]
                || (string) $existing_worker["status"] !== "ACTIVE") {
                return self::blocked_response("TRUSTBRIDGE_PAIRING_REPLAY_MISMATCH", 409);
            }
            return rest_ensure_response(array(
                "ok" => true,
                "worker_id" => $worker_id,
                "worker_binding_id" => (string) $existing_worker["worker_binding_public_id"],
                "agent" => array(
                    "slug" => (string) $pairing["agent_slug"],
                    "owner_binding_id" => (string) $pairing["owner_binding_sha256"],
                    "owner_binding_status" => "verified",
                    "passport_public_id" => (string) $pairing["passport_public_id"],
                    "passport_status" => "active",
                ),
                "status" => "TRUSTBRIDGE_WORKER_PAIRING_ALREADY_COMMITTED",
            ));
        }

        $worker_binding_id = self::public_id("nrtbwb_");
        if ($wpdb->query("START TRANSACTION") === false) {
            return self::blocked_response("TRUSTBRIDGE_PAIRING_TRANSACTION_FAILED", 503);
        }
        $wpdb->query($wpdb->prepare(
            "UPDATE " . self::workers_table() . " SET status = 'REVOKED', revoked_at = %s WHERE agent_id = %d AND status = 'ACTIVE'",
            current_time("mysql", true),
            absint($pairing["agent_id"])
        ));
        $inserted = $wpdb->insert(self::workers_table(), array(
            "worker_public_id" => $worker_id,
            "worker_binding_public_id" => $worker_binding_id,
            "public_key_b64url" => $public_key_b64url,
            "owner_binding_sha256" => (string) $pairing["owner_binding_sha256"],
            "agent_id" => absint($pairing["agent_id"]),
            "agent_slug" => (string) $pairing["agent_slug"],
            "passport_public_id" => (string) $pairing["passport_public_id"],
            "infrastructure_agent_id" => $infrastructure_agent_id,
            "worker_version" => $worker_version,
            "supported_job_types_json" => wp_json_encode($supported),
            "status" => "ACTIVE",
            "paired_at" => current_time("mysql", true),
        ));
        $consumed = $inserted === 1 ? $wpdb->update(self::worker_pairings_table(), array(
            "worker_public_id" => $worker_id,
            "status" => "CONSUMED",
            "consumed_at" => current_time("mysql", true),
        ), array("id" => absint($pairing["id"]), "status" => "PENDING")) : false;
        if ($inserted !== 1 || $consumed !== 1 || $wpdb->query("COMMIT") === false) {
            $wpdb->query("ROLLBACK");
            return self::blocked_response("TRUSTBRIDGE_PAIRING_ATOMIC_COMMIT_FAILED", 503);
        }
        return rest_ensure_response(array(
            "ok" => true,
            "worker_id" => $worker_id,
            "worker_binding_id" => $worker_binding_id,
            "agent" => array(
                "slug" => (string) $pairing["agent_slug"],
                "owner_binding_id" => (string) $pairing["owner_binding_sha256"],
                "owner_binding_status" => "verified",
                "passport_public_id" => (string) $pairing["passport_public_id"],
                "passport_status" => "active",
            ),
            "status" => "TRUSTBRIDGE_WORKER_PAIRED",
        ));
    }

    public static function worker_claim($request)
    {
        $worker = self::worker_guard($request);
        if (empty($worker["ok"])) {
            return self::rest_blocked($worker);
        }
        $body = self::request_json($request);
        if ((string) ($body["contract_version"] ?? "") !== self::WORKER_CONTRACT) {
            return self::blocked_response("WORKER_CONTRACT_MISMATCH", 409);
        }
        $supported = isset($body["supported_job_types"]) && is_array($body["supported_job_types"])
            ? array_values(array_intersect(self::$supported_worker_jobs, array_map("sanitize_key", $body["supported_job_types"])))
            : array();
        if (empty($supported)) {
            return self::blocked_response("WORKER_SUPPORTED_JOB_TYPES_REQUIRED", 400);
        }
        sort($supported, SORT_STRING);
        $stored_supported = self::decode_string_array((string) (self::worker_by_public_id((string) $worker["worker_id"])["supported_job_types_json"] ?? "[]"));
        if ($supported !== $stored_supported
            || ($body["gmail_draft_enabled"] ?? null) !== true
            || ($body["gmail_owner_approved_send_enabled"] ?? null) !== true
            || ($body["gmail_direct_send_enabled"] ?? null) !== false
            || ($body["gmail_delete_enabled"] ?? null) !== false
            || absint($body["max_jobs"] ?? 0) !== 1) {
            return self::blocked_response("WORKER_GMAIL_SAFETY_PROFILE_MISMATCH", 403);
        }

        global $wpdb;
        $candidates = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM " . self::jobs_table() . " WHERE status = 'PENDING' AND attempts = 0 AND expires_at > %s ORDER BY id ASC LIMIT 20",
            current_time("mysql", true)
        ), ARRAY_A);

        foreach ((array) $candidates as $job) {
            if (!in_array((string) $job["job_type"], $supported, true)) {
                continue;
            }
            if (absint($job["agent_id"] ?? 0) !== absint($worker["agent_id"])
                || (string) ($job["agent_slug"] ?? "") !== (string) $worker["agent_slug"]
                || (string) ($job["passport_public_id"] ?? "") !== (string) $worker["passport_public_id"]
                || !hash_equals((string) ($job["owner_binding_sha256"] ?? ""), (string) $worker["owner_binding_sha256"])) {
                continue;
            }
            $validation = self::validate_live_job_binding($job);
            if (empty($validation["ok"])) {
                self::fail_unclaimed_job($job, (string) ($validation["reason"] ?? "JOB_BINDING_INVALID"));
                continue;
            }
            $payload_json = self::open((string) $job["payload_ciphertext"]);
            if ($payload_json === "" || self::fingerprint($payload_json) !== (string) $job["payload_sha256"]) {
                self::fail_unclaimed_job($job, "JOB_PAYLOAD_DECRYPT_OR_HASH_FAILED");
                continue;
            }
            $authority_json = self::open((string) $job["authority_ciphertext"]);
            $authority = $authority_json !== "" ? json_decode($authority_json, true) : null;
            if (!is_array($authority) || self::fingerprint($authority_json) !== (string) $job["authority_sha256"]) {
                self::fail_unclaimed_job($job, "JOB_AUTHORITY_DECRYPT_OR_HASH_FAILED");
                continue;
            }
            $lease_token = self::random_token(48);
            $lease_expires = gmdate("Y-m-d H:i:s", min(
                strtotime((string) $job["expires_at"] . " UTC"),
                time() + self::CLAIM_LEASE_TTL_SECONDS
            ));
            if ($wpdb->query("START TRANSACTION") === false) {
                return self::blocked_response("WORKER_CLAIM_TRANSACTION_START_FAILED", 503);
            }
            $locked_connection_id = $wpdb->get_var($wpdb->prepare(
                "SELECT id FROM " . self::connections_table() . " WHERE id = %d FOR UPDATE",
                absint($job["connection_id"])
            ));
            if (absint($locked_connection_id) !== absint($job["connection_id"])) {
                $wpdb->query("ROLLBACK");
                self::fail_unclaimed_job($job, "JOB_CONNECTION_NOT_FOUND");
                continue;
            }
            $locked_validation = self::validate_live_job_binding($job);
            if (empty($locked_validation["ok"])) {
                $wpdb->query("ROLLBACK");
                self::fail_unclaimed_job($job, (string) ($locked_validation["reason"] ?? "JOB_BINDING_INVALID"));
                continue;
            }
            $active_claim = $wpdb->get_var($wpdb->prepare(
                "SELECT id FROM " . self::jobs_table() . " WHERE connection_id = %d AND status = 'CLAIMED' AND lease_expires_at > %s LIMIT 1",
                absint($job["connection_id"]),
                current_time("mysql", true)
            ));
            if (absint($active_claim) > 0) {
                $wpdb->query("ROLLBACK");
                continue;
            }
            $updated = $wpdb->query($wpdb->prepare(
                "UPDATE " . self::jobs_table() . " SET status = 'CLAIMED', worker_id = %s, lease_token_sha256 = %s, lease_expires_at = %s, claimed_at = %s, attempts = attempts + 1, updated_at = %s WHERE id = %d AND status = 'PENDING' AND attempts = 0",
                (string) $worker["worker_id"],
                hash("sha256", $lease_token),
                $lease_expires,
                current_time("mysql", true),
                current_time("mysql", true),
                absint($job["id"])
            ));
            if ($updated !== 1) {
                $wpdb->query("ROLLBACK");
                continue;
            }
            if ($wpdb->query("COMMIT") === false) {
                $wpdb->query("ROLLBACK");
                return self::blocked_response("WORKER_CLAIM_ATOMIC_COMMIT_FAILED", 503);
            }
            return rest_ensure_response(array(
                "ok" => true,
                "contract_version" => self::WORKER_CONTRACT,
                "job" => array(
                    "contract_version" => self::JOB_CONTRACT,
                    "job_id" => (string) $job["job_public_id"],
                    "job_type" => (string) $job["job_type"],
                    "connection_id" => (string) $locked_validation["connection"]["connection_public_id"],
                    "required_scope" => (string) $job["required_scope"],
                    "owner_binding_sha256" => (string) $job["owner_binding_sha256"],
                    "agent" => array(
                        "id" => absint($job["agent_id"]),
                        "slug" => (string) $job["agent_slug"],
                        "passport_public_id" => (string) $job["passport_public_id"],
                    ),
                    "payload_json" => $payload_json,
                    "payload_sha256" => (string) $job["payload_sha256"],
                    "authority" => $authority,
                    "lease_token" => $lease_token,
                    "expires_at" => gmdate("c", strtotime($lease_expires . " UTC")),
                ),
                "secret_values_logged" => false,
                "status" => "TRUSTBRIDGE_JOB_CLAIMED_ONCE",
            ));
        }

        return rest_ensure_response(array(
            "ok" => true,
            "contract_version" => self::WORKER_CONTRACT,
            "job" => null,
            "status" => "TRUSTBRIDGE_NO_PENDING_JOB",
        ));
    }

    public static function worker_complete($request)
    {
        $worker = self::worker_guard($request);
        if (empty($worker["ok"])) {
            return self::rest_blocked($worker);
        }
        $body = self::request_json($request);
        if ((string) ($body["contract_version"] ?? "") !== self::WORKER_CONTRACT) {
            return self::blocked_response("WORKER_CONTRACT_MISMATCH", 409);
        }
        $job_id = sanitize_text_field((string) $request->get_param("job_id"));
        if ($job_id === "" || $job_id !== sanitize_text_field((string) ($body["job_id"] ?? ""))) {
            return self::blocked_response("WORKER_JOB_ID_MISMATCH", 400);
        }
        $job = self::job_by_public_id($job_id);
        if (!$job) {
            return self::blocked_response("WORKER_JOB_NOT_FOUND", 404);
        }
        if ((string) $job["worker_id"] !== (string) $worker["worker_id"]) {
            return self::blocked_response("WORKER_JOB_OWNER_MISMATCH", 403);
        }
        $lease_token = trim((string) ($body["lease_token"] ?? ""));
        if ($lease_token === "" || !hash_equals((string) $job["lease_token_sha256"], hash("sha256", $lease_token))) {
            return self::blocked_response("WORKER_JOB_LEASE_INVALID", 403);
        }
        if ((string) ($body["payload_sha256"] ?? "") !== (string) $job["payload_sha256"]) {
            if ((string) $job["status"] === "CLAIMED"
                && !self::record_failed_job($job, "JOB_PAYLOAD_HASH_DRIFT", $worker)) {
                return self::blocked_response("JOB_ATOMIC_FAILURE_RECORDING_FAILED", 503);
            }
            return self::blocked_response("WORKER_JOB_PAYLOAD_HASH_MISMATCH", 409);
        }
        $outcome = sanitize_key((string) ($body["outcome"] ?? ""));
        if (in_array((string) $job["status"], array("SUCCEEDED", "FAILED", "UNKNOWN"), true)) {
            if ((string) $job["status"] === "SUCCEEDED") {
                $retry_result_json = isset($body["result"]) && is_array($body["result"])
                    ? wp_json_encode($body["result"], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
                    : false;
                if ($outcome !== "succeeded" || !is_string($retry_result_json)
                    || self::fingerprint($retry_result_json) !== (string) $job["result_sha256"]) {
                    return self::blocked_response("WORKER_TERMINAL_RETRY_MISMATCH", 409);
                }
            } elseif ((string) $job["status"] === "FAILED") {
                $retry_error = strtoupper(sanitize_key((string) ($body["error_code"] ?? "WORKER_JOB_FAILED")));
                if ($outcome !== "failed" || $retry_error !== (string) $job["error_code"]) {
                    return self::blocked_response("WORKER_TERMINAL_RETRY_MISMATCH", 409);
                }
            } else {
                $retry_error = strtoupper(sanitize_key((string) ($body["error_code"] ?? "PROVIDER_OUTCOME_UNKNOWN")));
                if ($outcome !== "unknown" || $retry_error !== (string) $job["error_code"]) {
                    return self::blocked_response("WORKER_TERMINAL_RETRY_MISMATCH", 409);
                }
            }
            return rest_ensure_response(array(
                "ok" => true,
                "job_id" => $job_id,
                "terminal" => true,
                "terminal_status" => (string) $job["status"],
                "provider_effect_repeated" => false,
                "status" => "TRUSTBRIDGE_JOB_ALREADY_TERMINAL",
            ));
        }
        if ((string) $job["status"] !== "CLAIMED") {
            return self::blocked_response("WORKER_JOB_NOT_CLAIMED", 409);
        }
        if (empty($job["lease_expires_at"]) || strtotime((string) $job["lease_expires_at"] . " UTC") <= time()) {
            if (!self::record_failed_job($job, "JOB_LEASE_EXPIRED", $worker)) {
                return self::blocked_response("JOB_ATOMIC_FAILURE_RECORDING_FAILED", 503);
            }
            return self::blocked_response("WORKER_JOB_LEASE_EXPIRED", 409);
        }
        $validation = self::validate_live_job_binding($job);
        if (empty($validation["ok"])) {
            if (!self::record_failed_job($job, (string) ($validation["reason"] ?? "JOB_BINDING_INVALID"), $worker)) {
                return self::blocked_response("JOB_ATOMIC_FAILURE_RECORDING_FAILED", 503);
            }
            return self::blocked_response("WORKER_JOB_LIVE_BINDING_REJECTED", 403);
        }

        if ($outcome === "failed") {
            $error_code = strtoupper(sanitize_key((string) ($body["error_code"] ?? "WORKER_JOB_FAILED")));
            $provider_attempt_count = absint($body["provider_attempt_count"] ?? 0);
            if ($provider_attempt_count !== 0
                || ($body["automatic_retry_attempted"] ?? null) !== false
                || ($body["exactly_once_effect_claimed"] ?? null) !== false
                || !self::record_failed_job($job, $error_code, $worker, 0)) {
                return self::blocked_response("JOB_ATOMIC_FAILURE_RECORDING_FAILED", 503);
            }
            return rest_ensure_response(array(
                "ok" => true,
                "job_id" => $job_id,
                "terminal" => true,
                "status" => "TRUSTBRIDGE_JOB_FAILURE_RECORDED",
            ));
        }
        if ($outcome === "unknown") {
            $error_code = strtoupper(sanitize_key((string) ($body["error_code"] ?? "PROVIDER_OUTCOME_UNKNOWN")));
            if (!in_array((string) $job["job_type"], array("gmail_draft_create", "gmail_send_approved_draft"), true)
                || absint($body["provider_attempt_count"] ?? 0) !== 1
                || ($body["automatic_retry_attempted"] ?? null) !== false
                || ($body["exactly_once_effect_claimed"] ?? null) !== false
                || !self::record_unknown_job($job, $error_code, $worker)) {
                return self::blocked_response("WORKER_UNKNOWN_OUTCOME_INVALID", 409);
            }
            return rest_ensure_response(array(
                "ok" => true,
                "job_id" => $job_id,
                "terminal" => true,
                "automatic_retry_allowed" => false,
                "status" => "TRUSTBRIDGE_JOB_UNKNOWN_SEALED",
            ));
        }
        if ($outcome !== "succeeded" || !isset($body["result"]) || !is_array($body["result"])) {
            return self::blocked_response("WORKER_JOB_OUTCOME_INVALID", 400);
        }
        $result = $body["result"];
        $result_json = wp_json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($result_json) || strlen($result_json) > self::MAX_RESULT_BYTES) {
            if (!self::record_failed_job($job, "JOB_RESULT_TOO_LARGE", $worker)) {
                return self::blocked_response("JOB_ATOMIC_FAILURE_RECORDING_FAILED", 503);
            }
            return self::blocked_response("WORKER_JOB_RESULT_TOO_LARGE", 413);
        }
        if (self::contains_secret_material($result, (string) $job["job_type"] === "gmail_oauth_start")) {
            if (!self::record_failed_job($job, "JOB_RESULT_SECRET_MATERIAL_REJECTED", $worker)) {
                return self::blocked_response("JOB_ATOMIC_FAILURE_RECORDING_FAILED", 503);
            }
            return self::blocked_response("WORKER_JOB_RESULT_SECRET_MATERIAL_REJECTED", 400);
        }

        $recorded = self::record_successful_job($job, $validation["connection"], $result, $result_json, $worker);
        if (empty($recorded["ok"])) {
            if (absint($recorded["http_status"] ?? 500) < 500
                && !self::record_failed_job($job, (string) ($recorded["reason"] ?? "JOB_RESULT_CONTRACT_INVALID"), $worker)) {
                return self::blocked_response("JOB_ATOMIC_FAILURE_RECORDING_FAILED", 503);
            }
            return self::rest_blocked($recorded);
        }

        return rest_ensure_response(array(
            "ok" => true,
            "job_id" => $job_id,
            "terminal" => true,
            "provider_token_received_by_noderooms" => false,
            "status" => "TRUSTBRIDGE_JOB_SUCCESS_RECORDED",
        ));
    }

    private static function migration_cli_approved()
    {
        return PHP_SAPI === "cli"
            && defined("WP_CLI")
            && WP_CLI
            && defined("NODEROOMS_TRUSTBRIDGE_MIGRATION_APPROVED")
            && (string) constant("NODEROOMS_TRUSTBRIDGE_MIGRATION_APPROVED") === self::SCHEMA_VERSION;
    }

    private static function install_schema()
    {
        global $wpdb;
        if (!isset($wpdb) || !is_object($wpdb)) {
            return;
        }
        require_once ABSPATH . "wp-admin/includes/upgrade.php";
        $charset = $wpdb->get_charset_collate();
        $connections = self::connections_table();
        $jobs = self::jobs_table();
        $receipts = self::receipts_table();
        $workers = self::workers_table();
        $pairings = self::worker_pairings_table();
        $worker_nonces = self::worker_nonces_table();

        dbDelta("CREATE TABLE {$connections} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            connection_public_id VARCHAR(64) NOT NULL,
            provider VARCHAR(32) NOT NULL,
            owner_binding_sha256 VARCHAR(71) NOT NULL,
            owner_user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            owner_session_type VARCHAR(32) NOT NULL,
            verification_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            agent_id BIGINT UNSIGNED NOT NULL,
            agent_slug VARCHAR(200) NOT NULL,
            passport_public_id VARCHAR(80) NOT NULL,
            account_email_ciphertext LONGTEXT NOT NULL,
            account_email_sha256 VARCHAR(71) NOT NULL,
            account_email_masked VARCHAR(254) NOT NULL,
            status VARCHAR(64) NOT NULL,
            capabilities_json LONGTEXT NOT NULL,
            capabilities_granted_at DATETIME NULL,
            capability_bundle_public_id VARCHAR(64) NULL,
            capability_purpose VARCHAR(500) NULL,
            capability_purpose_sha256 VARCHAR(71) NULL,
            capability_expires_at DATETIME NULL,
            authorization_url_ciphertext LONGTEXT NULL,
            oauth_state_sha256 CHAR(64) NULL,
            oauth_state_expires_at DATETIME NULL,
            worker_id VARCHAR(80) NULL,
            last_error_code VARCHAR(128) NULL,
            connected_at DATETIME NULL,
            revoked_at DATETIME NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY connection_public_id (connection_public_id),
            UNIQUE KEY oauth_state_sha256 (oauth_state_sha256),
            KEY owner_agent (owner_binding_sha256, agent_id),
            KEY agent_status (agent_id, status),
            KEY provider_status (provider, status)
        ) {$charset};");

        dbDelta("CREATE TABLE {$jobs} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            job_public_id VARCHAR(64) NOT NULL,
            connection_id BIGINT UNSIGNED NOT NULL,
            owner_binding_sha256 VARCHAR(71) NOT NULL,
            agent_id BIGINT UNSIGNED NOT NULL,
            agent_slug VARCHAR(200) NOT NULL,
            passport_public_id VARCHAR(80) NOT NULL,
            job_type VARCHAR(64) NOT NULL,
            required_scope VARCHAR(128) NOT NULL,
            payload_ciphertext LONGTEXT NOT NULL,
            payload_sha256 VARCHAR(71) NOT NULL,
            authority_ciphertext LONGTEXT NOT NULL,
            authority_sha256 VARCHAR(71) NOT NULL,
            target_fingerprint_sha256 VARCHAR(71) NOT NULL,
            run_lease_public_id VARCHAR(64) NOT NULL,
            run_lease_expires_at DATETIME NOT NULL,
            action_approval_public_id VARCHAR(64) NULL,
            dispatch_reservation_public_id VARCHAR(64) NULL,
            status VARCHAR(32) NOT NULL,
            worker_id VARCHAR(80) NULL,
            lease_token_sha256 CHAR(64) NULL,
            lease_expires_at DATETIME NULL,
            attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
            provider_attempt_count TINYINT UNSIGNED NOT NULL DEFAULT 0,
            result_ciphertext LONGTEXT NULL,
            result_sha256 VARCHAR(71) NULL,
            provider_resource_id_sha256 VARCHAR(71) NULL,
            error_code VARCHAR(128) NULL,
            expires_at DATETIME NOT NULL,
            claimed_at DATETIME NULL,
            completed_at DATETIME NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY job_public_id (job_public_id),
            KEY queue (status, attempts, expires_at),
            KEY connection_jobs (connection_id, id),
            KEY owner_agent_jobs (owner_binding_sha256, agent_id)
        ) {$charset};");

        dbDelta("CREATE TABLE {$workers} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            worker_public_id VARCHAR(64) NOT NULL,
            worker_binding_public_id VARCHAR(64) NOT NULL,
            public_key_b64url VARCHAR(64) NOT NULL,
            owner_binding_sha256 VARCHAR(71) NOT NULL,
            agent_id BIGINT UNSIGNED NOT NULL,
            agent_slug VARCHAR(200) NOT NULL,
            passport_public_id VARCHAR(80) NOT NULL,
            infrastructure_agent_id VARCHAR(80) NOT NULL,
            worker_version VARCHAR(64) NOT NULL,
            supported_job_types_json LONGTEXT NOT NULL,
            status VARCHAR(32) NOT NULL,
            paired_at DATETIME NOT NULL,
            last_seen_at DATETIME NULL,
            revoked_at DATETIME NULL,
            PRIMARY KEY (id),
            UNIQUE KEY worker_public_id (worker_public_id),
            UNIQUE KEY worker_binding_public_id (worker_binding_public_id),
            UNIQUE KEY public_key_b64url (public_key_b64url),
            KEY active_agent (agent_id, status)
        ) {$charset};");

        dbDelta("CREATE TABLE {$pairings} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            pairing_public_id VARCHAR(64) NOT NULL,
            challenge_sha256 VARCHAR(71) NOT NULL,
            owner_binding_sha256 VARCHAR(71) NOT NULL,
            agent_id BIGINT UNSIGNED NOT NULL,
            agent_slug VARCHAR(200) NOT NULL,
            passport_public_id VARCHAR(80) NOT NULL,
            worker_public_id VARCHAR(64) NULL,
            status VARCHAR(32) NOT NULL,
            expires_at DATETIME NOT NULL,
            consumed_at DATETIME NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY pairing_public_id (pairing_public_id),
            UNIQUE KEY challenge_sha256 (challenge_sha256),
            KEY active_pairing (agent_id, status, expires_at)
        ) {$charset};");

        dbDelta("CREATE TABLE {$receipts} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            receipt_public_id VARCHAR(64) NOT NULL,
            job_public_id VARCHAR(64) NOT NULL,
            connection_public_id VARCHAR(64) NOT NULL,
            owner_binding_sha256 VARCHAR(71) NOT NULL,
            agent_id BIGINT UNSIGNED NOT NULL,
            agent_slug VARCHAR(200) NOT NULL,
            passport_public_id VARCHAR(80) NOT NULL,
            required_scope VARCHAR(128) NOT NULL,
            payload_sha256 VARCHAR(71) NOT NULL,
            result_sha256 VARCHAR(71) NULL,
            outcome VARCHAR(32) NOT NULL,
            error_code VARCHAR(128) NULL,
            worker_id VARCHAR(80) NOT NULL,
            receipt_json LONGTEXT NOT NULL,
            receipt_hmac_sha256 CHAR(64) NOT NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY receipt_public_id (receipt_public_id),
            UNIQUE KEY job_public_id (job_public_id),
            KEY agent_receipts (agent_id, id),
            KEY connection_receipts (connection_public_id, id)
        ) {$charset};");

        dbDelta("CREATE TABLE {$worker_nonces} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            nonce_sha256 CHAR(64) NOT NULL,
            worker_id VARCHAR(80) NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY nonce_sha256 (nonce_sha256),
            KEY nonce_expiry (expires_at)
        ) {$charset};");

        if (!self::all_schema_tables_exist()) {
            return false;
        }
        update_option(self::SCHEMA_OPTION, self::SCHEMA_VERSION, false);
        return self::schema_is_ready();
    }

    private static function schema_is_ready()
    {
        return (string) get_option(self::SCHEMA_OPTION, "") === self::SCHEMA_VERSION
            && self::all_schema_tables_exist();
    }

    private static function schema_tables()
    {
        return array(
            self::connections_table(),
            self::jobs_table(),
            self::workers_table(),
            self::worker_pairings_table(),
            self::receipts_table(),
            self::worker_nonces_table(),
        );
    }

    private static function table_exists($table)
    {
        global $wpdb;
        return (string) $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->esc_like((string) $table))) === (string) $table;
    }

    private static function all_schema_tables_exist()
    {
        foreach (self::schema_tables() as $table) {
            if (!self::table_exists($table)) {
                return false;
            }
        }
        return true;
    }

    private static function any_schema_table_exists()
    {
        foreach (self::schema_tables() as $table) {
            if (self::table_exists($table)) {
                return true;
            }
        }
        return false;
    }

    private static function runtime_guard()
    {
        if (!self::schema_is_ready()) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_MIGRATION_REQUIRED", "http_status" => 503);
        }
        if (!defined(self::RUNTIME_ENABLED_CONSTANT) || constant(self::RUNTIME_ENABLED_CONSTANT) !== true) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_RUNTIME_DISABLED", "http_status" => 503);
        }
        if (!function_exists("sodium_crypto_sign_verify_detached")) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_ED25519_RUNTIME_REQUIRED", "http_status" => 503);
        }
        return array("ok" => true);
    }

    private static function connections_table()
    {
        global $wpdb;
        return $wpdb->prefix . "ago_trustbridge_connections";
    }

    private static function jobs_table()
    {
        global $wpdb;
        return $wpdb->prefix . "ago_trustbridge_jobs";
    }

    private static function receipts_table()
    {
        global $wpdb;
        return $wpdb->prefix . "ago_trustbridge_receipts";
    }

    private static function worker_nonces_table()
    {
        global $wpdb;
        return $wpdb->prefix . "ago_trustbridge_worker_nonces";
    }

    private static function workers_table()
    {
        global $wpdb;
        return $wpdb->prefix . "ago_trustbridge_workers";
    }

    private static function worker_pairings_table()
    {
        global $wpdb;
        return $wpdb->prefix . "ago_trustbridge_worker_pairings";
    }

    private static function owner_guard($request)
    {
        $runtime = self::runtime_guard();
        if (empty($runtime["ok"])) {
            return $runtime;
        }
        $owner = self::current_owner_context();
        if (empty($owner["ok"])) {
            return $owner;
        }
        $nonce = $request instanceof WP_REST_Request ? trim((string) $request->get_header("x-noderooms-owner-nonce")) : "";
        if ($nonce === "") {
            $nonce = self::request_string($request, "owner_nonce");
        }
        if ($nonce === "" || !wp_verify_nonce($nonce, self::OWNER_NONCE_ACTION_PREFIX . (string) $owner["owner_binding_sha256"])) {
            return array("ok" => false, "reason" => "NODEROOMS_OWNER_NONCE_INVALID", "http_status" => 403);
        }
        $requested_agent = sanitize_title(self::request_string($request, "agent_slug"));
        if ($requested_agent !== "" && $requested_agent !== (string) $owner["agent_slug"]) {
            return array("ok" => false, "reason" => "OWNER_SESSION_AGENT_MISMATCH", "http_status" => 403);
        }
        return $owner;
    }

    private static function current_owner_context()
    {
        if (!class_exists("AGO_Agent_Session")) {
            return array("ok" => false, "reason" => "OWNER_SESSION_RUNTIME_NOT_READY", "http_status" => 503);
        }
        $session = array();
        $session_type = "";
        if (method_exists("AGO_Agent_Session", "get_current_owner_invite_session")) {
            $candidate = AGO_Agent_Session::get_current_owner_invite_session();
            if (!empty($candidate["active"])) {
                $session = $candidate;
                $session_type = "owner_invite";
            }
        }
        if ($session_type === "" && function_exists("is_user_logged_in") && is_user_logged_in() && method_exists("AGO_Agent_Session", "get_current_owner_login_session_for_current_user")) {
            $candidate = AGO_Agent_Session::get_current_owner_login_session_for_current_user();
            if (!empty($candidate["active"])) {
                $session = $candidate;
                $session_type = "wordpress_owner";
            }
        }
        if ($session_type === "") {
            return array("ok" => false, "reason" => "NODEROOMS_OWNER_SESSION_REQUIRED", "http_status" => 403);
        }

        $binding = self::agent_binding_by_slug((string) ($session["agent_slug"] ?? ""));
        if (empty($binding["ok"])) {
            return $binding;
        }
        if (absint($session["agent_id"] ?? 0) !== absint($binding["agent_id"])) {
            return array("ok" => false, "reason" => "OWNER_SESSION_AGENT_ID_DRIFT", "http_status" => 403);
        }
        if ($session_type === "owner_invite") {
            if (absint($session["verification_id"] ?? 0) !== absint($binding["verification_id"])) {
                return array("ok" => false, "reason" => "OWNER_INVITE_VERIFICATION_DRIFT", "http_status" => 403);
            }
        } else {
            if (absint(get_current_user_id()) !== absint($binding["owner_user_id"])) {
                return array("ok" => false, "reason" => "CURRENT_USER_IS_NOT_AGENT_OWNER", "http_status" => 403);
            }
        }

        $owner = array_merge($binding, array(
            "ok" => true,
            "owner_session_type" => $session_type,
        ));
        $owner["owner_binding_sha256"] = self::owner_binding_fingerprint($owner);
        $passport = self::passport_guard($owner, "trustbridge_owner_context");
        if (empty($passport["ok"])) {
            return $passport;
        }
        $owner["passport_public_id"] = (string) $passport["passport_public_id"];
        return $owner;
    }

    private static function agent_binding_by_slug($agent_slug)
    {
        global $wpdb;
        $agent_slug = sanitize_title((string) $agent_slug);
        if ($agent_slug === "") {
            return array("ok" => false, "reason" => "AGENT_SLUG_REQUIRED", "http_status" => 400);
        }
        $agents = $wpdb->prefix . "ago_agents";
        $submissions = $wpdb->prefix . "ago_agent_submission_requests";
        $claims = $wpdb->prefix . "ago_agent_claim_requests";
        $verifications = $wpdb->prefix . "ago_agent_owner_verifications";
        foreach (array($agents, $submissions, $claims, $verifications) as $table) {
            if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table)) !== $table) {
                return array("ok" => false, "reason" => "AGENT_BINDING_TABLE_NOT_READY", "http_status" => 503);
            }
        }
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT a.id AS agent_id, a.agent_slug, a.agent_name, a.role_label, a.status AS agent_status, a.public_posting, s.id AS submission_id, s.status AS submission_status, s.public_preview, c.id AS claim_id, c.owner_user_id AS claim_owner_user_id, c.claim_status, v.id AS verification_id, v.owner_user_id AS verification_owner_user_id, v.provider, v.provider_user_id, v.provider_login, v.status AS verification_status FROM {$agents} a LEFT JOIN {$submissions} s ON s.created_agent_id = a.id LEFT JOIN {$claims} c ON c.agent_id = a.id LEFT JOIN {$verifications} v ON v.agent_id = a.id WHERE a.agent_slug = %s ORDER BY s.id DESC, c.id DESC, v.id DESC LIMIT 1",
            $agent_slug
        ), ARRAY_A);
        if (!is_array($row)) {
            return array("ok" => false, "reason" => "AGENT_NOT_FOUND", "http_status" => 404);
        }
        $claim_owner = absint($row["claim_owner_user_id"] ?? 0);
        $verification_owner = absint($row["verification_owner_user_id"] ?? 0);
        if ($claim_owner <= 0 || $claim_owner !== $verification_owner) {
            return array("ok" => false, "reason" => "AGENT_OWNER_BINDING_NOT_FINAL", "http_status" => 403);
        }
        if (strtoupper(trim((string) ($row["agent_status"] ?? ""))) !== "ACTIVE"
            || (string) ($row["submission_status"] ?? "") !== "OWNER_CLAIM_FINALIZED_AGENT_ACTIVE"
            || (string) ($row["claim_status"] ?? "") !== "OWNER_CLAIM_FINALIZED_AGENT_ACTIVE"
            || strtoupper(trim((string) ($row["verification_status"] ?? ""))) !== "VERIFIED") {
            return array("ok" => false, "reason" => "AGENT_OWNER_BINDING_NOT_ACTIVE", "http_status" => 403);
        }
        if (!self::is_falsey($row["public_posting"] ?? null) || !self::is_truthy($row["public_preview"] ?? null)) {
            return array("ok" => false, "reason" => "AGENT_PUBLIC_SAFETY_POLICY_BLOCKED", "http_status" => 403);
        }
        return array(
            "ok" => true,
            "agent_id" => absint($row["agent_id"]),
            "agent_slug" => sanitize_title((string) $row["agent_slug"]),
            "agent_name" => sanitize_text_field((string) $row["agent_name"]),
            "role_label" => sanitize_text_field((string) $row["role_label"]),
            "owner_user_id" => $verification_owner,
            "submission_id" => absint($row["submission_id"]),
            "claim_id" => absint($row["claim_id"]),
            "verification_id" => absint($row["verification_id"]),
            "provider" => sanitize_key((string) $row["provider"]),
            "provider_user_id_sha256" => self::fingerprint((string) ($row["provider_user_id"] ?? "")),
            "provider_login" => sanitize_text_field((string) $row["provider_login"]),
        );
    }

    private static function passport_guard($binding, $operation)
    {
        $agent_id = absint($binding["agent_id"] ?? 0);
        if ($agent_id <= 0 || !class_exists("AGO_Passport_Lifecycle") || !method_exists("AGO_Passport_Lifecycle", "decision")) {
            return array("ok" => false, "reason" => "PASSPORT_LIFECYCLE_NOT_READY", "http_status" => 503);
        }
        $decision = AGO_Passport_Lifecycle::decision($agent_id, (string) $operation, array(
            "operation_class" => "privileged",
        ));
        if (empty($decision["allowed"])) {
            return array(
                "ok" => false,
                "reason" => (string) ($decision["reason_code"] ?? "PASSPORT_OPERATION_BLOCKED"),
                "http_status" => 403,
            );
        }
        $passport_id = sanitize_text_field((string) ($decision["passport_id"] ?? ""));
        if (!preg_match('/^NRP-[0-9]{6,}-AGENT$/', $passport_id)) {
            return array("ok" => false, "reason" => "PASSPORT_PUBLIC_ID_INVALID", "http_status" => 403);
        }
        return array(
            "ok" => true,
            "passport_public_id" => $passport_id,
            "passport_lifecycle_status" => sanitize_text_field((string) ($decision["lifecycle_status"] ?? "ACTIVE")),
        );
    }

    private static function owner_binding_fingerprint($binding)
    {
        $canonical = implode("|", array(
            absint($binding["owner_user_id"] ?? 0),
            absint($binding["verification_id"] ?? 0),
            absint($binding["agent_id"] ?? 0),
            sanitize_title((string) ($binding["agent_slug"] ?? "")),
            (string) ($binding["provider_user_id_sha256"] ?? ""),
        ));
        return "sha256:" . hash_hmac("sha256", $canonical, wp_salt("auth"));
    }

    private static function owner_connection_from_request($request, $owner)
    {
        $connection_id = sanitize_text_field(self::request_string($request, "connection_id"));
        $connection = $connection_id !== "" ? self::connection_by_public_id($connection_id) : self::latest_connection_for_owner($owner);
        if (!$connection || !self::row_matches_owner($connection, $owner)) {
            return array("ok" => false, "reason" => "GMAIL_CONNECTION_NOT_FOUND", "http_status" => 404);
        }
        return array("ok" => true, "connection" => $connection);
    }

    private static function latest_connection_for_owner($owner)
    {
        global $wpdb;
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM " . self::connections_table() . " WHERE owner_binding_sha256 = %s AND agent_id = %d AND provider = 'gmail' ORDER BY id DESC LIMIT 1",
            (string) $owner["owner_binding_sha256"],
            absint($owner["agent_id"])
        ), ARRAY_A);
        return is_array($row) ? $row : null;
    }

    private static function connection_by_public_id($connection_id)
    {
        global $wpdb;
        $connection_id = sanitize_text_field((string) $connection_id);
        if (!preg_match('/^nrtbc_[a-f0-9]{32}$/', $connection_id)) {
            return null;
        }
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM " . self::connections_table() . " WHERE connection_public_id = %s LIMIT 1",
            $connection_id
        ), ARRAY_A);
        return is_array($row) ? $row : null;
    }

    private static function job_by_public_id($job_id)
    {
        global $wpdb;
        $job_id = sanitize_text_field((string) $job_id);
        if (!preg_match('/^nrtbj_[a-f0-9]{32}$/', $job_id)) {
            return null;
        }
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM " . self::jobs_table() . " WHERE job_public_id = %s LIMIT 1",
            $job_id
        ), ARRAY_A);
        return is_array($row) ? $row : null;
    }

    private static function worker_by_public_id($worker_id)
    {
        global $wpdb;
        $worker_id = sanitize_text_field((string) $worker_id);
        if (!preg_match('/^nrtbw_[a-f0-9]{32}$/', $worker_id)) {
            return null;
        }
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM " . self::workers_table() . " WHERE worker_public_id = %s LIMIT 1",
            $worker_id
        ), ARRAY_A);
        return is_array($row) ? $row : null;
    }

    private static function active_worker_for_agent($binding)
    {
        global $wpdb;
        $agent_id = absint($binding["agent_id"] ?? 0);
        if ($agent_id <= 0) {
            return null;
        }
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM " . self::workers_table() . " WHERE agent_id = %d AND status = 'ACTIVE' ORDER BY id DESC LIMIT 1",
            $agent_id
        ), ARRAY_A);
        return is_array($row)
            && hash_equals(self::REQUIRED_WORKER_VERSION, (string) ($row["worker_version"] ?? ""))
            ? $row
            : null;
    }

    private static function create_job($connection, $job_type, $payload, $ttl_seconds, $action_approval_request = null)
    {
        if (!is_array($connection)
            || empty($connection["id"])
            || !in_array($job_type, self::$supported_worker_jobs, true)
            || !is_array($payload)) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_JOB_INPUT_INVALID", "http_status" => 400);
        }
        $scopes = array(
            "gmail_oauth_start" => "connector.gmail.account.connect",
            "gmail_oauth_complete" => "connector.gmail.account.connect",
            "gmail_search" => "connector.gmail.message.search",
            "gmail_thread_read" => "connector.gmail.thread.read",
            "gmail_draft_create" => "connector.gmail.draft.create",
            "gmail_send_approved_draft" => "connector.gmail.draft.send",
            "gmail_disconnect" => "connector.gmail.account.disconnect",
        );
        $account_email = self::normalize_email((string) ($payload["account_email"] ?? ""));
        if ($account_email === "" || !isset($scopes[$job_type])) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_JOB_ACCOUNT_OR_SCOPE_INVALID", "http_status" => 400);
        }
        $payload_json = wp_json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $sealed_payload = is_string($payload_json) ? self::seal($payload_json) : "";
        if ($sealed_payload === "") {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_JOB_ENCRYPTION_FAILED", "http_status" => 503);
        }

        $job_id = self::public_id("nrtbj_");
        $capability_id = self::public_id("nrtbcap_");
        $run_lease_id = self::public_id("nrtblease_");
        $purpose_id = self::public_id("nrtbpurpose_");
        $payload_sha256 = self::fingerprint($payload_json);
        $target_sha256 = self::job_target_fingerprint($job_type, $payload);
        if ($target_sha256 === "") {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_JOB_TARGET_INVALID", "http_status" => 400);
        }
        $ttl = max(60, min(900, absint($ttl_seconds)));
        $authority_expiry = time() + $ttl;
        $purpose = "Owner-managed Gmail connection for the exact Passport Agent";
        if (in_array($job_type, array("gmail_search", "gmail_thread_read", "gmail_draft_create"), true)) {
            $purpose = trim((string) ($connection["capability_purpose"] ?? ""));
            $capability_expiry = strtotime((string) ($connection["capability_expires_at"] ?? "") . " UTC");
            if ($purpose === ""
                || empty($connection["capability_bundle_public_id"])
                || $capability_expiry === false
                || $capability_expiry <= time()) {
                return array("ok" => false, "reason" => "TRUSTBRIDGE_PURPOSE_BOUND_CAPABILITY_REQUIRED", "http_status" => 403);
            }
            $authority_expiry = min($authority_expiry, $capability_expiry);
        } elseif ($job_type === "gmail_send_approved_draft") {
            if (!is_array($action_approval_request)
                || (string) ($action_approval_request["policy"] ?? "") !== "allow_once"
                || (string) ($action_approval_request["decision_source"] ?? "") !== "verified_human_owner"
                || ($action_approval_request["automated"] ?? true) !== false
                || !hash_equals((string) $connection["owner_binding_sha256"], (string) ($action_approval_request["owner_binding_id"] ?? ""))) {
                return array("ok" => false, "reason" => "TRUSTBRIDGE_SEND_APPROVAL_REQUIRED", "http_status" => 403);
            }
            $purpose = trim((string) ($action_approval_request["purpose"] ?? ""));
            if ($purpose === "" || strlen($purpose) > 500) {
                return array("ok" => false, "reason" => "TRUSTBRIDGE_SEND_PURPOSE_REQUIRED", "http_status" => 403);
            }
        }
        if ($authority_expiry <= time()) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_AUTHORITY_EXPIRED", "http_status" => 403);
        }

        $issued_at_iso = gmdate("c");
        $expires_at_iso = gmdate("c", $authority_expiry);
        $purpose_sha256 = self::fingerprint($purpose);
        $account_binding_sha256 = self::fingerprint($account_email);
        $authority = array(
            "contract_version" => self::AUTHORITY_CONTRACT,
            "surfaces" => array(
                "registration" => "noderooms",
                "work" => "noderooms",
                "connector_setup" => "noderooms",
                "operations" => "noderooms",
                "automations" => "noderooms",
                "approvals" => "noderooms",
                "results" => "noderooms",
            ),
            "runtime" => array(
                "role" => "background_infrastructure",
                "user_visible" => false,
                "user_cli_allowed" => false,
                "user_install_allowed" => false,
                "user_plugin_allowed" => false,
                "user_branding_allowed" => false,
            ),
            "agent" => array(
                "slug" => (string) $connection["agent_slug"],
                "owner_binding_id" => (string) $connection["owner_binding_sha256"],
                "owner_binding_status" => "verified",
                "passport_public_id" => (string) $connection["passport_public_id"],
                "passport_status" => "active",
            ),
            "capability" => array(
                "capability_id" => $capability_id,
                "status" => "active",
                "decision" => "allow",
                "decision_source" => "verified_human_owner",
                "automated" => false,
                "agent_slug" => (string) $connection["agent_slug"],
                "owner_binding_id" => (string) $connection["owner_binding_sha256"],
                "passport_public_id" => (string) $connection["passport_public_id"],
                "provider" => "gmail",
                "account_binding_sha256" => $account_binding_sha256,
                "target_fingerprint_sha256" => $target_sha256,
                "scope" => $scopes[$job_type],
                "purpose_id" => $purpose_id,
                "purpose_sha256" => $purpose_sha256,
                "issued_at" => $issued_at_iso,
                "expires_at" => $expires_at_iso,
            ),
            "run_lease" => array(
                "run_lease_id" => $run_lease_id,
                "status" => "active",
                "capability_id" => $capability_id,
                "agent_slug" => (string) $connection["agent_slug"],
                "owner_binding_id" => (string) $connection["owner_binding_sha256"],
                "passport_public_id" => (string) $connection["passport_public_id"],
                "provider" => "gmail",
                "account_binding_sha256" => $account_binding_sha256,
                "target_fingerprint_sha256" => $target_sha256,
                "scope" => $scopes[$job_type],
                "purpose_id" => $purpose_id,
                "purpose_sha256" => $purpose_sha256,
                "remaining_actions" => 1,
                "issued_at" => $issued_at_iso,
                "expires_at" => $expires_at_iso,
            ),
            "action_approval" => null,
            "job_binding" => array(
                "job_id" => $job_id,
                "job_type" => $job_type,
                "payload_sha256" => $payload_sha256,
            ),
        );

        $approval_id = null;
        $dispatch_id = null;
        if ($job_type === "gmail_send_approved_draft") {
            $draft_id = (string) ($payload["draft_id"] ?? "");
            $draft_id_sha256 = self::fingerprint($draft_id);
            $approval_id = self::public_id("nrtbapproval_");
            $dispatch_id = self::public_id("nrtbdispatch_");
            $authority["action_approval"] = array(
                "policy" => "allow_once",
                "status" => "approved",
                "decision_source" => "verified_human_owner",
                "automated" => false,
                "owner_binding_id" => (string) $connection["owner_binding_sha256"],
                "approval_receipt_id" => $approval_id,
                "dispatch_reservation_id" => $dispatch_id,
                "draft_id_sha256" => $draft_id_sha256,
                "action_fingerprint_sha256" => self::connector_action_fingerprint(array(
                    "job_id" => $job_id,
                    "job_type" => $job_type,
                    "payload_sha256" => $payload_sha256,
                    "agent_slug" => (string) $connection["agent_slug"],
                    "passport_public_id" => (string) $connection["passport_public_id"],
                    "owner_binding_id" => (string) $connection["owner_binding_sha256"],
                    "capability_id" => $capability_id,
                    "run_lease_id" => $run_lease_id,
                    "provider" => "gmail",
                    "account_binding_sha256" => $account_binding_sha256,
                    "target_fingerprint_sha256" => $target_sha256,
                    "scope" => $scopes[$job_type],
                    "purpose_id" => $purpose_id,
                    "purpose_sha256" => $purpose_sha256,
                    "draft_id_sha256" => $draft_id_sha256,
                )),
                "provider_attempt_max" => 1,
                "automatic_retry_allowed" => false,
                "expires_at" => $expires_at_iso,
            );
        }
        $authority_json = wp_json_encode($authority, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $sealed_authority = is_string($authority_json) ? self::seal($authority_json) : "";
        if ($sealed_authority === "") {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_AUTHORITY_ENCRYPTION_FAILED", "http_status" => 503);
        }

        global $wpdb;
        $send_transaction_started = false;
        if ($job_type === "gmail_send_approved_draft") {
            if ($wpdb->query("START TRANSACTION") === false) {
                return array("ok" => false, "reason" => "GMAIL_SEND_RESERVATION_TRANSACTION_FAILED", "http_status" => 503);
            }
            $send_transaction_started = true;
            $locked_connection_id = $wpdb->get_var($wpdb->prepare(
                "SELECT id FROM " . self::connections_table() . " WHERE id = %d FOR UPDATE",
                absint($connection["id"])
            ));
            if (absint($locked_connection_id) !== absint($connection["id"])) {
                $wpdb->query("ROLLBACK");
                return array("ok" => false, "reason" => "GMAIL_SEND_CONNECTION_LOCK_FAILED", "http_status" => 503);
            }
            $existing = $wpdb->get_var($wpdb->prepare(
                "SELECT id FROM " . self::jobs_table() . " WHERE connection_id = %d AND job_type = 'gmail_send_approved_draft' AND target_fingerprint_sha256 = %s AND status IN ('PENDING','CLAIMED','SUCCEEDED','UNKNOWN') LIMIT 1",
                absint($connection["id"]),
                $target_sha256
            ));
            if (absint($existing) > 0) {
                $wpdb->query("ROLLBACK");
                return array("ok" => false, "reason" => "GMAIL_APPROVED_DRAFT_SEND_ALREADY_RESERVED", "http_status" => 409);
            }
        }
        $now = current_time("mysql", true);
        $expires_at_mysql = gmdate("Y-m-d H:i:s", $authority_expiry);
        $inserted = $wpdb->insert(self::jobs_table(), array(
            "job_public_id" => $job_id,
            "connection_id" => absint($connection["id"]),
            "owner_binding_sha256" => (string) $connection["owner_binding_sha256"],
            "agent_id" => absint($connection["agent_id"]),
            "agent_slug" => (string) $connection["agent_slug"],
            "passport_public_id" => (string) $connection["passport_public_id"],
            "job_type" => $job_type,
            "required_scope" => $scopes[$job_type],
            "payload_ciphertext" => $sealed_payload,
            "payload_sha256" => $payload_sha256,
            "authority_ciphertext" => $sealed_authority,
            "authority_sha256" => self::fingerprint($authority_json),
            "target_fingerprint_sha256" => $target_sha256,
            "run_lease_public_id" => $run_lease_id,
            "run_lease_expires_at" => $expires_at_mysql,
            "action_approval_public_id" => $approval_id,
            "dispatch_reservation_public_id" => $dispatch_id,
            "status" => "PENDING",
            "attempts" => 0,
            "provider_attempt_count" => 0,
            "expires_at" => $expires_at_mysql,
            "created_at" => $now,
            "updated_at" => $now,
        ));
        if ($inserted !== 1) {
            if ($send_transaction_started) {
                $wpdb->query("ROLLBACK");
            }
            return array("ok" => false, "reason" => "TRUSTBRIDGE_JOB_CREATE_FAILED", "http_status" => 500);
        }
        if ($send_transaction_started && $wpdb->query("COMMIT") === false) {
            $wpdb->query("ROLLBACK");
            return array("ok" => false, "reason" => "GMAIL_SEND_RESERVATION_COMMIT_FAILED", "http_status" => 503);
        }
        return array("ok" => true, "job_id" => $job_id);
    }

    private static function job_target_fingerprint($job_type, $payload)
    {
        $account = self::normalize_email((string) ($payload["account_email"] ?? ""));
        if ($account === "") {
            return "";
        }
        if (in_array($job_type, array("gmail_oauth_start", "gmail_oauth_complete", "gmail_disconnect"), true)) {
            return self::fingerprint("gmail\naccount\n" . $account);
        }
        if ($job_type === "gmail_search") {
            $query = (string) ($payload["query"] ?? "");
            return $query !== "" && strlen($query) <= 500
                ? self::fingerprint("gmail\nsearch\n" . $account . "\n" . $query)
                : "";
        }
        if ($job_type === "gmail_thread_read") {
            $thread_id = (string) ($payload["thread_id"] ?? "");
            return preg_match('/^[A-Za-z0-9_-]{1,256}$/', $thread_id)
                ? self::fingerprint("gmail\nthread\n" . $account . "\n" . $thread_id)
                : "";
        }
        if ($job_type === "gmail_draft_create") {
            $to = self::normalize_email((string) ($payload["to"] ?? ""));
            return $to !== ""
                ? self::fingerprint("gmail\nrecipient\n" . $account . "\n" . $to)
                : "";
        }
        if ($job_type === "gmail_send_approved_draft") {
            $draft_id = (string) ($payload["draft_id"] ?? "");
            return preg_match('/^[A-Za-z0-9_-]{1,256}$/', $draft_id)
                ? self::fingerprint("gmail\ndraft\n" . $account . "\n" . $draft_id)
                : "";
        }
        return "";
    }

    private static function connector_action_fingerprint($input)
    {
        $keys = array(
            "job_id", "job_type", "payload_sha256", "agent_slug",
            "passport_public_id", "owner_binding_id", "capability_id",
            "run_lease_id", "provider", "account_binding_sha256",
            "target_fingerprint_sha256", "scope", "purpose_id",
            "purpose_sha256", "draft_id_sha256",
        );
        $parts = array(self::AUTHORITY_CONTRACT);
        foreach ($keys as $key) {
            $parts[] = isset($input[$key]) && (string) $input[$key] !== ""
                ? (string) $input[$key]
                : "none";
        }
        return self::fingerprint(implode("\n", $parts));
    }

    private static function owner_has_exact_unsent_draft($connection, $draft_id)
    {
        global $wpdb;
        $draft_sha256 = self::fingerprint((string) $draft_id);
        $draft_job = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM " . self::jobs_table() . " WHERE connection_id = %d AND job_type = 'gmail_draft_create' AND status = 'SUCCEEDED' AND provider_resource_id_sha256 = %s LIMIT 1",
            absint($connection["id"] ?? 0),
            $draft_sha256
        ));
        if (absint($draft_job) <= 0) {
            return false;
        }
        $send_target = self::job_target_fingerprint("gmail_send_approved_draft", array(
            "account_email" => self::normalize_email(self::open((string) ($connection["account_email_ciphertext"] ?? ""))),
            "draft_id" => (string) $draft_id,
        ));
        if ($send_target === "") {
            return false;
        }
        $existing_send = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM " . self::jobs_table() . " WHERE connection_id = %d AND job_type = 'gmail_send_approved_draft' AND target_fingerprint_sha256 = %s AND status IN ('PENDING','CLAIMED','SUCCEEDED','UNKNOWN') LIMIT 1",
            absint($connection["id"] ?? 0),
            $send_target
        ));
        return absint($existing_send) <= 0;
    }

    private static function validate_live_job_binding($job)
    {
        if (!is_array($job)) {
            return array("ok" => false, "reason" => "JOB_RECORD_INVALID", "http_status" => 403);
        }
        $connection = self::connection_by_database_id(absint($job["connection_id"] ?? 0));
        if (!$connection) {
            return array("ok" => false, "reason" => "JOB_CONNECTION_NOT_FOUND", "http_status" => 403);
        }
        foreach (array("owner_binding_sha256", "agent_id", "agent_slug", "passport_public_id") as $key) {
            if ((string) ($job[$key] ?? "") !== (string) ($connection[$key] ?? "")) {
                return array("ok" => false, "reason" => "JOB_CONNECTION_BINDING_DRIFT", "http_status" => 403);
            }
        }
        $authority_json = self::open((string) ($job["authority_ciphertext"] ?? ""));
        $authority = $authority_json !== "" ? json_decode($authority_json, true) : null;
        if (!is_array($authority)
            || !hash_equals((string) ($job["authority_sha256"] ?? ""), self::fingerprint($authority_json))
            || (string) ($authority["contract_version"] ?? "") !== self::AUTHORITY_CONTRACT
            || (string) ($authority["job_binding"]["job_id"] ?? "") !== (string) ($job["job_public_id"] ?? "")
            || (string) ($authority["job_binding"]["job_type"] ?? "") !== (string) ($job["job_type"] ?? "")
            || (string) ($authority["job_binding"]["payload_sha256"] ?? "") !== (string) ($job["payload_sha256"] ?? "")
            || (string) ($authority["agent"]["owner_binding_id"] ?? "") !== (string) ($job["owner_binding_sha256"] ?? "")
            || (string) ($authority["agent"]["passport_public_id"] ?? "") !== (string) ($job["passport_public_id"] ?? "")
            || (string) ($authority["capability"]["target_fingerprint_sha256"] ?? "") !== (string) ($job["target_fingerprint_sha256"] ?? "")
            || (string) ($authority["capability"]["scope"] ?? "") !== (string) ($job["required_scope"] ?? "")
            || (string) ($authority["run_lease"]["run_lease_id"] ?? "") !== (string) ($job["run_lease_public_id"] ?? "")
            || absint($authority["run_lease"]["remaining_actions"] ?? 0) !== 1
            || strtotime((string) ($job["run_lease_expires_at"] ?? "") . " UTC") <= time()) {
            return array("ok" => false, "reason" => "JOB_AUTHORITY_NOT_LIVE", "http_status" => 403);
        }
        $job_type = (string) $job["job_type"];
        $status = (string) $connection["status"];
        if ($job_type === "gmail_disconnect") {
            if ($status !== "REVOKE_QUEUED") {
                return array("ok" => false, "reason" => "GMAIL_REVOKE_CONNECTION_STATE_INVALID", "http_status" => 409);
            }
            return array(
                "ok" => true,
                "connection" => $connection,
                "cleanup_only" => true,
                "passport_authority_used" => false,
            );
        }
        $binding = self::agent_binding_by_slug((string) $job["agent_slug"]);
        if (empty($binding["ok"]) || absint($binding["agent_id"] ?? 0) !== absint($job["agent_id"])) {
            return array("ok" => false, "reason" => "JOB_AGENT_BINDING_NOT_LIVE", "http_status" => 403);
        }
        $binding["owner_session_type"] = (string) $connection["owner_session_type"];
        if (!hash_equals((string) $connection["owner_binding_sha256"], self::owner_binding_fingerprint($binding))) {
            return array("ok" => false, "reason" => "JOB_OWNER_BINDING_NOT_LIVE", "http_status" => 403);
        }
        $passport = self::passport_guard($binding, "trustbridge_worker_" . (string) $job["job_type"]);
        if (empty($passport["ok"]) || (string) $passport["passport_public_id"] !== (string) $job["passport_public_id"]) {
            return array("ok" => false, "reason" => "JOB_PASSPORT_NOT_LIVE", "http_status" => 403);
        }
        if ($job_type === "gmail_oauth_start" && $status !== "QUEUED_OAUTH_START") {
            return array("ok" => false, "reason" => "OAUTH_START_CONNECTION_STATE_INVALID", "http_status" => 409);
        }
        if ($job_type === "gmail_oauth_complete" && $status !== "OAUTH_CALLBACK_RECEIVED") {
            return array("ok" => false, "reason" => "OAUTH_COMPLETE_CONNECTION_STATE_INVALID", "http_status" => 409);
        }
        if (in_array($job_type, array("gmail_search", "gmail_thread_read", "gmail_draft_create", "gmail_send_approved_draft"), true)) {
            if ($status !== "CONNECTED_READ_COMPOSE") {
                return array("ok" => false, "reason" => "GMAIL_CONNECTION_NOT_ACTIVE", "http_status" => 409);
            }
            $capabilities = self::decode_string_array((string) $connection["capabilities_json"]);
            if ($job_type !== "gmail_send_approved_draft"
                && !in_array((string) $job["required_scope"], $capabilities, true)) {
                return array("ok" => false, "reason" => "GMAIL_JOB_CAPABILITY_REVOKED", "http_status" => 403);
            }
            if ($job_type === "gmail_send_approved_draft"
                && (empty($job["action_approval_public_id"])
                    || empty($job["dispatch_reservation_public_id"])
                    || (string) ($authority["action_approval"]["policy"] ?? "") !== "allow_once"
                    || (string) ($authority["action_approval"]["status"] ?? "") !== "approved")) {
                return array("ok" => false, "reason" => "GMAIL_SEND_APPROVAL_NOT_LIVE", "http_status" => 403);
            }
        }
        return array(
            "ok" => true,
            "connection" => $connection,
            "binding" => $binding,
            "passport" => $passport,
            "authority" => $authority,
        );
    }

    private static function connection_by_database_id($id)
    {
        global $wpdb;
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM " . self::connections_table() . " WHERE id = %d LIMIT 1",
            absint($id)
        ), ARRAY_A);
        return is_array($row) ? $row : null;
    }

    private static function result_has_exact_keys($result, $expected_keys)
    {
        if (!is_array($result)) {
            return false;
        }
        $actual = array_map("strval", array_keys($result));
        $expected = array_map("strval", (array) $expected_keys);
        sort($actual, SORT_STRING);
        sort($expected, SORT_STRING);
        return $actual === $expected;
    }

    private static function apply_successful_job_to_connection($job, $connection, $result)
    {
        global $wpdb;
        $job_type = (string) $job["job_type"];
        $now = current_time("mysql", true);
        if ($job_type === "gmail_oauth_start") {
            if (!self::result_has_exact_keys($result, array(
                "status", "account_email", "auth_url", "auth_url_sha256",
                "provider_token_exposed", "write_enabled",
            ))) {
                return array("ok" => false, "reason" => "OAUTH_START_RESULT_FIELDS_INVALID", "http_status" => 400);
            }
            $auth_url = isset($result["auth_url"]) ? trim((string) $result["auth_url"]) : "";
            $account = self::normalize_email((string) ($result["account_email"] ?? ""));
            $expected = self::normalize_email(self::open((string) $connection["account_email_ciphertext"]));
            $parts = wp_parse_url($auth_url);
            if ((string) ($result["status"] ?? "") !== "awaiting_owner_consent"
                || $account === "" || $account !== $expected || !is_array($parts)
                || strtolower((string) ($parts["scheme"] ?? "")) !== "https"
                || strtolower((string) ($parts["host"] ?? "")) !== "accounts.google.com"
                || !array_key_exists("provider_token_exposed", $result) || $result["provider_token_exposed"] !== false
                || !array_key_exists("write_enabled", $result) || $result["write_enabled"] !== false
                || (string) ($result["auth_url_sha256"] ?? "") !== self::fingerprint($auth_url)) {
                return array("ok" => false, "reason" => "OAUTH_START_RESULT_INVALID", "http_status" => 400);
            }
            parse_str((string) ($parts["query"] ?? ""), $query);
            $state = isset($query["state"]) ? (string) $query["state"] : "";
            $redirect_uri = isset($query["redirect_uri"]) ? (string) $query["redirect_uri"] : "";
            $challenge = isset($query["code_challenge"]) ? (string) $query["code_challenge"] : "";
            $challenge_method = isset($query["code_challenge_method"]) ? (string) $query["code_challenge_method"] : "";
            if (strlen($state) < 16 || strlen($state) > 2048
                || $redirect_uri !== self::CALLBACK_URI
                || $challenge_method !== "S256"
                || !preg_match('/^[A-Za-z0-9._~-]{43,128}$/', $challenge)) {
                return array("ok" => false, "reason" => "OAUTH_START_PKCE_OR_CALLBACK_INVALID", "http_status" => 400);
            }
            $sealed_url = self::seal($auth_url);
            if ($sealed_url === "") {
                return array("ok" => false, "reason" => "OAUTH_AUTHORIZATION_URL_ENCRYPTION_FAILED", "http_status" => 503);
            }
            $updated = $wpdb->update(self::connections_table(), array(
                "status" => "AWAITING_OWNER_CONSENT",
                "authorization_url_ciphertext" => $sealed_url,
                "oauth_state_sha256" => hash("sha256", $state),
                "oauth_state_expires_at" => gmdate("Y-m-d H:i:s", time() + self::OAUTH_JOB_TTL_SECONDS),
                "worker_id" => sanitize_text_field((string) $job["worker_id"]),
                "last_error_code" => null,
                "updated_at" => $now,
            ), array("id" => absint($connection["id"]), "status" => "QUEUED_OAUTH_START"));
            if ($updated !== 1) {
                return array("ok" => false, "reason" => "OAUTH_START_CONNECTION_UPDATE_FAILED", "http_status" => 503);
            }
            return array("ok" => true);
        }
        if ($job_type === "gmail_oauth_complete") {
            if (!self::result_has_exact_keys($result, array(
                "status", "account_email", "account_fingerprint_sha256",
                "token_stored_in_agent_keyring", "provider_token_exposed",
                "draft_enabled", "owner_approved_send_enabled",
                "mailbox_delete_enabled",
            ))) {
                return array("ok" => false, "reason" => "OAUTH_COMPLETE_RESULT_FIELDS_INVALID", "http_status" => 400);
            }
            $account = self::normalize_email((string) ($result["account_email"] ?? ""));
            $expected = self::normalize_email(self::open((string) $connection["account_email_ciphertext"]));
            if ((string) ($result["status"] ?? "") !== "connected_read_compose" || $account === "" || $account !== $expected
                || $expected === ""
                || (string) ($result["account_fingerprint_sha256"] ?? "") !== self::fingerprint($account)
                || !array_key_exists("token_stored_in_agent_keyring", $result) || $result["token_stored_in_agent_keyring"] !== true
                || !array_key_exists("provider_token_exposed", $result) || $result["provider_token_exposed"] !== false
                || !array_key_exists("draft_enabled", $result) || $result["draft_enabled"] !== true
                || !array_key_exists("owner_approved_send_enabled", $result) || $result["owner_approved_send_enabled"] !== true
                || !array_key_exists("mailbox_delete_enabled", $result) || $result["mailbox_delete_enabled"] !== false) {
                return array("ok" => false, "reason" => "OAUTH_COMPLETE_RESULT_INVALID", "http_status" => 400);
            }
            $updated = $wpdb->update(self::connections_table(), array(
                "status" => "CONNECTED_READ_COMPOSE",
                "account_email_sha256" => self::fingerprint($account),
                "account_email_masked" => self::mask_email($account),
                "oauth_state_sha256" => null,
                "oauth_state_expires_at" => null,
                "authorization_url_ciphertext" => null,
                "worker_id" => sanitize_text_field((string) $job["worker_id"]),
                "last_error_code" => null,
                "connected_at" => $now,
                "updated_at" => $now,
            ), array("id" => absint($connection["id"]), "status" => "OAUTH_CALLBACK_RECEIVED"));
            if ($updated !== 1) {
                return array("ok" => false, "reason" => "OAUTH_COMPLETE_CONNECTION_UPDATE_FAILED", "http_status" => 503);
            }
            return array("ok" => true);
        }
        if ($job_type === "gmail_search" || $job_type === "gmail_thread_read") {
            $expected_keys = array(
                "status", "operation", "account_fingerprint_sha256", "result",
                "remote_content_untrusted", "remote_content_executed", "write_enabled",
            );
            if ($job_type === "gmail_thread_read") {
                $expected_keys[] = "attachments_downloaded";
            }
            if (!self::result_has_exact_keys($result, $expected_keys)) {
                return array("ok" => false, "reason" => "GMAIL_READ_RESULT_FIELDS_INVALID", "http_status" => 400);
            }
            $expected = self::normalize_email(self::open((string) $connection["account_email_ciphertext"]));
            $expected_operation = $job_type === "gmail_search" ? "gmail_search" : "gmail_thread_read";
            if ((string) ($result["status"] ?? "") !== "completed"
                || (string) ($result["operation"] ?? "") !== $expected_operation
                || !array_key_exists("remote_content_untrusted", $result) || $result["remote_content_untrusted"] !== true
                || $expected === ""
                || (string) ($result["account_fingerprint_sha256"] ?? "") !== self::fingerprint($expected)
                || !array_key_exists("remote_content_executed", $result) || $result["remote_content_executed"] !== false
                || !array_key_exists("write_enabled", $result) || $result["write_enabled"] !== false
                || ($job_type === "gmail_thread_read"
                    && (!array_key_exists("attachments_downloaded", $result) || $result["attachments_downloaded"] !== false))) {
                return array("ok" => false, "reason" => "GMAIL_READ_RESULT_CONTRACT_INVALID", "http_status" => 400);
            }
            return array("ok" => true);
        }
        if ($job_type === "gmail_draft_create") {
            if (!self::result_has_exact_keys($result, array(
                "status", "operation", "account_fingerprint_sha256",
                "draft_id", "draft_id_sha256", "provider_response_exposed",
                "sent", "mailbox_delete_enabled",
            ))) {
                return array("ok" => false, "reason" => "GMAIL_DRAFT_RESULT_FIELDS_INVALID", "http_status" => 400);
            }
            $expected_account = self::normalize_email(self::open((string) $connection["account_email_ciphertext"]));
            $draft_id = (string) ($result["draft_id"] ?? "");
            if ((string) ($result["status"] ?? "") !== "draft_created"
                || (string) ($result["operation"] ?? "") !== "gmail_draft_create"
                || $expected_account === ""
                || (string) ($result["account_fingerprint_sha256"] ?? "") !== self::fingerprint($expected_account)
                || !preg_match('/^[A-Za-z0-9_-]{1,256}$/', $draft_id)
                || (string) ($result["draft_id_sha256"] ?? "") !== self::fingerprint($draft_id)
                || ($result["provider_response_exposed"] ?? null) !== false
                || ($result["sent"] ?? null) !== false
                || ($result["mailbox_delete_enabled"] ?? null) !== false) {
                return array("ok" => false, "reason" => "GMAIL_DRAFT_RESULT_INVALID", "http_status" => 400);
            }
            return array("ok" => true);
        }
        if ($job_type === "gmail_send_approved_draft") {
            if (!self::result_has_exact_keys($result, array(
                "status", "operation", "account_fingerprint_sha256",
                "draft_id_sha256", "message_id", "message_id_sha256",
                "provider_response_exposed", "owner_approval_consumed",
                "provider_attempt_count", "automatic_retry_attempted",
                "exactly_once_effect_claimed", "mailbox_delete_enabled",
            ))) {
                return array("ok" => false, "reason" => "GMAIL_SEND_RESULT_FIELDS_INVALID", "http_status" => 400);
            }
            $expected_account = self::normalize_email(self::open((string) $connection["account_email_ciphertext"]));
            $payload_json = self::open((string) ($job["payload_ciphertext"] ?? ""));
            $payload = $payload_json !== "" ? json_decode($payload_json, true) : null;
            $draft_id = is_array($payload) ? (string) ($payload["draft_id"] ?? "") : "";
            $message_id = (string) ($result["message_id"] ?? "");
            if ((string) ($result["status"] ?? "") !== "sent"
                || (string) ($result["operation"] ?? "") !== "gmail_send_approved_draft"
                || $expected_account === ""
                || (string) ($result["account_fingerprint_sha256"] ?? "") !== self::fingerprint($expected_account)
                || !preg_match('/^[A-Za-z0-9_-]{1,256}$/', $draft_id)
                || (string) ($result["draft_id_sha256"] ?? "") !== self::fingerprint($draft_id)
                || !preg_match('/^[A-Za-z0-9_-]{1,256}$/', $message_id)
                || (string) ($result["message_id_sha256"] ?? "") !== self::fingerprint($message_id)
                || ($result["provider_response_exposed"] ?? null) !== false
                || ($result["owner_approval_consumed"] ?? null) !== true
                || absint($result["provider_attempt_count"] ?? 0) !== 1
                || ($result["automatic_retry_attempted"] ?? null) !== false
                || ($result["exactly_once_effect_claimed"] ?? null) !== false
                || ($result["mailbox_delete_enabled"] ?? null) !== false) {
                return array("ok" => false, "reason" => "GMAIL_SEND_RESULT_INVALID", "http_status" => 400);
            }
            return array("ok" => true);
        }
        if ($job_type === "gmail_disconnect") {
            if (!self::result_has_exact_keys($result, array(
                "status", "account_fingerprint_sha256",
                "token_removed_from_agent_keyring", "provider_token_exposed",
                "write_enabled",
            ))) {
                return array("ok" => false, "reason" => "GMAIL_DISCONNECT_RESULT_FIELDS_INVALID", "http_status" => 400);
            }
            $expected = self::normalize_email(self::open((string) $connection["account_email_ciphertext"]));
            if ((string) ($result["status"] ?? "") !== "disconnected" || $expected === ""
                || (string) ($result["account_fingerprint_sha256"] ?? "") !== self::fingerprint($expected)
                || !array_key_exists("token_removed_from_agent_keyring", $result) || $result["token_removed_from_agent_keyring"] !== true
                || !array_key_exists("provider_token_exposed", $result) || $result["provider_token_exposed"] !== false
                || !array_key_exists("write_enabled", $result) || $result["write_enabled"] !== false) {
                return array("ok" => false, "reason" => "GMAIL_DISCONNECT_RESULT_INVALID", "http_status" => 400);
            }
            $updated = $wpdb->update(self::connections_table(), array(
                "status" => "REVOKED",
                "capabilities_json" => "[]",
                "revoked_at" => $now,
                "updated_at" => $now,
            ), array("id" => absint($connection["id"]), "status" => "REVOKE_QUEUED"));
            if ($updated !== 1) {
                return array("ok" => false, "reason" => "GMAIL_DISCONNECT_CONNECTION_UPDATE_FAILED", "http_status" => 503);
            }
            return array("ok" => true);
        }
        return array("ok" => false, "reason" => "JOB_RESULT_TYPE_UNSUPPORTED", "http_status" => 400);
    }

    private static function apply_failed_job_to_connection($job, $error_code)
    {
        if (!in_array((string) $job["job_type"], array("gmail_oauth_start", "gmail_oauth_complete", "gmail_disconnect"), true)) {
            return true;
        }
        global $wpdb;
        $job_type = (string) $job["job_type"];
        $status = $job_type === "gmail_disconnect" ? "REVOKED_ACCESS_BLOCKED" : "FAILED";
        $expected_status = array(
            "gmail_oauth_start" => "QUEUED_OAUTH_START",
            "gmail_oauth_complete" => "OAUTH_CALLBACK_RECEIVED",
            "gmail_disconnect" => "REVOKE_QUEUED",
        );
        $values = array(
            "status" => $status,
            "last_error_code" => sanitize_text_field((string) $error_code),
            "updated_at" => current_time("mysql", true),
        );
        if ($status === "REVOKED_ACCESS_BLOCKED") {
            $values["revoked_at"] = current_time("mysql", true);
            $values["capabilities_json"] = "[]";
        }
        $updated = $wpdb->update(self::connections_table(), $values, array(
            "id" => absint($job["connection_id"]),
            "status" => $expected_status[$job_type],
        ));
        return $updated === 1;
    }

    private static function record_successful_job($job, $connection, $result, $result_json, $worker)
    {
        global $wpdb;
        if ($wpdb->query("START TRANSACTION") === false) {
            return array("ok" => false, "reason" => "JOB_ATOMIC_TRANSACTION_START_FAILED", "http_status" => 503);
        }
        $applied = self::apply_successful_job_to_connection($job, $connection, $result);
        if (empty($applied["ok"])) {
            $wpdb->query("ROLLBACK");
            return $applied;
        }
        if (!self::terminalize_job($job, "SUCCEEDED", "", $result_json, $worker, 1)) {
            $wpdb->query("ROLLBACK");
            return array("ok" => false, "reason" => "JOB_ATOMIC_TERMINAL_RECORD_FAILED", "http_status" => 503);
        }
        if ($wpdb->query("COMMIT") === false) {
            $wpdb->query("ROLLBACK");
            return array("ok" => false, "reason" => "JOB_ATOMIC_COMMIT_FAILED", "http_status" => 503);
        }
        return array("ok" => true);
    }

    private static function record_failed_job($job, $error_code, $worker, $provider_attempt_count = 0)
    {
        global $wpdb;
        if ($wpdb->query("START TRANSACTION") === false) {
            return false;
        }
        if (!self::apply_failed_job_to_connection($job, $error_code)
            || !self::terminalize_job($job, "FAILED", $error_code, null, $worker, $provider_attempt_count)) {
            $wpdb->query("ROLLBACK");
            return false;
        }
        if ($wpdb->query("COMMIT") === false) {
            $wpdb->query("ROLLBACK");
            return false;
        }
        return true;
    }

    private static function record_unknown_job($job, $error_code, $worker)
    {
        global $wpdb;
        if ($wpdb->query("START TRANSACTION") === false) {
            return false;
        }
        if (!self::terminalize_job($job, "UNKNOWN", $error_code, null, $worker, 1)) {
            $wpdb->query("ROLLBACK");
            return false;
        }
        if ($wpdb->query("COMMIT") === false) {
            $wpdb->query("ROLLBACK");
            return false;
        }
        return true;
    }

    private static function terminalize_job($job, $status, $error_code, $result_json, $worker, $provider_attempt_count = 0)
    {
        global $wpdb;
        $sealed_result = is_string($result_json) && $result_json !== "" ? self::seal($result_json) : null;
        if (is_string($result_json) && $result_json !== "" && $sealed_result === "") {
            return false;
        }
        $result_hash = is_string($result_json) && $result_json !== "" ? self::fingerprint($result_json) : null;
        $values = array(
            "status" => $status,
            "result_ciphertext" => $sealed_result,
            "result_sha256" => $result_hash,
            "provider_attempt_count" => max(0, min(1, absint($provider_attempt_count))),
            "error_code" => $error_code !== "" ? sanitize_text_field((string) $error_code) : null,
            "completed_at" => current_time("mysql", true),
            "updated_at" => current_time("mysql", true),
        );
        if ($status === "SUCCEEDED"
            && (string) ($job["job_type"] ?? "") === "gmail_draft_create"
            && is_string($result_json)) {
            $decoded_result = json_decode($result_json, true);
            $draft_id = is_array($decoded_result) ? (string) ($decoded_result["draft_id"] ?? "") : "";
            if (!preg_match('/^[A-Za-z0-9_-]{1,256}$/', $draft_id)) {
                return false;
            }
            $values["provider_resource_id_sha256"] = self::fingerprint($draft_id);
        }
        $updated = $wpdb->update(self::jobs_table(), $values, array("id" => absint($job["id"]), "status" => "CLAIMED"));
        if ($updated !== 1) {
            return false;
        }
        return self::create_receipt($job, $status, $error_code, $result_hash, (string) ($worker["worker_id"] ?? ""));
    }

    private static function create_receipt($job, $outcome, $error_code, $result_hash, $worker_id)
    {
        $connection = self::connection_by_database_id(absint($job["connection_id"]));
        if (!$connection) {
            return false;
        }
        $receipt = array(
            "contract_version" => "noderooms-trustbridge-receipt.v1",
            "receipt_id" => self::public_id("nrtbr_"),
            "job_id" => (string) $job["job_public_id"],
            "connection_id" => (string) $connection["connection_public_id"],
            "owner_binding_sha256" => (string) $job["owner_binding_sha256"],
            "agent_id" => absint($job["agent_id"]),
            "agent_slug" => (string) $job["agent_slug"],
            "passport_public_id" => (string) $job["passport_public_id"],
            "required_scope" => (string) $job["required_scope"],
            "payload_sha256" => (string) $job["payload_sha256"],
            "result_sha256" => $result_hash,
            "outcome" => $outcome,
            "error_code" => $error_code !== "" ? (string) $error_code : null,
            "worker_id_sha256" => self::fingerprint($worker_id),
            "created_at" => gmdate("c"),
            "provider_token_included" => false,
            "mailbox_content_included" => false,
        );
        $json = wp_json_encode($receipt, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            return false;
        }
        $key = self::receipt_key();
        if ($key === "") {
            return false;
        }
        global $wpdb;
        $inserted = $wpdb->insert(self::receipts_table(), array(
            "receipt_public_id" => (string) $receipt["receipt_id"],
            "job_public_id" => (string) $job["job_public_id"],
            "connection_public_id" => (string) $connection["connection_public_id"],
            "owner_binding_sha256" => (string) $job["owner_binding_sha256"],
            "agent_id" => absint($job["agent_id"]),
            "agent_slug" => (string) $job["agent_slug"],
            "passport_public_id" => (string) $job["passport_public_id"],
            "required_scope" => (string) $job["required_scope"],
            "payload_sha256" => (string) $job["payload_sha256"],
            "result_sha256" => $result_hash,
            "outcome" => $outcome,
            "error_code" => $error_code !== "" ? (string) $error_code : null,
            "worker_id" => sanitize_text_field($worker_id),
            "receipt_json" => $json,
            "receipt_hmac_sha256" => hash_hmac("sha256", $json, $key),
            "created_at" => current_time("mysql", true),
        ));
        return $inserted === 1;
    }

    private static function fail_unclaimed_job($job, $reason)
    {
        global $wpdb;
        $wpdb->update(self::jobs_table(), array(
            "status" => "FAILED",
            "error_code" => strtoupper(sanitize_key($reason)),
            "completed_at" => current_time("mysql", true),
            "updated_at" => current_time("mysql", true),
        ), array("id" => absint($job["id"]), "status" => "PENDING"));
    }

    private static function worker_guard($request)
    {
        $runtime = self::runtime_guard();
        if (empty($runtime["ok"])) {
            return $runtime;
        }
        $worker_id = trim((string) $request->get_header("x-noderooms-worker-id"));
        $timestamp = trim((string) $request->get_header("x-noderooms-worker-timestamp"));
        $nonce = strtolower(trim((string) $request->get_header("x-noderooms-worker-nonce")));
        $signature_b64url = trim((string) $request->get_header("x-noderooms-worker-signature"));
        if (!preg_match('/^nrtbw_[a-f0-9]{32}$/', $worker_id)
            || !preg_match('/^[0-9]{10,13}$/', $timestamp)
            || !preg_match('/^[a-f0-9]{32,128}$/', $nonce)
            || !preg_match('/^[A-Za-z0-9_-]{86}$/', $signature_b64url)) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_WORKER_HEADERS_INVALID", "http_status" => 403);
        }
        if (abs(time() - (int) $timestamp) > self::WORKER_CLOCK_SKEW_SECONDS) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_WORKER_TIMESTAMP_STALE", "http_status" => 403);
        }
        $worker = self::worker_by_public_id($worker_id);
        if (!$worker
            || (string) $worker["status"] !== "ACTIVE"
            || !hash_equals(self::REQUIRED_WORKER_VERSION, (string) ($worker["worker_version"] ?? ""))) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_WORKER_NOT_ACTIVE", "http_status" => 403);
        }
        $route = (string) $request->get_route();
        $path = "/wp-json" . $route;
        $body = (string) $request->get_body();
        if (strlen($body) > self::MAX_WORKER_REQUEST_BYTES) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_WORKER_REQUEST_TOO_LARGE", "http_status" => 413);
        }
        $canonical = implode("\n", array(
            strtoupper((string) $request->get_method()),
            $path,
            $timestamp,
            $nonce,
            hash("sha256", $body),
        ));
        $signature = self::base64url_decode($signature_b64url);
        $public_key = self::base64url_decode((string) $worker["public_key_b64url"]);
        if (!is_string($signature) || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES
            || !is_string($public_key) || strlen($public_key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            || !sodium_crypto_sign_verify_detached($signature, $canonical, $public_key)) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_WORKER_SIGNATURE_INVALID", "http_status" => 403);
        }
        global $wpdb;
        $wpdb->query($wpdb->prepare(
            "DELETE FROM " . self::worker_nonces_table() . " WHERE expires_at <= %s",
            current_time("mysql", true)
        ));
        $nonce_inserted = $wpdb->insert(self::worker_nonces_table(), array(
            "nonce_sha256" => hash("sha256", $worker_id . "|" . $nonce),
            "worker_id" => $worker_id,
            "expires_at" => gmdate("Y-m-d H:i:s", time() + (self::WORKER_CLOCK_SKEW_SECONDS * 2)),
            "created_at" => current_time("mysql", true),
        ));
        if ($nonce_inserted !== 1) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_WORKER_NONCE_REPLAYED", "http_status" => 409);
        }
        $json = self::request_json($request);
        if (sanitize_text_field((string) ($json["worker_id"] ?? "")) !== $worker_id
            || sanitize_text_field((string) ($json["worker_binding_id"] ?? "")) !== (string) $worker["worker_binding_public_id"]) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_WORKER_BODY_ID_MISMATCH", "http_status" => 403);
        }
        $binding = self::agent_binding_by_slug((string) $worker["agent_slug"]);
        if (empty($binding["ok"])
            || absint($binding["agent_id"] ?? 0) !== absint($worker["agent_id"])
            || !hash_equals((string) $worker["owner_binding_sha256"], self::owner_binding_fingerprint($binding))) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_WORKER_OWNER_BINDING_NOT_LIVE", "http_status" => 403);
        }
        $passport = self::passport_guard($binding, "trustbridge_worker_request");
        if (empty($passport["ok"]) || (string) $passport["passport_public_id"] !== (string) $worker["passport_public_id"]) {
            return array("ok" => false, "reason" => "TRUSTBRIDGE_WORKER_PASSPORT_NOT_LIVE", "http_status" => 403);
        }
        global $wpdb;
        $wpdb->update(self::workers_table(), array(
            "last_seen_at" => current_time("mysql", true),
        ), array("id" => absint($worker["id"]), "status" => "ACTIVE"));
        return array(
            "ok" => true,
            "worker_id" => $worker_id,
            "worker_binding_id" => (string) $worker["worker_binding_public_id"],
            "owner_binding_sha256" => (string) $worker["owner_binding_sha256"],
            "agent_id" => absint($worker["agent_id"]),
            "agent_slug" => (string) $worker["agent_slug"],
            "passport_public_id" => (string) $worker["passport_public_id"],
        );
    }

    private static function storage_key()
    {
        $configured = defined(self::STORAGE_KEY_CONSTANT) ? (string) constant(self::STORAGE_KEY_CONSTANT) : "";
        if ($configured === "") {
            $configured = wp_salt("secure_auth") . "|" . wp_salt("auth") . "|noderooms-trustbridge-storage-v1";
        }
        return hash("sha256", $configured, true);
    }

    private static function receipt_key()
    {
        $configured = defined(self::RECEIPT_KEY_CONSTANT) ? (string) constant(self::RECEIPT_KEY_CONSTANT) : "";
        if ($configured === "") {
            $configured = wp_salt("logged_in") . "|" . wp_salt("nonce") . "|noderooms-trustbridge-receipt-v1";
        }
        return strlen($configured) >= 32 ? $configured : "";
    }

    private static function seal($plaintext)
    {
        $plaintext = (string) $plaintext;
        if ($plaintext === "") {
            return "";
        }
        $key = self::storage_key();
        if (function_exists("sodium_crypto_secretbox") && function_exists("sodium_crypto_secretbox_keygen")) {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
            return "nrtb1.sodium." . base64_encode($nonce . $ciphertext);
        }
        if (function_exists("openssl_encrypt")) {
            $iv = random_bytes(12);
            $tag = "";
            $ciphertext = openssl_encrypt($plaintext, "aes-256-gcm", $key, OPENSSL_RAW_DATA, $iv, $tag, "noderooms-trustbridge-v1", 16);
            if (is_string($ciphertext) && strlen($tag) === 16) {
                return "nrtb1.aesgcm." . base64_encode($iv . $tag . $ciphertext);
            }
        }
        return "";
    }

    private static function open($sealed)
    {
        $sealed = (string) $sealed;
        $key = self::storage_key();
        if (strpos($sealed, "nrtb1.sodium.") === 0 && function_exists("sodium_crypto_secretbox_open")) {
            $raw = base64_decode(substr($sealed, strlen("nrtb1.sodium.")), true);
            if (!is_string($raw) || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
                return "";
            }
            $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $ciphertext = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
            return is_string($plaintext) ? $plaintext : "";
        }
        if (strpos($sealed, "nrtb1.aesgcm.") === 0 && function_exists("openssl_decrypt")) {
            $raw = base64_decode(substr($sealed, strlen("nrtb1.aesgcm.")), true);
            if (!is_string($raw) || strlen($raw) <= 28) {
                return "";
            }
            $iv = substr($raw, 0, 12);
            $tag = substr($raw, 12, 16);
            $ciphertext = substr($raw, 28);
            $plaintext = openssl_decrypt($ciphertext, "aes-256-gcm", $key, OPENSSL_RAW_DATA, $iv, $tag, "noderooms-trustbridge-v1");
            return is_string($plaintext) ? $plaintext : "";
        }
        return "";
    }

    private static function contains_secret_material($value, $allow_auth_url)
    {
        if (!is_array($value)) {
            return false;
        }
        $blocked = array(
            "access_token", "refresh_token", "id_token", "client_secret",
            "authorization_code", "code_verifier", "password",
            "authorization", "cookie", "lease_token",
        );
        foreach ($value as $key => $entry) {
            $normalized = strtolower((string) $key);
            if (in_array($normalized, $blocked, true)) {
                return true;
            }
            if ($normalized === "auth_url" && !$allow_auth_url) {
                return true;
            }
            if (is_array($entry) && self::contains_secret_material($entry, $allow_auth_url)) {
                return true;
            }
            if (is_string($entry) && preg_match('/^Bearer\s+/i', $entry)) {
                return true;
            }
        }
        return false;
    }

    private static function public_connection($row, $include_authorization_url)
    {
        if (!is_array($row)) {
            return null;
        }
        $authorization_url = "";
        if ($include_authorization_url && (string) ($row["status"] ?? "") === "AWAITING_OWNER_CONSENT") {
            $candidate = self::open((string) ($row["authorization_url_ciphertext"] ?? ""));
            $parts = wp_parse_url($candidate);
            if (is_array($parts) && strtolower((string) ($parts["scheme"] ?? "")) === "https" && strtolower((string) ($parts["host"] ?? "")) === "accounts.google.com") {
                $authorization_url = $candidate;
            }
        }
        return array(
            "connection_id" => (string) ($row["connection_public_id"] ?? ""),
            "provider" => "gmail",
            "agent_slug" => (string) ($row["agent_slug"] ?? ""),
            "passport_public_id" => (string) ($row["passport_public_id"] ?? ""),
            "account_email_masked" => (string) ($row["account_email_masked"] ?? ""),
            "status" => (string) ($row["status"] ?? ""),
            "granted_scopes" => self::decode_string_array((string) ($row["capabilities_json"] ?? "[]")),
            "authorization_url" => $authorization_url,
            "last_error_code" => sanitize_text_field((string) ($row["last_error_code"] ?? "")),
            "connected_at" => (string) ($row["connected_at"] ?? ""),
            "updated_at" => (string) ($row["updated_at"] ?? ""),
            "provider_token_stored_by_noderooms" => false,
            "draft_creation_live" => true,
            "send_policy" => "exact_draft_allow_once_verified_owner_approval",
            "direct_send_allowed" => false,
            "delete_allowed" => false,
        );
    }

    private static function public_job($row, $include_result)
    {
        if (!is_array($row)) {
            return null;
        }
        $result = null;
        if ($include_result && (string) ($row["status"] ?? "") === "SUCCEEDED" && !empty($row["result_ciphertext"])) {
            $json = self::open((string) $row["result_ciphertext"]);
            if ($json !== "" && self::fingerprint($json) === (string) ($row["result_sha256"] ?? "")) {
                $decoded = json_decode($json, true);
                if (is_array($decoded)) {
                    $result = $decoded;
                }
            }
        }
        return array(
            "job_id" => (string) ($row["job_public_id"] ?? ""),
            "action" => self::public_job_action((string) ($row["job_type"] ?? "")),
            "required_scope" => (string) ($row["required_scope"] ?? ""),
            "status" => (string) ($row["status"] ?? ""),
            "result" => $result,
            "error_code" => sanitize_text_field((string) ($row["error_code"] ?? "")),
            "expires_at" => self::mysql_to_iso((string) ($row["expires_at"] ?? "")),
            "created_at" => self::mysql_to_iso((string) ($row["created_at"] ?? "")),
            "completed_at" => self::mysql_to_iso((string) ($row["completed_at"] ?? "")),
            "one_action_run_lease" => true,
            "lease_secret_exposed" => false,
            "provider_token_exposed" => false,
        );
    }

    private static function public_job_action($job_type)
    {
        $map = array(
            "gmail_oauth_start" => "connect_prepare",
            "gmail_oauth_complete" => "connect_complete",
            "gmail_search" => "search",
            "gmail_thread_read" => "thread_read",
            "gmail_draft_create" => "draft_create",
            "gmail_send_approved_draft" => "send_approved_draft",
            "gmail_disconnect" => "disconnect",
        );
        return isset($map[$job_type]) ? $map[$job_type] : "unknown";
    }

    private static function public_agent($binding)
    {
        return array(
            "id" => absint($binding["agent_id"] ?? 0),
            "slug" => sanitize_title((string) ($binding["agent_slug"] ?? "")),
            "name" => sanitize_text_field((string) ($binding["agent_name"] ?? "")),
            "passport_public_id" => sanitize_text_field((string) ($binding["passport_public_id"] ?? "")),
            "owner_bound" => true,
        );
    }

    private static function gmail_capability_catalog()
    {
        return array(
            array("scope" => "connector.gmail.message.search", "label" => "Search email", "access" => "read", "live" => true),
            array("scope" => "connector.gmail.thread.read", "label" => "Read email threads", "access" => "read", "live" => true),
            array("scope" => "connector.gmail.draft.create", "label" => "Create drafts", "access" => "draft", "live" => true),
            array("scope" => "connector.gmail.draft.send", "label" => "Send exact approved draft", "access" => "allow_once", "live" => true, "reusable" => false),
            array("scope" => "connector.gmail.message.delete", "label" => "Delete or Trash", "access" => "prohibited", "live" => false, "permanently_denied" => true),
        );
    }

    private static function row_matches_owner($row, $owner)
    {
        return is_array($row)
            && hash_equals((string) ($row["owner_binding_sha256"] ?? ""), (string) ($owner["owner_binding_sha256"] ?? ""))
            && absint($row["agent_id"] ?? 0) === absint($owner["agent_id"] ?? 0)
            && (string) ($row["agent_slug"] ?? "") === (string) ($owner["agent_slug"] ?? "");
    }

    private static function request_json($request)
    {
        if ($request instanceof WP_REST_Request) {
            $body = $request->get_json_params();
            return is_array($body) ? $body : array();
        }
        return array();
    }

    private static function request_value($request, $key, $default = "")
    {
        if (!($request instanceof WP_REST_Request)) {
            return $default;
        }
        $value = $request->get_param($key);
        return $value === null ? $default : $value;
    }

    private static function request_string($request, $key)
    {
        $value = self::request_value($request, $key, "");
        return is_scalar($value) ? sanitize_text_field((string) $value) : "";
    }

    private static function normalize_email($email)
    {
        $email = strtolower(trim((string) $email));
        return $email !== "" && strlen($email) <= 254 && is_email($email) ? $email : "";
    }

    private static function mask_email($email)
    {
        $email = self::normalize_email($email);
        if ($email === "" || strpos($email, "@") === false) {
            return "";
        }
        list($local, $domain) = explode("@", $email, 2);
        $visible = substr($local, 0, min(2, strlen($local)));
        return $visible . str_repeat("*", max(3, strlen($local) - strlen($visible))) . "@" . $domain;
    }

    private static function decode_string_array($json)
    {
        $decoded = json_decode((string) $json, true);
        if (!is_array($decoded)) {
            return array();
        }
        $out = array();
        foreach ($decoded as $value) {
            $value = strtolower(trim((string) $value));
            if ($value !== "" && !in_array($value, $out, true)) {
                $out[] = $value;
            }
        }
        sort($out, SORT_STRING);
        return $out;
    }

    private static function fingerprint($value)
    {
        return "sha256:" . hash("sha256", (string) $value);
    }

    private static function public_id($prefix)
    {
        return (string) $prefix . bin2hex(random_bytes(16));
    }

    private static function random_token($bytes)
    {
        return rtrim(strtr(base64_encode(random_bytes(max(32, absint($bytes)))), "+/", "-_"), "=");
    }

    private static function base64url_encode($value)
    {
        return rtrim(strtr(base64_encode((string) $value), "+/", "-_"), "=");
    }

    private static function base64url_decode($value)
    {
        $value = trim((string) $value);
        if ($value === "" || !preg_match('/^[A-Za-z0-9_-]+$/', $value)) {
            return false;
        }
        $padding = strlen($value) % 4;
        if ($padding !== 0) {
            $value .= str_repeat("=", 4 - $padding);
        }
        return base64_decode(strtr($value, "-_", "+/"), true);
    }

    private static function gmail_oauth_scopes()
    {
        return array(
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.compose",
        );
    }

    private static function mysql_to_iso($value)
    {
        $timestamp = strtotime((string) $value . " UTC");
        return $timestamp > 0 ? gmdate("c", $timestamp) : "";
    }

    private static function is_truthy($value)
    {
        return in_array(strtolower(trim((string) $value)), array("1", "true", "yes", "on"), true);
    }

    private static function is_falsey($value)
    {
        return in_array(strtolower(trim((string) $value)), array("", "0", "false", "no", "off"), true);
    }

    private static function oauth_redirect($result)
    {
        $url = add_query_arg(array("nr_gmail" => sanitize_key($result)), home_url("/owner-dashboard/"));
        nocache_headers();
        wp_safe_redirect($url, 302, "NodeRooms TrustBridge");
        exit;
    }

    private static function rest_blocked($result)
    {
        $status = isset($result["http_status"]) ? absint($result["http_status"]) : 403;
        return new WP_REST_Response(array(
            "ok" => false,
            "reason" => sanitize_text_field((string) ($result["reason"] ?? "TRUSTBRIDGE_REQUEST_BLOCKED")),
            "provider_token_exposed" => false,
            "public_write_unlocked" => false,
            "status" => "NODEROOMS_TRUSTBRIDGE_FAIL_CLOSED",
        ), $status > 0 ? $status : 403);
    }

    private static function blocked_response($reason, $status)
    {
        return self::rest_blocked(array(
            "ok" => false,
            "reason" => $reason,
            "http_status" => $status,
        ));
    }
}
