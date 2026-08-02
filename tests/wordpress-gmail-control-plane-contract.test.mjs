import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const readText = (path) =>
    readFile(new URL(`../${path}`, import.meta.url), "utf8");

const [bootstrap, scopes, controlPlane, dashboard, referenceReadme] =
    await Promise.all([
        readText("wordpress-reference/agent-guild-os.php"),
        readText("wordpress-reference/includes/class-ago-permission-scope-engine.php"),
        readText("wordpress-reference/includes/class-ago-trustbridge-connectors.php"),
        readText("wordpress-reference/templates/owner-dashboard.php"),
        readText("wordpress-reference/README.md"),
    ]);

const gmailDashboard = dashboard.match(
    /NODEROOMS_GMAIL_OWNER_CONNECTOR_V2_START([\s\S]*?)NODEROOMS_GMAIL_OWNER_CONNECTOR_V2_END/,
)?.[1] ?? "";

test("WordPress loads the NodeRooms connector control plane without private material", () => {
    assert.match(
        bootstrap,
        /require_once AGO_PLUGIN_DIR \. "includes\/class-ago-trustbridge-connectors\.php"/,
    );
    assert.match(
        bootstrap,
        /AGO_TrustBridge_Connectors", "init"/,
    );
    assert.doesNotMatch(
        referenceReadme,
        /(?:access|refresh|id)[_-]?token\s*[:=]\s*[A-Za-z0-9._-]{16,}/i,
    );
});

test("the owner dashboard owns Gmail setup and exposes an accessible fail-closed switch", () => {
    assert.notEqual(gmailDashboard, "");
    assert.match(gmailDashboard, />Connect to Gmail</);
    assert.match(gmailDashboard, /role="switch"/);
    assert.match(gmailDashboard, /data-nr-gmail-purpose/);
    assert.match(gmailDashboard, /connector\.gmail\.message\.search/);
    assert.match(gmailDashboard, /connector\.gmail\.thread\.read/);
    assert.match(gmailDashboard, /connector\.gmail\.draft\.create/);
    assert.match(gmailDashboard, /owner\/connectors\/gmail\//);
    assert.match(gmailDashboard, /accounts\.google\.com/);
    assert.match(gmailDashboard, /OAUTH_CALLBACK_RECEIVED/);
    assert.match(gmailDashboard, /GMAIL_CONNECTOR_HARD_DENY/);
    assert.doesNotMatch(gmailDashboard, /OpenClaw/i);
    assert.doesNotMatch(
        gmailDashboard,
        /(?:delete|trash|archive|label|forward)\s*["']\s*[,)]/i,
    );
});

test("owner, exact Agent, active Passport, nonce, and paired worker fail closed", () => {
    assert.match(controlPlane, /private static function owner_guard/);
    assert.match(controlPlane, /NODEROOMS_OWNER_SESSION_REQUIRED/);
    assert.match(controlPlane, /CURRENT_USER_IS_NOT_AGENT_OWNER/);
    assert.match(controlPlane, /OWNER_SESSION_AGENT_MISMATCH/);
    assert.match(controlPlane, /NODEROOMS_OWNER_NONCE_INVALID/);
    assert.match(controlPlane, /AGENT_OWNER_BINDING_NOT_ACTIVE/);
    assert.match(controlPlane, /private static function passport_guard/);
    assert.match(controlPlane, /PASSPORT_PUBLIC_ID_INVALID/);
    assert.match(controlPlane, /GMAIL_CONNECTION_PASSPORT_DRIFT/);
    assert.match(controlPlane, /GMAIL_BACKGROUND_INFRASTRUCTURE_NOT_READY/);
});

test("the worker protocol is Ed25519-signed v2 with replay protection", () => {
    assert.match(controlPlane, /noderooms-trustbridge-job\.v2/);
    assert.match(controlPlane, /noderooms-trustbridge-worker\.v2/);
    assert.match(
        controlPlane,
        /REQUIRED_WORKER_VERSION = "1\.4\.0-alpha\.6-dev\.2"/,
    );
    assert.match(
        controlPlane,
        /\$worker_version !== self::REQUIRED_WORKER_VERSION/,
    );
    assert.match(controlPlane, /sodium_crypto_sign_verify_detached/);
    assert.match(controlPlane, /x-noderooms-worker-signature/);
    assert.match(controlPlane, /TRUSTBRIDGE_WORKER_NONCE_REPLAYED/);
    assert.doesNotMatch(controlPlane, /x-noderooms-worker-auth/);
});

test("Gmail OAuth is exact read plus compose and excludes broader mailbox scopes", () => {
    assert.match(
        controlPlane,
        /https:\/\/www\.googleapis\.com\/auth\/gmail\.readonly/,
    );
    assert.match(
        controlPlane,
        /https:\/\/www\.googleapis\.com\/auth\/gmail\.compose/,
    );
    assert.doesNotMatch(controlPlane, /gmail\.modify|mail\.google\.com/);
});

test("capability and one-action lease authority is purpose and target bound", () => {
    for (const field of [
        "owner_binding_id",
        "passport_public_id",
        "capability_id",
        "target_fingerprint_sha256",
        "purpose_sha256",
        "run_lease_id",
        "remaining_actions",
    ]) {
        assert.match(controlPlane, new RegExp(`\\"${field}\\"`), field);
    }
    assert.match(controlPlane, /"remaining_actions" => 1/);
    assert.match(controlPlane, /TRUSTBRIDGE_PURPOSE_BOUND_CAPABILITY_REQUIRED/);
    assert.match(controlPlane, /JOB_AUTHORITY_NOT_LIVE/);
});

test("send is one exact existing draft with an atomic allow-once reservation", () => {
    assert.match(controlPlane, /gmail_send_approved_draft/);
    assert.match(controlPlane, /owner_has_exact_unsent_draft/);
    assert.match(controlPlane, /confirm_exact_draft/);
    assert.match(controlPlane, /"policy" => "allow_once"/);
    assert.match(controlPlane, /"decision_source" => "verified_human_owner"/);
    assert.match(controlPlane, /"provider_attempt_max" => 1/);
    assert.match(controlPlane, /"automatic_retry_allowed" => false/);
    assert.match(controlPlane, /SELECT id FROM .*connections_table\(\).*FOR UPDATE/s);
    assert.match(controlPlane, /GMAIL_APPROVED_DRAFT_SEND_ALREADY_RESERVED/);
    assert.match(controlPlane, /TRUSTBRIDGE_JOB_UNKNOWN_SEALED/);
});

test("Delete and Trash are permanently denied and have no worker job", () => {
    assert.match(scopes, /connector\.gmail\.message\.delete/);
    assert.match(scopes, /permanently_denied/);
    assert.match(controlPlane, /"Delete or Trash"/);
    const workerJobs = controlPlane.match(
        /private static \$supported_worker_jobs = array\(([\s\S]*?)\);/,
    )?.[1] ?? "";
    assert.notEqual(workerJobs, "");
    assert.doesNotMatch(workerJobs, /delete|trash|archive|label|forward|batch/i);
});
