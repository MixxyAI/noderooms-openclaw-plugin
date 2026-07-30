import { sha256Fingerprint } from "./passport-runtime-binding.js";
import {
    validateRuntimeToolInventoryV1,
} from "./universal-connector-engine.js";

export const EMAIL_READ_DRAFT_CONTRACT_VERSION =
    "noderooms-email-read-draft-profile-v1";
export const EMAIL_READ_DRAFT_DEVELOPMENT_IDENTITY =
    "1.4.0-alpha.2-dev.1";
export const EMAIL_READ_DRAFT_LIVE_USE_ALLOWED = false;
export const EMAIL_READ_DRAFT_RUNTIME_VALIDATION_STATUS =
    "external_validation_pending";

const PROFILE_ID_PATTERN = /^nrc002_[a-z0-9][a-z0-9._-]{2,95}$/;
const OWNER_ID_PATTERN = /^[A-Za-z0-9._:@/-]{1,160}$/;
const VERSION_PATTERN =
    /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;

const READER_TOOL_NAMES = Object.freeze([
    "gmail_read_email_thread",
    "gmail_search_emails",
]);
const DRAFT_TOOL_NAME = "gmail_create_draft";
const FORBIDDEN_TOOL_NAMES = Object.freeze([
    "gmail_apply_labels_to_emails",
    "gmail_archive_emails",
    "gmail_batch_modify_email",
    "gmail_bulk_label_matching_emails",
    "gmail_create_label",
    "gmail_delete_emails",
    "gmail_forward_emails",
    "gmail_send_draft",
    "gmail_send_email",
    "gmail_update_draft",
]);
const READER_DENIED_TOOL_GROUPS = Object.freeze([
    "browser",
    "cron",
    "gateway",
    "group:fs",
    "group:runtime",
    "group:web",
    "nodes",
]);

export class EmailReadDraftProfileError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "EmailReadDraftProfileError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new EmailReadDraftProfileError(code, message);
}

function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, required, optional, label) {
    if (!isRecord(value)) {
        fail("EMAIL_PROFILE_INVALID", `${label} must be an object.`);
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail(
                "EMAIL_PROFILE_INVALID",
                `${label} contains unsupported field ${key}.`,
            );
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail("EMAIL_PROFILE_INVALID", `${label} is missing ${key}.`);
        }
    }
}

function exactString(value, pattern, label, maxLength = 512) {
    if (typeof value !== "string"
        || value.length < 1
        || value.length > maxLength
        || !pattern.test(value)) {
        fail("EMAIL_PROFILE_INVALID", `${label} is invalid.`);
    }
    return value;
}

function exactSha(value, label) {
    return exactString(value, SHA256_PATTERN, label, 71);
}

function exactVersion(value, label) {
    return exactString(value, VERSION_PATTERN, label, 128);
}

function toolProjection(tool) {
    return Object.freeze({
        tool_name: tool.tool_name,
        profile_id: tool.policy_binding.profile_id,
        scope: tool.policy_binding.scope,
        action: tool.policy_binding.action,
        resource_type: tool.policy_binding.resource_type,
        input_schema_fingerprint_sha256:
            tool.actual_input_schema_fingerprint_sha256,
        side_effect_class: tool.side_effect_class,
        risk: tool.risk,
        replay_semantics: tool.replay_semantics,
        approval_policy: tool.policy_binding.approval_policy,
        receipt_profile: tool.output_receipt_profile,
        coverage_status: tool.coverage_status,
        enforce_eligible: false,
        authority_status: "contract_only_no_authority",
    });
}

function requireTool(inventory, toolName) {
    const tool = inventory.tools.find((entry) => entry.tool_name === toolName);
    if (!tool) {
        fail(
            "EMAIL_PROFILE_TOOL_MISSING",
            `Required Gmail tool ${toolName} is absent.`,
        );
    }
    if (tool.owner?.kind !== "plugin"
        || tool.owner?.owner_id !== "gmail"
        || tool.owner?.resolution !== "exact") {
        fail(
            "EMAIL_PROFILE_OWNER_DRIFT",
            `Gmail tool ${toolName} has no exact Gmail plugin owner.`,
        );
    }
    if (!exactSha(
        tool.actual_input_schema_fingerprint_sha256,
        `${toolName}.actual_input_schema_fingerprint_sha256`,
    )
        || tool.actual_input_schema_fingerprint_sha256
            !== tool.expected_input_schema_fingerprint_sha256) {
        fail(
            "EMAIL_PROFILE_SCHEMA_DRIFT",
            `Gmail tool ${toolName} schema is unavailable or drifted.`,
        );
    }
    const policy = tool.policy_binding;
    if (tool.coverage_status !== "covered_contract_only"
        || tool.enforce_eligible !== false
        || tool.authority_status !== "inventory_only_no_authority"
        || policy?.profile_status !== "reference_only"
        || policy?.provider !== "gmail"
        || policy?.connector_id !== "openclaw.codex.gmail-app"
        || policy?.connector_version !== "0.1.5") {
        fail(
            "EMAIL_PROFILE_POLICY_DRIFT",
            `Gmail tool ${toolName} policy binding has drifted.`,
        );
    }
    return tool;
}

function assertToolSemantics(tool, expected) {
    if (tool.side_effect_class !== expected.sideEffectClass
        || tool.risk !== expected.risk
        || tool.replay_semantics !== expected.replaySemantics
        || tool.declared_replay_safe !== expected.replaySafe
        || tool.policy_binding.approval_policy !== expected.approval
        || tool.output_receipt_profile !== expected.receipt) {
        fail(
            "EMAIL_PROFILE_SEMANTICS_DRIFT",
            `Gmail tool ${tool.tool_name} semantics have drifted.`,
        );
    }
}

function profileProjection(profile) {
    return {
        contract_version: profile.contract_version,
        development_identity: profile.development_identity,
        activation_state: profile.activation_state,
        live_email_use_allowed: profile.live_email_use_allowed,
        runtime_validation_status: profile.runtime_validation_status,
        profile_id: profile.profile_id,
        captured_at: profile.captured_at,
        connector: profile.connector,
        inventory_binding: profile.inventory_binding,
        reader: profile.reader,
        drafter: profile.drafter,
        forbidden_tool_names: profile.forbidden_tool_names,
        safety: profile.safety,
    };
}

export function emailReadDraftProfileFingerprint(profile) {
    return sha256Fingerprint(profileProjection(profile));
}

export function buildEmailReadDraftProfileV1(input) {
    assertExactKeys(
        input,
        [
            "profile_id",
            "captured_at",
            "inventory_snapshot",
            "owner_version",
            "version_source",
            "account_binding_fingerprint_sha256",
            "reader_agent_id",
            "drafter_agent_id",
        ],
        [],
        "email profile input",
    );
    exactString(input.profile_id, PROFILE_ID_PATTERN, "profile_id", 101);
    const capturedAt = Date.parse(input.captured_at);
    if (!Number.isFinite(capturedAt)) {
        fail("EMAIL_PROFILE_INVALID", "captured_at is invalid.");
    }
    exactVersion(input.owner_version, "owner_version");
    if (input.owner_version !== "0.1.5"
        || input.version_source !== "contract_fixture") {
        fail(
            "EMAIL_PROFILE_VERSION_SOURCE_INVALID",
            "Gmail owner version source is not the exact C002 fixture.",
        );
    }
    exactSha(
        input.account_binding_fingerprint_sha256,
        "account_binding_fingerprint_sha256",
    );
    exactString(
        input.reader_agent_id,
        OWNER_ID_PATTERN,
        "reader_agent_id",
        160,
    );
    exactString(
        input.drafter_agent_id,
        OWNER_ID_PATTERN,
        "drafter_agent_id",
        160,
    );
    if (input.reader_agent_id === input.drafter_agent_id) {
        fail(
            "EMAIL_PROFILE_AGENT_ISOLATION_INVALID",
            "Reader and drafter Agents must be distinct.",
        );
    }

    const inventory = validateRuntimeToolInventoryV1(
        input.inventory_snapshot,
    );
    if (inventory.source?.catalog_kind !== "contract_fixture"
        || inventory.activation_state !== "inventory_only"
        || inventory.live_enforce_allowed !== false
        || inventory.registry_binding?.activation_state !== "contract_only"
        || inventory.registry_binding?.live_enforce_allowed !== false
        || inventory.metrics.inventory_completeness_percent !== 100
        || inventory.metrics.enforce_profile_ready !== false) {
        fail(
            "EMAIL_PROFILE_INVENTORY_BOUNDARY_INVALID",
            "C002 requires a complete non-live contract inventory.",
        );
    }
    const expectedToolNames = [...READER_TOOL_NAMES, DRAFT_TOOL_NAME].toSorted();
    const actualToolNames = inventory.tools
        .map((entry) => entry.tool_name)
        .toSorted();
    if (JSON.stringify(actualToolNames) !== JSON.stringify(expectedToolNames)) {
        fail(
            "EMAIL_PROFILE_TOOL_SET_INVALID",
            "C002 inventory must contain exactly search, read, and draft.",
        );
    }

    const searchTool = requireTool(inventory, "gmail_search_emails");
    const readTool = requireTool(inventory, "gmail_read_email_thread");
    const draftTool = requireTool(inventory, DRAFT_TOOL_NAME);
    for (const tool of [searchTool, readTool]) {
        assertToolSemantics(tool, {
            sideEffectClass: "read",
            risk: "medium",
            replaySemantics: "replay_safe_read",
            replaySafe: true,
            approval: "none",
            receipt: "read_observation_v1",
        });
    }
    assertToolSemantics(draftTool, {
        sideEffectClass: "write",
        risk: "high",
        replaySemantics: "at_most_once_dispatch",
        replaySafe: false,
        approval: "allow_once",
        receipt: "external_action_receipt_v2",
    });

    const connectorIdentity = {
        provider: "gmail",
        connector_id: "openclaw.codex.gmail-app",
        connector_version: "0.1.5",
    };
    for (const tool of [searchTool, readTool, draftTool]) {
        const policy = tool.policy_binding;
        if (policy.provider !== connectorIdentity.provider
            || policy.connector_id !== connectorIdentity.connector_id
            || policy.connector_version
                !== connectorIdentity.connector_version) {
            fail(
                "EMAIL_PROFILE_CONNECTOR_DRIFT",
                "C002 tool profiles span connector identities.",
            );
        }
    }

    const profile = {
        contract_version: EMAIL_READ_DRAFT_CONTRACT_VERSION,
        development_identity: EMAIL_READ_DRAFT_DEVELOPMENT_IDENTITY,
        activation_state: "contract_only",
        live_email_use_allowed: EMAIL_READ_DRAFT_LIVE_USE_ALLOWED,
        runtime_validation_status:
            EMAIL_READ_DRAFT_RUNTIME_VALIDATION_STATUS,
        profile_id: input.profile_id,
        captured_at: new Date(capturedAt).toISOString(),
        connector: Object.freeze({
            owner: Object.freeze({
                kind: "plugin",
                owner_id: "gmail",
                resolution: "exact",
                owner_version: input.owner_version,
                version_source: input.version_source,
            }),
            ...connectorIdentity,
            credential_custodian: "openclaw",
            noderooms_stores_provider_credentials: false,
            account_binding_fingerprint_sha256:
                input.account_binding_fingerprint_sha256,
        }),
        inventory_binding: Object.freeze({
            inventory_contract_version: inventory.contract_version,
            inventory_snapshot_fingerprint_sha256:
                inventory.snapshot_fingerprint_sha256,
            registry_version: inventory.registry_binding.registry_version,
            policy_version: inventory.registry_binding.policy_version,
            inventory_tool_count: inventory.metrics.inventory_tool_count,
            schema_verified_tool_count:
                inventory.metrics.covered_tool_count,
            unclassified_tool_count:
                inventory.metrics.unclassified_tool_count,
            drifted_tool_count: inventory.metrics.drifted_tool_count,
        }),
        reader: Object.freeze({
            role: "dedicated_mail_reader",
            agent_id_fingerprint_sha256: sha256Fingerprint({
                role: "dedicated_mail_reader",
                agent_id: input.reader_agent_id,
            }),
            input_trust: "untrusted_external_content",
            sandbox_mode: "all",
            sandbox_scope: "session",
            workspace_access: "none",
            allowed_tool_names: READER_TOOL_NAMES,
            denied_tool_groups: READER_DENIED_TOOL_GROUPS,
            tools: Object.freeze(
                [readTool, searchTool]
                    .map(toolProjection)
                    .toSorted((left, right) =>
                        left.tool_name.localeCompare(right.tool_name)),
            ),
            handoff_policy: "summary_only",
            memory_ingestion_enabled: false,
            swarm_enabled: false,
        }),
        drafter: Object.freeze({
            role: "owner_reviewed_mail_drafter",
            agent_id_fingerprint_sha256: sha256Fingerprint({
                role: "owner_reviewed_mail_drafter",
                agent_id: input.drafter_agent_id,
            }),
            tool: toolProjection(draftTool),
            mailbox_effect: "create_unsent_draft_only",
            exact_recipient_resolution_required: true,
            automatic_recipient_selection_allowed: false,
            human_owner_review_required: true,
            approval_policy: "allow_once",
            send_capability_present: false,
            forward_capability_present: false,
            destructive_capability_present: false,
        }),
        forbidden_tool_names: FORBIDDEN_TOOL_NAMES,
        safety: Object.freeze({
            grants_authority: false,
            executes_tools: false,
            invokes_email_connector: false,
            reads_live_mailbox: false,
            creates_live_draft: false,
            sends_email: false,
            forwards_email: false,
            mutates_labels: false,
            archives_email: false,
            deletes_email: false,
            stores_provider_credentials: false,
            stores_raw_email_content: false,
            stores_raw_draft_content: false,
            stores_raw_recipient_values: false,
            automates_recipient_selection: false,
            automates_owner_decision: false,
            memory_ingestion_enabled: false,
            swarm_enabled: false,
        }),
    };
    profile.profile_fingerprint_sha256 =
        emailReadDraftProfileFingerprint(profile);
    return Object.freeze(profile);
}

export function validateEmailReadDraftProfileV1(profile) {
    assertExactKeys(
        profile,
        [
            "contract_version",
            "development_identity",
            "activation_state",
            "live_email_use_allowed",
            "runtime_validation_status",
            "profile_id",
            "captured_at",
            "connector",
            "inventory_binding",
            "reader",
            "drafter",
            "forbidden_tool_names",
            "safety",
            "profile_fingerprint_sha256",
        ],
        [],
        "email read draft profile",
    );
    if (profile.contract_version !== EMAIL_READ_DRAFT_CONTRACT_VERSION
        || profile.development_identity
            !== EMAIL_READ_DRAFT_DEVELOPMENT_IDENTITY
        || profile.activation_state !== "contract_only"
        || profile.live_email_use_allowed !== false
        || profile.runtime_validation_status
            !== EMAIL_READ_DRAFT_RUNTIME_VALIDATION_STATUS
        || !Number.isFinite(Date.parse(profile.captured_at))) {
        fail("EMAIL_PROFILE_INVALID", "C002 profile metadata is invalid.");
    }
    exactString(profile.profile_id, PROFILE_ID_PATTERN, "profile_id", 101);
    exactSha(
        profile.profile_fingerprint_sha256,
        "profile_fingerprint_sha256",
    );
    if (profile.reader?.input_trust !== "untrusted_external_content"
        || profile.reader?.sandbox_mode !== "all"
        || profile.reader?.sandbox_scope !== "session"
        || profile.reader?.workspace_access !== "none"
        || profile.reader?.memory_ingestion_enabled !== false
        || profile.reader?.swarm_enabled !== false
        || profile.drafter?.mailbox_effect !== "create_unsent_draft_only"
        || profile.drafter?.exact_recipient_resolution_required !== true
        || profile.drafter?.automatic_recipient_selection_allowed !== false
        || profile.drafter?.human_owner_review_required !== true
        || profile.drafter?.approval_policy !== "allow_once"
        || profile.drafter?.send_capability_present !== false
        || profile.safety?.grants_authority !== false
        || profile.safety?.executes_tools !== false
        || profile.safety?.invokes_email_connector !== false
        || profile.safety?.reads_live_mailbox !== false
        || profile.safety?.creates_live_draft !== false
        || profile.safety?.sends_email !== false
        || profile.safety?.stores_provider_credentials !== false
        || profile.safety?.stores_raw_email_content !== false
        || profile.safety?.stores_raw_draft_content !== false
        || profile.safety?.stores_raw_recipient_values !== false
        || profile.safety?.automates_recipient_selection !== false
        || profile.safety?.automates_owner_decision !== false
        || profile.safety?.memory_ingestion_enabled !== false
        || profile.safety?.swarm_enabled !== false) {
        fail("EMAIL_PROFILE_SAFETY_INVALID", "C002 safety boundary drifted.");
    }
    const readNames = profile.reader.tools
        ?.map((tool) => tool.tool_name)
        .toSorted();
    if (JSON.stringify(readNames) !== JSON.stringify(READER_TOOL_NAMES)
        || profile.drafter?.tool?.tool_name !== DRAFT_TOOL_NAME
        || profile.drafter.tool.approval_policy !== "allow_once"
        || profile.drafter.tool.side_effect_class !== "write"
        || profile.drafter.tool.enforce_eligible !== false
        || profile.forbidden_tool_names.some((toolName) =>
            [...READER_TOOL_NAMES, DRAFT_TOOL_NAME].includes(toolName))
        || !profile.forbidden_tool_names.includes("gmail_send_email")
        || !profile.forbidden_tool_names.includes("gmail_send_draft")
        || !profile.forbidden_tool_names.includes("gmail_delete_emails")) {
        fail("EMAIL_PROFILE_TOOL_SET_INVALID", "C002 tool boundary drifted.");
    }
    if (profile.profile_fingerprint_sha256
        !== emailReadDraftProfileFingerprint(profile)) {
        fail(
            "EMAIL_PROFILE_FINGERPRINT_DRIFT",
            "C002 profile fingerprint has drifted.",
        );
    }
    return Object.freeze(profile);
}
