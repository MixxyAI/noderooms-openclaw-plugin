import { createHash } from "node:crypto";

export const NODEROOMS_CONNECTOR_AUTHORITY_CONTRACT_VERSION =
    "noderooms-connector-job-authority.v1";

export const NODEROOMS_CONNECTOR_JOB_SCOPES = Object.freeze({
    gmail_oauth_start: "connector.gmail.account.connect",
    gmail_oauth_complete: "connector.gmail.account.connect",
    gmail_search: "connector.gmail.message.search",
    gmail_thread_read: "connector.gmail.thread.read",
    gmail_draft_create: "connector.gmail.draft.create",
    gmail_send_approved_draft: "connector.gmail.draft.send",
    gmail_disconnect: "connector.gmail.account.disconnect",
});

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,159}$/;
const AGENT_SLUG_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export class NodeRoomsConnectorAuthorityError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "NodeRoomsConnectorAuthorityError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new NodeRoomsConnectorAuthorityError(code, message);
}

function isRecord(value) {
    return Boolean(value)
        && typeof value === "object"
        && !Array.isArray(value);
}

function exactKeys(value, required, label, code) {
    if (!isRecord(value)) {
        fail(code, `${label} is required.`);
    }
    const expected = new Set(required);
    for (const key of Object.keys(value)) {
        if (!expected.has(key)) {
            fail(
                "NODEROOMS_CONNECTOR_AUTHORITY_INVALID",
                `${label} contains unsupported field ${key}.`,
            );
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail(code, `${label}.${key} is required.`);
        }
    }
}

function exactIdentifier(value, label) {
    if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
        fail(
            "NODEROOMS_CONNECTOR_AUTHORITY_INVALID",
            `${label} is invalid.`,
        );
    }
    return value;
}

function exactSha256(value, label) {
    if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
        fail(
            "NODEROOMS_CONNECTOR_AUTHORITY_INVALID",
            `${label} is invalid.`,
        );
    }
    return value;
}

function parseTime(value, label) {
    const time = Date.parse(value ?? "");
    if (!Number.isFinite(time)) {
        fail(
            "NODEROOMS_CONNECTOR_AUTHORITY_INVALID",
            `${label} is invalid.`,
        );
    }
    return time;
}

function sha256(value) {
    return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function noderoomsConnectorActionFingerprint(input) {
    return sha256([
        NODEROOMS_CONNECTOR_AUTHORITY_CONTRACT_VERSION,
        input.jobId,
        input.jobType,
        input.payloadSha256,
        input.agentSlug,
        input.passportPublicId,
        input.ownerBindingId,
        input.capabilityId,
        input.runLeaseId,
        input.provider,
        input.accountBindingSha256,
        input.targetFingerprintSha256,
        input.scope,
        input.purposeId,
        input.purposeSha256,
        input.draftIdSha256 ?? "none",
    ].join("\n"));
}

function validateSurfaces(surfaces) {
    const fields = [
        "registration",
        "work",
        "connector_setup",
        "operations",
        "automations",
        "approvals",
        "results",
    ];
    exactKeys(
        surfaces,
        fields,
        "surfaces",
        "NODEROOMS_PRODUCT_SURFACE_REQUIRED",
    );
    if (fields.some((field) => surfaces[field] !== "noderooms")) {
        fail(
            "NODEROOMS_PRODUCT_SURFACE_REQUIRED",
            "Every user-facing connector surface must be NodeRooms.",
        );
    }
}

function validateRuntimeBoundary(runtime) {
    exactKeys(
        runtime,
        [
            "role",
            "user_visible",
            "user_cli_allowed",
            "user_install_allowed",
            "user_plugin_allowed",
            "user_branding_allowed",
        ],
        "runtime",
        "NODEROOMS_RUNTIME_BOUNDARY_REQUIRED",
    );
    if (runtime.role !== "background_infrastructure"
        || runtime.user_visible !== false
        || runtime.user_cli_allowed !== false
        || runtime.user_install_allowed !== false
        || runtime.user_plugin_allowed !== false
        || runtime.user_branding_allowed !== false) {
        fail(
            "NODEROOMS_RUNTIME_BOUNDARY_REQUIRED",
            "The connector runtime must remain invisible background infrastructure.",
        );
    }
}

function validateAgent(agent, expected) {
    exactKeys(
        agent,
        [
            "slug",
            "owner_binding_id",
            "owner_binding_status",
            "passport_public_id",
            "passport_status",
        ],
        "agent",
        "NODEROOMS_OWNER_BINDING_REQUIRED",
    );
    if (typeof agent.slug !== "string"
        || !AGENT_SLUG_PATTERN.test(agent.slug)
        || agent.slug !== expected.agentSlug) {
        fail(
            "NODEROOMS_CONNECTOR_AUTHORITY_MISMATCH",
            "The connector job belongs to another NodeRooms Agent.",
        );
    }
    exactIdentifier(agent.owner_binding_id, "agent.owner_binding_id");
    if (agent.owner_binding_id !== expected.ownerBindingId
        || agent.owner_binding_status !== "verified") {
        fail(
            "NODEROOMS_OWNER_BINDING_REQUIRED",
            "A verified active Owner binding is required.",
        );
    }
    if (typeof agent.passport_public_id !== "string"
        || agent.passport_public_id !== expected.passportPublicId) {
        fail(
            "NODEROOMS_PASSPORT_REQUIRED",
            "The exact NodeRooms Agent Passport is required.",
        );
    }
    exactIdentifier(agent.passport_public_id, "agent.passport_public_id");
    if (agent.passport_status !== "active") {
        fail(
            "NODEROOMS_PASSPORT_REQUIRED",
            "An active NodeRooms Agent Passport is required.",
        );
    }
    return agent;
}

function validateCapability(capability, expected, agent, nowMs) {
    exactKeys(
        capability,
        [
            "capability_id",
            "status",
            "decision",
            "decision_source",
            "automated",
            "agent_slug",
            "owner_binding_id",
            "passport_public_id",
            "provider",
            "account_binding_sha256",
            "target_fingerprint_sha256",
            "scope",
            "purpose_id",
            "purpose_sha256",
            "issued_at",
            "expires_at",
        ],
        "capability",
        "NODEROOMS_CAPABILITY_REQUIRED",
    );
    exactIdentifier(capability.capability_id, "capability.capability_id");
    exactIdentifier(capability.purpose_id, "capability.purpose_id");
    exactSha256(capability.purpose_sha256, "capability.purpose_sha256");
    exactSha256(
        capability.account_binding_sha256,
        "capability.account_binding_sha256",
    );
    exactSha256(
        capability.target_fingerprint_sha256,
        "capability.target_fingerprint_sha256",
    );
    const issuedAt = parseTime(capability.issued_at, "capability.issued_at");
    const expiresAt = parseTime(capability.expires_at, "capability.expires_at");
    if (capability.status !== "active"
        || capability.decision !== "allow"
        || capability.decision_source !== "verified_human_owner"
        || capability.automated !== false
        || issuedAt > nowMs
        || expiresAt <= nowMs) {
        fail(
            "NODEROOMS_CAPABILITY_REQUIRED",
            "An active purpose-bound capability approved by the verified human Owner is required.",
        );
    }
    if (capability.agent_slug !== agent.slug
        || capability.owner_binding_id !== agent.owner_binding_id
        || capability.passport_public_id !== agent.passport_public_id
        || capability.provider !== expected.provider
        || capability.account_binding_sha256
            !== expected.accountBindingSha256
        || capability.target_fingerprint_sha256
            !== expected.targetFingerprintSha256
        || capability.scope !== expected.scope) {
        fail(
            "NODEROOMS_CONNECTOR_AUTHORITY_MISMATCH",
            "The capability does not match the exact connector job.",
        );
    }
    return { ...capability, issuedAt, expiresAt };
}

function validateRunLease(runLease, expected, agent, capability, nowMs) {
    exactKeys(
        runLease,
        [
            "run_lease_id",
            "status",
            "capability_id",
            "agent_slug",
            "owner_binding_id",
            "passport_public_id",
            "provider",
            "account_binding_sha256",
            "target_fingerprint_sha256",
            "scope",
            "purpose_id",
            "purpose_sha256",
            "remaining_actions",
            "issued_at",
            "expires_at",
        ],
        "run_lease",
        "NODEROOMS_RUN_LEASE_REQUIRED",
    );
    exactIdentifier(runLease.run_lease_id, "run_lease.run_lease_id");
    const issuedAt = parseTime(runLease.issued_at, "run_lease.issued_at");
    const expiresAt = parseTime(runLease.expires_at, "run_lease.expires_at");
    if (runLease.status !== "active"
        || !Number.isSafeInteger(runLease.remaining_actions)
        || runLease.remaining_actions < 1
        || issuedAt > nowMs
        || expiresAt <= nowMs) {
        fail(
            "NODEROOMS_RUN_LEASE_REQUIRED",
            "An active scoped run lease with remaining authority is required.",
        );
    }
    if (runLease.capability_id !== capability.capability_id
        || runLease.agent_slug !== agent.slug
        || runLease.owner_binding_id !== agent.owner_binding_id
        || runLease.passport_public_id !== agent.passport_public_id
        || runLease.provider !== expected.provider
        || runLease.account_binding_sha256
            !== expected.accountBindingSha256
        || runLease.target_fingerprint_sha256
            !== expected.targetFingerprintSha256
        || runLease.scope !== expected.scope
        || runLease.purpose_id !== capability.purpose_id
        || runLease.purpose_sha256 !== capability.purpose_sha256
        || runLease.expires_at !== capability.expires_at) {
        fail(
            "NODEROOMS_CONNECTOR_AUTHORITY_MISMATCH",
            "The run lease does not match the exact capability and connector job.",
        );
    }
    return { ...runLease, issuedAt, expiresAt };
}

function validateJobBinding(jobBinding, expected) {
    exactKeys(
        jobBinding,
        ["job_id", "job_type", "payload_sha256"],
        "job_binding",
        "NODEROOMS_CONNECTOR_AUTHORITY_INVALID",
    );
    if (jobBinding.job_id !== expected.jobId
        || jobBinding.job_type !== expected.jobType
        || jobBinding.payload_sha256 !== expected.payloadSha256) {
        fail(
            "NODEROOMS_CONNECTOR_AUTHORITY_MISMATCH",
            "The authority envelope is bound to another job.",
        );
    }
}

function validateActionApproval(
    approval,
    expected,
    agent,
    capability,
    runLease,
    nowMs,
) {
    const isSend = expected.jobType === "gmail_send_approved_draft";
    if (!isSend) {
        if (approval !== null) {
            fail(
                "NODEROOMS_CONNECTOR_AUTHORITY_INVALID",
                "Per-action approval must be null for this connector job.",
            );
        }
        return null;
    }
    exactKeys(
        approval,
        [
            "policy",
            "status",
            "decision_source",
            "automated",
            "owner_binding_id",
            "approval_receipt_id",
            "dispatch_reservation_id",
            "draft_id_sha256",
            "action_fingerprint_sha256",
            "provider_attempt_max",
            "automatic_retry_allowed",
            "expires_at",
        ],
        "action_approval",
        "NODEROOMS_SEND_APPROVAL_REQUIRED",
    );
    exactIdentifier(
        approval.approval_receipt_id,
        "action_approval.approval_receipt_id",
    );
    exactIdentifier(
        approval.dispatch_reservation_id,
        "action_approval.dispatch_reservation_id",
    );
    exactSha256(
        approval.draft_id_sha256,
        "action_approval.draft_id_sha256",
    );
    if (approval.draft_id_sha256 !== expected.draftIdSha256) {
        fail(
            "NODEROOMS_SEND_APPROVAL_REQUIRED",
            "The one-use Owner approval belongs to another Gmail draft.",
        );
    }
    exactSha256(
        approval.action_fingerprint_sha256,
        "action_approval.action_fingerprint_sha256",
    );
    const expiresAt = parseTime(
        approval.expires_at,
        "action_approval.expires_at",
    );
    if (approval.policy !== "allow_once"
        || approval.status !== "approved"
        || approval.decision_source !== "verified_human_owner"
        || approval.automated !== false
        || approval.owner_binding_id !== agent.owner_binding_id
        || approval.provider_attempt_max !== 1
        || approval.automatic_retry_allowed !== false
        || expiresAt <= nowMs
        || expiresAt > runLease.expiresAt) {
        fail(
            "NODEROOMS_SEND_APPROVAL_REQUIRED",
            "Sending requires an unexpired one-use approval from the verified human Owner.",
        );
    }
    const expectedFingerprint = noderoomsConnectorActionFingerprint({
        jobId: expected.jobId,
        jobType: expected.jobType,
        payloadSha256: expected.payloadSha256,
        agentSlug: agent.slug,
        passportPublicId: agent.passport_public_id,
        ownerBindingId: agent.owner_binding_id,
        capabilityId: capability.capability_id,
        runLeaseId: runLease.run_lease_id,
        provider: expected.provider,
        accountBindingSha256: expected.accountBindingSha256,
        targetFingerprintSha256: expected.targetFingerprintSha256,
        scope: expected.scope,
        purposeId: capability.purpose_id,
        purposeSha256: capability.purpose_sha256,
        draftIdSha256: expected.draftIdSha256,
    });
    if (approval.action_fingerprint_sha256 !== expectedFingerprint) {
        fail(
            "NODEROOMS_SEND_APPROVAL_REQUIRED",
            "The one-use Owner approval is not bound to this exact draft send.",
        );
    }
    return { ...approval, expiresAt };
}

export function validateNodeRoomsConnectorJobAuthority(
    authority,
    expected,
) {
    if (!isRecord(authority)) {
        fail(
            "NODEROOMS_CONNECTOR_AUTHORITY_REQUIRED",
            "The NodeRooms connector authority envelope is required.",
        );
    }
    if (!Object.hasOwn(authority, "agent")) {
        fail(
            "NODEROOMS_OWNER_BINDING_REQUIRED",
            "The Owner-bound Agent authority is required.",
        );
    }
    if (!Object.hasOwn(authority, "capability")) {
        fail(
            "NODEROOMS_CAPABILITY_REQUIRED",
            "The owner-approved purpose-bound capability is required.",
        );
    }
    if (!Object.hasOwn(authority, "run_lease")) {
        fail(
            "NODEROOMS_RUN_LEASE_REQUIRED",
            "The active scoped run lease is required.",
        );
    }
    exactKeys(
        authority,
        [
            "contract_version",
            "surfaces",
            "runtime",
            "agent",
            "capability",
            "run_lease",
            "action_approval",
            "job_binding",
        ],
        "authority",
        "NODEROOMS_CONNECTOR_AUTHORITY_REQUIRED",
    );
    if (authority.contract_version
        !== NODEROOMS_CONNECTOR_AUTHORITY_CONTRACT_VERSION) {
        fail(
            "NODEROOMS_CONNECTOR_AUTHORITY_INVALID",
            "The connector authority contract version is unsupported.",
        );
    }
    const scope = NODEROOMS_CONNECTOR_JOB_SCOPES[expected.jobType];
    if (!scope || scope !== expected.scope) {
        fail(
            "NODEROOMS_CONNECTOR_AUTHORITY_INVALID",
            "The connector job type has no exact canonical scope.",
        );
    }
    const nowMs = Number.isFinite(expected.nowMs)
        ? expected.nowMs
        : Date.now();
    validateSurfaces(authority.surfaces);
    validateRuntimeBoundary(authority.runtime);
    const agent = validateAgent(authority.agent, expected);
    const capability = validateCapability(
        authority.capability,
        expected,
        agent,
        nowMs,
    );
    const runLease = validateRunLease(
        authority.run_lease,
        expected,
        agent,
        capability,
        nowMs,
    );
    validateJobBinding(authority.job_binding, expected);
    const actionApproval = validateActionApproval(
        authority.action_approval,
        expected,
        agent,
        capability,
        runLease,
        nowMs,
    );
    return Object.freeze({
        scope,
        ownerBindingId: agent.owner_binding_id,
        capabilityId: capability.capability_id,
        runLeaseId: runLease.run_lease_id,
        purposeId: capability.purpose_id,
        actionApproval,
    });
}
