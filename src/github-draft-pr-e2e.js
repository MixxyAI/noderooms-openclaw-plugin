import {
    createPublicKey,
    generateKeyPairSync,
    sign,
    verify,
} from "node:crypto";
import {
    mkdir,
    open,
    readFile,
    rename,
    unlink,
    writeFile,
} from "node:fs/promises";
import path from "node:path";

import {
    canonicalJson,
    sha256Fingerprint,
} from "./passport-runtime-binding.js";

export const GITHUB_DRAFT_PR_E2E_CONTRACT_VERSION =
    "noderooms-github-draft-pr-e2e-v1";
export const GITHUB_DRAFT_PR_E2E_RECEIPT_CONTRACT_VERSION =
    "noderooms-github-draft-pr-e2e-receipt-v1";
export const GITHUB_DRAFT_PR_E2E_SCOPE =
    "connector.github.pull_request.draft";
export const GITHUB_DRAFT_PR_E2E_PROFILE_ID =
    "nrscp_github_pull_request_draft_v1";
export const GITHUB_DRAFT_PR_E2E_TOOL_NAME =
    "github_create_pull_request";
export const GITHUB_DRAFT_PR_E2E_TRANSPORT_ADAPTER =
    "noderooms-github-mcp-create-pull-request-adapter-v1";
export const GITHUB_DRAFT_PR_E2E_MCP_SERVER_NAME =
    "github-noderooms-draft-pr";
export const GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID =
    "github-noderooms-draft-pr__create_pull_request";
export const GITHUB_DRAFT_PR_E2E_MCP_RAW_TOOL_NAME =
    "create_pull_request";
export const GITHUB_DRAFT_PR_E2E_MCP_RAW_SCHEMA_FINGERPRINT =
    "sha256:e249ccd5a1f2364cbfc0a5d9e11bebdc298626351cc7e43fd59b851c3d520238";
export const GITHUB_DRAFT_PR_E2E_LIVE_PLUGIN_ARMED = false;

const STORE_VERSION = 1;
const MAX_STORE_BYTES = 1_048_576;
const LOCK_RETRY_COUNT = 100;
const LOCK_RETRY_DELAY_MS = 10;
const MAX_APPROVAL_WINDOW_MS = 15 * 60 * 1_000;

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const SHA_PATTERN = /^[a-f0-9]{40}$/;
const NONCE_PATTERN = /^[a-f0-9]{64}$/;
const REPOSITORY_PATTERN =
    /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const REF_PATTERN = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\/\/)[A-Za-z0-9._/-]{1,255}$/;
const AGENT_SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$/;
const PASSPORT_PATTERN = /^NRP-[0-9]{6}-AGENT$/;
const CONNECTION_PATTERN = /^nrgh_inst_[a-f0-9]{16}$/;
const TOOL_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const OWNER_ID_PATTERN = /^[A-Za-z0-9._:@/-]{1,160}$/;
const CONTEXT_ID_PATTERN = /^[A-Za-z0-9._:/-]{1,200}$/;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{2,95}$/;
const URL_PATTERN =
    /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/pull\/[1-9][0-9]*$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const KEY_ID_PATTERN = /^nrp4ckey_[a-f0-9]{24}$/;
const PROOF_ID_PATTERN = /^nrp4c_[a-f0-9]{32}$/;
const APPROVAL_ID_PATTERN = /^nrcapdec_[a-f0-9]{32}$/;
const LEASE_ID_PATTERN = /^nrlv2_[a-f0-9]{32}$/;
const INTENT_ID_PATTERN = /^nreai_[a-f0-9]{32}$/;
const RESERVATION_ID_PATTERN = /^nrdispatch_[a-f0-9]{32}$/;
const RECEIPT_ID_PATTERN = /^nrear_[a-f0-9]{32}$/;

const FORBIDDEN_CHANGED_PATHS = [
    /^\.github\/workflows(?:\/|$)/i,
    /(^|\/)\.env(?:\.|$)/i,
    /(^|\/)(?:secrets?|credentials?)(?:\/|\.|$)/i,
    /\.(?:pem|p12|pfx|key)$/i,
];

const SENSITIVE_FIELD_PATTERN =
    /(?:^|_)(?:token|secret|password|private_key|authorization|cookie|pat|pem)(?:$|_)/i;

export class GitHubDraftPrE2EError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "GitHubDraftPrE2EError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new GitHubDraftPrE2EError(code, message);
}

function isRecord(value) {
    return Boolean(value)
        && typeof value === "object"
        && !Array.isArray(value);
}

function assertExactKeys(value, required, optional, label) {
    if (!isRecord(value)) {
        fail("OBJECT_REQUIRED", `${label} must be an object.`);
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail("UNKNOWN_FIELD", `${label}.${key} is not allowed.`);
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail("MISSING_FIELD", `${label}.${key} is required.`);
        }
    }
}

function boundedString(
    value,
    pattern,
    label,
    minimum = 1,
    maximum = 512,
) {
    if (typeof value !== "string"
        || value.length < minimum
        || value.length > maximum
        || (pattern && !pattern.test(value))) {
        fail("STRING_INVALID", `${label} is invalid.`);
    }
    return value;
}

function exactBoolean(value, expected, label) {
    if (value !== expected) {
        fail("BOOLEAN_INVALID", `${label} must be ${expected}.`);
    }
}

function exactInteger(value, label, minimum = 0) {
    if (!Number.isSafeInteger(value) || value < minimum) {
        fail("INTEGER_INVALID", `${label} is invalid.`);
    }
    return value;
}

function parseTime(value, label) {
    boundedString(value, null, label, 20, 40);
    const milliseconds = Date.parse(value);
    if (!Number.isFinite(milliseconds)
        || new Date(milliseconds).toISOString() !== value) {
        fail("TIME_INVALID", `${label} must be canonical UTC date-time.`);
    }
    return milliseconds;
}

function normalizeNow(value) {
    const date = value instanceof Date ? value : new Date(value);
    if (!Number.isFinite(date.getTime())) {
        fail("TIME_INVALID", "Current proof time is invalid.");
    }
    return date;
}

function cloneJson(value, label = "value") {
    let serialized;
    try {
        serialized = JSON.stringify(value);
    }
    catch {
        fail("JSON_INVALID", `${label} must be JSON-compatible.`);
    }
    if (serialized === undefined || Buffer.byteLength(serialized) > MAX_STORE_BYTES) {
        fail("JSON_INVALID", `${label} is missing or too large.`);
    }
    return JSON.parse(serialized);
}

function deepFreeze(value) {
    if (value && typeof value === "object" && !Object.isFrozen(value)) {
        Object.freeze(value);
        for (const child of Object.values(value)) {
            deepFreeze(child);
        }
    }
    return value;
}

function sameJson(left, right) {
    return canonicalJson(left) === canonicalJson(right);
}

function assertNoSensitiveFields(value, location = "$") {
    if (Array.isArray(value)) {
        value.forEach((entry, index) =>
            assertNoSensitiveFields(entry, `${location}[${index}]`));
        return;
    }
    if (!isRecord(value)) {
        return;
    }
    for (const [key, child] of Object.entries(value)) {
        if (SENSITIVE_FIELD_PATTERN.test(key)
            && child !== false
            && child !== null) {
            fail(
                "SENSITIVE_FIELD_FORBIDDEN",
                `${location}.${key} is forbidden in Phase 4C evidence.`,
            );
        }
        assertNoSensitiveFields(child, `${location}.${key}`);
    }
}

function idFor(prefix, seed) {
    return `${prefix}${sha256Fingerprint(seed).slice(7, 39)}`;
}

function base64url(value) {
    return Buffer.from(value).toString("base64url");
}

function publicJwkThumbprint(publicKeyJwk) {
    return sha256Fingerprint({
        crv: publicKeyJwk.crv,
        kty: publicKeyJwk.kty,
        x: publicKeyJwk.x,
    });
}

function validatePublicJwk(value) {
    assertExactKeys(value, ["kty", "crv", "x"], [], "public_key_jwk");
    if (value.kty !== "OKP" || value.crv !== "Ed25519") {
        fail("RECEIPT_KEY_INVALID", "Receipt key must be Ed25519.");
    }
    boundedString(value.x, /^[A-Za-z0-9_-]{43}$/, "public_key_jwk.x");
    return value;
}

function validateReceiptTrustAnchor(value) {
    assertExactKeys(value, [
        "issuer",
        "algorithm",
        "key_id",
        "public_key_jwk",
        "key_thumbprint_sha256",
    ], [], "receipt_trust_anchor");
    if (value.issuer !== "noderooms-isolated-proof"
        || value.algorithm !== "Ed25519") {
        fail(
            "RECEIPT_TRUST_ANCHOR_INVALID",
            "Receipt trust anchor is invalid.",
        );
    }
    boundedString(value.key_id, KEY_ID_PATTERN, "receipt_trust_anchor.key_id");
    const publicJwk = validatePublicJwk(value.public_key_jwk);
    boundedString(
        value.key_thumbprint_sha256,
        SHA256_PATTERN,
        "receipt_trust_anchor.key_thumbprint_sha256",
    );
    if (value.key_thumbprint_sha256 !== publicJwkThumbprint(publicJwk)) {
        fail(
            "RECEIPT_TRUST_ANCHOR_INVALID",
            "Receipt trust-anchor thumbprint is invalid.",
        );
    }
    return value;
}

function receiptSignaturePayload(receiptFingerprint) {
    return canonicalJson({
        domain: "noderooms/github-draft-pr-e2e-receipt/v1",
        receipt_fingerprint_sha256: receiptFingerprint,
    });
}

export function createGitHubDraftPrE2EReceiptSigner() {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeyJwk = publicKey.export({ format: "jwk" });
    const keyThumbprint = publicJwkThumbprint(publicKeyJwk);
    const trustAnchor = deepFreeze({
        issuer: "noderooms-isolated-proof",
        algorithm: "Ed25519",
        key_id: idFor("nrp4ckey_", {
            key_thumbprint_sha256: keyThumbprint,
        }).slice(0, 33),
        public_key_jwk: publicKeyJwk,
        key_thumbprint_sha256: keyThumbprint,
    });
    validateReceiptTrustAnchor(trustAnchor);
    return Object.freeze({
        trust_anchor: trustAnchor,
        signReceiptFingerprint(receiptFingerprint) {
            boundedString(
                receiptFingerprint,
                SHA256_PATTERN,
                "receipt_fingerprint_sha256",
            );
            return base64url(sign(
                null,
                Buffer.from(
                    receiptSignaturePayload(receiptFingerprint),
                    "utf8",
                ),
                privateKey,
            ));
        },
    });
}

function validateChangedPaths(value) {
    if (!Array.isArray(value) || value.length < 1 || value.length > 64) {
        fail("CHANGED_PATHS_INVALID", "At least one bounded changed path is required.");
    }
    const seen = new Set();
    for (const entry of value) {
        boundedString(entry, null, "changed_path", 1, 512);
        if (path.posix.isAbsolute(entry)
            || entry.includes("\\")
            || entry.split("/").includes("..")
            || entry.startsWith("./")
            || FORBIDDEN_CHANGED_PATHS.some((pattern) => pattern.test(entry))) {
            fail(
                "CHANGED_PATH_FORBIDDEN",
                "Phase 4C cannot target a workflow, secret, credential, key, or unsafe path.",
            );
        }
        if (seen.has(entry)) {
            fail("CHANGED_PATH_DUPLICATE", "Changed paths must be unique.");
        }
        seen.add(entry);
    }
    return [...value].sort();
}

export function githubDraftPrPayloadProjection(payload) {
    assertExactKeys(payload, [
        "repository_full_name",
        "head_ref",
        "base_ref",
        "title",
        "body",
        "draft",
    ], [], "GitHub Draft PR payload");
    boundedString(
        payload.repository_full_name,
        REPOSITORY_PATTERN,
        "repository_full_name",
        3,
        200,
    );
    boundedString(payload.head_ref, REF_PATTERN, "head_ref", 1, 255);
    boundedString(payload.base_ref, REF_PATTERN, "base_ref", 1, 255);
    boundedString(payload.title, null, "title", 1, 256);
    boundedString(payload.body, null, "body", 0, 65_536);
    exactBoolean(payload.draft, true, "draft");
    if (payload.head_ref === payload.base_ref
        || payload.head_ref === "main"
        || payload.base_ref !== "main") {
        fail(
            "BRANCH_BOUNDARY_INVALID",
            "Phase 4C requires an exact non-main head and main base.",
        );
    }
    return {
        repository_full_name: payload.repository_full_name,
        head_ref: payload.head_ref,
        base_ref: payload.base_ref,
        draft: true,
        title_sha256: sha256Fingerprint(payload.title),
        body_sha256: sha256Fingerprint(payload.body),
    };
}

export function githubDraftPrPayloadFingerprint(payload) {
    return sha256Fingerprint(githubDraftPrPayloadProjection(payload));
}

export function githubMcpCreatePullRequestParams(payload) {
    githubDraftPrPayloadProjection(payload);
    const separator = payload.repository_full_name.indexOf("/");
    const owner = payload.repository_full_name.slice(0, separator);
    const repo = payload.repository_full_name.slice(separator + 1);
    return deepFreeze({
        owner,
        repo,
        title: payload.title,
        head: payload.head_ref,
        base: payload.base_ref,
        body: payload.body,
        draft: true,
        maintainer_can_modify: false,
    });
}

export function githubMcpCreatePullRequestParamsFingerprint(payload) {
    return sha256Fingerprint(githubMcpCreatePullRequestParams(payload));
}

function validateAgentBinding(value) {
    assertExactKeys(value, [
        "noderooms_agent_id",
        "passport_id",
        "agent_slug",
    ], [], "agent_binding");
    exactInteger(value.noderooms_agent_id, "noderooms_agent_id", 1);
    boundedString(value.passport_id, PASSPORT_PATTERN, "passport_id");
    boundedString(value.agent_slug, AGENT_SLUG_PATTERN, "agent_slug", 3, 80);
    return value;
}

function validateOwnerBinding(value) {
    assertExactKeys(value, [
        "binding_kind",
        "active_binding_id",
        "provider",
        "provider_login",
        "connection_id",
        "github_installation_id",
        "verified_human_owner",
    ], [], "owner_binding");
    if (value.binding_kind !== "noderooms_provider_binding"
        || value.provider !== "github") {
        fail("OWNER_BINDING_INVALID", "Owner provider binding is invalid.");
    }
    exactInteger(value.active_binding_id, "active_binding_id", 1);
    boundedString(
        value.provider_login,
        /^[A-Za-z0-9-]{1,39}$/,
        "provider_login",
    );
    boundedString(
        value.connection_id,
        CONNECTION_PATTERN,
        "connection_id",
    );
    exactInteger(
        value.github_installation_id,
        "github_installation_id",
        1,
    );
    exactBoolean(
        value.verified_human_owner,
        true,
        "verified_human_owner",
    );
    return value;
}

function validateRuntimeBinding(value) {
    assertExactKeys(value, [
        "platform",
        "openclaw_version",
        "openclaw_agent_id",
        "session_key_fingerprint_sha256",
        "gateway_instance_fingerprint_sha256",
        "runtime_catalog_fingerprint_sha256",
    ], [], "runtime_binding");
    if (value.platform !== "openclaw") {
        fail("RUNTIME_BINDING_INVALID", "Phase 4C requires OpenClaw.");
    }
    boundedString(
        value.openclaw_version,
        /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/,
        "openclaw_version",
    );
    boundedString(
        value.openclaw_agent_id,
        CONTEXT_ID_PATTERN,
        "openclaw_agent_id",
    );
    for (const field of [
        "session_key_fingerprint_sha256",
        "gateway_instance_fingerprint_sha256",
        "runtime_catalog_fingerprint_sha256",
    ]) {
        boundedString(value[field], SHA256_PATTERN, field);
    }
    return value;
}

function validateConnectorBinding(value) {
    assertExactKeys(value, [
        "provider",
        "owner_kind",
        "owner_id",
        "owner_resolution",
        "tool_name",
        "tool_schema_fingerprint",
        "effective_catalog_fingerprint_sha256",
    ], [], "connector_binding");
    if (value.provider !== "github"
        || value.owner_kind !== "mcp"
        || value.owner_resolution !== "exact") {
        fail(
            "CONNECTOR_OWNER_INVALID",
            "Phase 4C requires one exact GitHub MCP owner.",
        );
    }
    boundedString(value.owner_id, OWNER_ID_PATTERN, "owner_id");
    boundedString(value.tool_name, TOOL_PATTERN, "tool_name");
    if (value.tool_name !== GITHUB_DRAFT_PR_E2E_TOOL_NAME) {
        fail(
            "TOOL_NAME_MISMATCH",
            "The effective GitHub Draft PR tool name has drifted.",
        );
    }
    boundedString(
        value.tool_schema_fingerprint,
        SHA256_PATTERN,
        "tool_schema_fingerprint",
    );
    boundedString(
        value.effective_catalog_fingerprint_sha256,
        SHA256_PATTERN,
        "effective_catalog_fingerprint_sha256",
    );
    return value;
}

function validateTransportBinding(value) {
    assertExactKeys(value, [
        "platform",
        "transport",
        "server_name",
        "exact_tool_id",
        "raw_tool_name",
        "raw_input_schema_fingerprint",
        "adapter_contract",
        "reviewers_allowed",
        "maintainer_can_modify",
    ], [], "transport_binding");
    if (value.platform !== "openclaw"
        || value.transport !== "mcp_stdio"
        || value.server_name !== GITHUB_DRAFT_PR_E2E_MCP_SERVER_NAME
        || value.exact_tool_id !== GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID
        || value.raw_tool_name !== GITHUB_DRAFT_PR_E2E_MCP_RAW_TOOL_NAME
        || value.raw_input_schema_fingerprint
            !== GITHUB_DRAFT_PR_E2E_MCP_RAW_SCHEMA_FINGERPRINT
        || value.adapter_contract
            !== GITHUB_DRAFT_PR_E2E_TRANSPORT_ADAPTER) {
        fail(
            "TRANSPORT_BINDING_MISMATCH",
            "The exact GitHub MCP transport binding has drifted.",
        );
    }
    exactBoolean(
        value.reviewers_allowed,
        false,
        "transport_binding.reviewers_allowed",
    );
    exactBoolean(
        value.maintainer_can_modify,
        false,
        "transport_binding.maintainer_can_modify",
    );
    return value;
}

function validatePhase4BPrerequisite(value, connector) {
    assertExactKeys(value, [
        "bundle_id",
        "bundle_fingerprint_sha256",
        "checkpoint_fingerprint_sha256",
        "registry_version",
        "policy_version",
        "registry_fingerprint_sha256",
        "inventory_snapshot_fingerprint_sha256",
        "inventory_binding_fingerprint_sha256",
        "profile_id",
        "scope",
        "tool_name",
        "owner_kind",
        "owner_id",
        "tool_schema_fingerprint",
        "owner_exact",
        "schema_matches",
        "policy_matches",
        "phase4c_contract_prerequisite_ready",
        "phase4c_external_write_authority_granted",
    ], [], "phase4b_prerequisite");
    for (const field of [
        "bundle_fingerprint_sha256",
        "checkpoint_fingerprint_sha256",
        "registry_fingerprint_sha256",
        "inventory_snapshot_fingerprint_sha256",
        "inventory_binding_fingerprint_sha256",
        "tool_schema_fingerprint",
    ]) {
        boundedString(value[field], SHA256_PATTERN, field);
    }
    boundedString(
        value.bundle_id,
        /^nrpolicy_[a-f0-9]{32}$/,
        "bundle_id",
    );
    boundedString(
        value.registry_version,
        /^nrcr_[a-z0-9][a-z0-9._-]{2,63}$/,
        "registry_version",
    );
    boundedString(
        value.policy_version,
        /^nrp_[a-z0-9][a-z0-9._-]{2,63}$/,
        "policy_version",
    );
    if (value.profile_id !== GITHUB_DRAFT_PR_E2E_PROFILE_ID
        || value.scope !== GITHUB_DRAFT_PR_E2E_SCOPE
        || value.tool_name !== connector.tool_name
        || value.owner_kind !== connector.owner_kind
        || value.owner_id !== connector.owner_id
        || value.tool_schema_fingerprint
            !== connector.tool_schema_fingerprint) {
        fail(
            "PHASE4B_BINDING_MISMATCH",
            "Phase 4B policy, owner, schema, or tool binding has drifted.",
        );
    }
    exactBoolean(value.owner_exact, true, "owner_exact");
    exactBoolean(value.schema_matches, true, "schema_matches");
    exactBoolean(value.policy_matches, true, "policy_matches");
    exactBoolean(
        value.phase4c_contract_prerequisite_ready,
        true,
        "phase4c_contract_prerequisite_ready",
    );
    exactBoolean(
        value.phase4c_external_write_authority_granted,
        false,
        "phase4c_external_write_authority_granted",
    );
    return value;
}

function validateTarget(value) {
    assertExactKeys(value, [
        "repository_full_name",
        "base_ref",
        "base_sha",
        "head_ref",
        "head_sha",
        "changed_paths",
    ], [], "target");
    boundedString(
        value.repository_full_name,
        REPOSITORY_PATTERN,
        "target.repository_full_name",
        3,
        200,
    );
    boundedString(value.base_ref, REF_PATTERN, "target.base_ref", 1, 255);
    boundedString(value.head_ref, REF_PATTERN, "target.head_ref", 1, 255);
    boundedString(value.base_sha, SHA_PATTERN, "target.base_sha", 40, 40);
    boundedString(value.head_sha, SHA_PATTERN, "target.head_sha", 40, 40);
    if (value.base_ref !== "main"
        || value.head_ref === "main"
        || value.head_ref === value.base_ref
        || value.head_sha === value.base_sha) {
        fail(
            "TARGET_BRANCH_INVALID",
            "Phase 4C target must be one exact non-main branch ahead of main.",
        );
    }
    return {
        ...value,
        changed_paths: validateChangedPaths(value.changed_paths),
    };
}

function validateOwnerApproval(value, now) {
    assertExactKeys(value, [
        "kind",
        "decision",
        "decision_automated",
        "evidence_source",
        "evidence_fingerprint_sha256",
        "approved_at",
        "expires_at",
    ], [], "owner_approval");
    if (value.kind !== "verified_human_owner"
        || value.decision !== "approved_once"
        || value.evidence_source !== "interactive_user_message") {
        fail(
            "OWNER_APPROVAL_INVALID",
            "One explicit interactive Verified Human Owner approval is required.",
        );
    }
    exactBoolean(
        value.decision_automated,
        false,
        "owner_approval.decision_automated",
    );
    boundedString(
        value.evidence_fingerprint_sha256,
        SHA256_PATTERN,
        "owner_approval.evidence_fingerprint_sha256",
    );
    const approvedAt = parseTime(value.approved_at, "approved_at");
    const expiresAt = parseTime(value.expires_at, "expires_at");
    if (expiresAt <= approvedAt
        || expiresAt - approvedAt > MAX_APPROVAL_WINDOW_MS
        || approvedAt > now.getTime()
        || expiresAt <= now.getTime()) {
        fail(
            "OWNER_APPROVAL_EXPIRED",
            "Owner approval is expired, future-dated, or too broad.",
        );
    }
    return value;
}

function planProjection(plan) {
    return {
        contract_version: plan.contract_version,
        proof_mode: plan.proof_mode,
        live_plugin_armed: plan.live_plugin_armed,
        proof_id: plan.proof_id,
        agent_binding: plan.agent_binding,
        owner_binding: plan.owner_binding,
        runtime_binding: plan.runtime_binding,
        connector_binding: plan.connector_binding,
        transport_binding: plan.transport_binding,
        phase4b_prerequisite: plan.phase4b_prerequisite,
        receipt_trust_anchor: plan.receipt_trust_anchor,
        target: plan.target,
        payload_binding: plan.payload_binding,
        owner_approval: plan.owner_approval,
        approval_id: plan.approval_id,
        lease: plan.lease,
        intent: plan.intent,
        boundaries: plan.boundaries,
        created_at: plan.created_at,
        expires_at: plan.expires_at,
    };
}

export function githubDraftPrE2EPlanFingerprint(plan) {
    return sha256Fingerprint(planProjection(plan));
}

export function createGitHubDraftPrE2EPlan(input, options = {}) {
    assertExactKeys(input, [
        "nonce",
        "agent_binding",
        "owner_binding",
        "runtime_binding",
        "connector_binding",
        "transport_binding",
        "phase4b_prerequisite",
        "receipt_trust_anchor",
        "target",
        "payload",
        "owner_approval",
        "created_at",
        "expires_at",
    ], [], "Phase 4C plan input");
    boundedString(input.nonce, NONCE_PATTERN, "nonce", 64, 64);
    const now = normalizeNow(options.now ?? Date.now());
    const agentBinding = cloneJson(
        validateAgentBinding(input.agent_binding),
    );
    const ownerBinding = cloneJson(
        validateOwnerBinding(input.owner_binding),
    );
    const runtimeBinding = cloneJson(
        validateRuntimeBinding(input.runtime_binding),
    );
    const connectorBinding = cloneJson(
        validateConnectorBinding(input.connector_binding),
    );
    const transportBinding = cloneJson(
        validateTransportBinding(input.transport_binding),
    );
    const prerequisite = cloneJson(validatePhase4BPrerequisite(
        input.phase4b_prerequisite,
        connectorBinding,
    ));
    const receiptTrustAnchor = cloneJson(validateReceiptTrustAnchor(
        input.receipt_trust_anchor,
    ));
    const target = validateTarget(input.target);
    const payloadProjection = githubDraftPrPayloadProjection(input.payload);
    if (payloadProjection.repository_full_name
            !== target.repository_full_name
        || payloadProjection.head_ref !== target.head_ref
        || payloadProjection.base_ref !== target.base_ref) {
        fail(
            "PAYLOAD_TARGET_MISMATCH",
            "GitHub Draft PR payload does not match the exact reviewed target.",
        );
    }
    const ownerApproval = cloneJson(validateOwnerApproval(
        input.owner_approval,
        now,
    ));
    const createdAt = parseTime(input.created_at, "created_at");
    const expiresAt = parseTime(input.expires_at, "expires_at");
    if (createdAt > now.getTime()
        || expiresAt <= now.getTime()
        || expiresAt > parseTime(ownerApproval.expires_at, "approval.expires_at")
        || expiresAt - createdAt > MAX_APPROVAL_WINDOW_MS) {
        fail(
            "PROOF_WINDOW_INVALID",
            "Phase 4C proof window is invalid.",
        );
    }
    const seed = {
        nonce: input.nonce,
        agent_binding: agentBinding,
        owner_binding: ownerBinding,
        runtime_binding: runtimeBinding,
        transport_binding: transportBinding,
        receipt_trust_anchor: receiptTrustAnchor,
        target,
        payload_fingerprint_sha256:
            githubDraftPrPayloadFingerprint(input.payload),
        created_at: input.created_at,
    };
    const proofId = idFor("nrp4c_", seed);
    const approvalId = idFor("nrcapdec_", {
        proof_id: proofId,
        owner_approval: ownerApproval,
    });
    const leaseId = idFor("nrlv2_", {
        proof_id: proofId,
        approval_id: approvalId,
    });
    const intentId = idFor("nreai_", {
        proof_id: proofId,
        lease_id: leaseId,
        payload: payloadProjection,
    });
    const reservationId = idFor("nrdispatch_", {
        intent_id: intentId,
        nonce: input.nonce,
    });
    const plan = {
        contract_version: GITHUB_DRAFT_PR_E2E_CONTRACT_VERSION,
        proof_mode: "isolated_owner_approved_once",
        live_plugin_armed: GITHUB_DRAFT_PR_E2E_LIVE_PLUGIN_ARMED,
        proof_id: proofId,
        agent_binding: agentBinding,
        owner_binding: ownerBinding,
        runtime_binding: runtimeBinding,
        connector_binding: connectorBinding,
        transport_binding: transportBinding,
        phase4b_prerequisite: prerequisite,
        receipt_trust_anchor: receiptTrustAnchor,
        target: cloneJson(target),
        payload_binding: {
            payload_projection: payloadProjection,
            payload_fingerprint_sha256:
                githubDraftPrPayloadFingerprint(input.payload),
            transport_payload_fingerprint_sha256:
                githubMcpCreatePullRequestParamsFingerprint(input.payload),
            raw_title_persisted: false,
            raw_body_persisted: false,
        },
        owner_approval: ownerApproval,
        approval_id: approvalId,
        lease: {
            lease_id: leaseId,
            scope: GITHUB_DRAFT_PR_E2E_SCOPE,
            profile_id: GITHUB_DRAFT_PR_E2E_PROFILE_ID,
            approval_policy: "allow_once",
            max_actions: 1,
            automatic_write_retry_allowed: false,
            shared_lease_allowed: false,
            shared_run_secret_allowed: false,
        },
        intent: {
            intent_id: intentId,
            reservation_id: reservationId,
            max_provider_attempts: 1,
            reconcile_mode: "read_only",
            exactly_once_effect_claimed: false,
        },
        boundaries: {
            direct_main_push_allowed: false,
            non_draft_pull_request_allowed: false,
            workflow_edit_allowed: false,
            secret_access_allowed: false,
            credential_persistence_allowed: false,
            automatic_write_retry_allowed: false,
            read_only_reconcile_required_for_unknown: true,
            merge_allowed: false,
            publish_allowed: false,
            production_change_allowed: false,
        },
        created_at: input.created_at,
        expires_at: input.expires_at,
    };
    plan.plan_fingerprint_sha256 = githubDraftPrE2EPlanFingerprint(plan);
    return validateGitHubDraftPrE2EPlan(plan, { now });
}

export function validateGitHubDraftPrE2EPlan(plan, options = {}) {
    assertExactKeys(plan, [
        "contract_version",
        "proof_mode",
        "live_plugin_armed",
        "proof_id",
        "agent_binding",
        "owner_binding",
        "runtime_binding",
        "connector_binding",
        "transport_binding",
        "phase4b_prerequisite",
        "receipt_trust_anchor",
        "target",
        "payload_binding",
        "owner_approval",
        "approval_id",
        "lease",
        "intent",
        "boundaries",
        "created_at",
        "expires_at",
        "plan_fingerprint_sha256",
    ], [], "Phase 4C plan");
    if (plan.contract_version !== GITHUB_DRAFT_PR_E2E_CONTRACT_VERSION
        || plan.proof_mode !== "isolated_owner_approved_once") {
        fail("CONTRACT_VERSION_MISMATCH", "Phase 4C plan is unsupported.");
    }
    exactBoolean(plan.live_plugin_armed, false, "live_plugin_armed");
    boundedString(plan.proof_id, PROOF_ID_PATTERN, "proof_id");
    validateAgentBinding(plan.agent_binding);
    validateOwnerBinding(plan.owner_binding);
    validateRuntimeBinding(plan.runtime_binding);
    validateConnectorBinding(plan.connector_binding);
    validateTransportBinding(plan.transport_binding);
    validatePhase4BPrerequisite(
        plan.phase4b_prerequisite,
        plan.connector_binding,
    );
    validateReceiptTrustAnchor(plan.receipt_trust_anchor);
    const target = validateTarget(plan.target);
    assertExactKeys(plan.payload_binding, [
        "payload_projection",
        "payload_fingerprint_sha256",
        "transport_payload_fingerprint_sha256",
        "raw_title_persisted",
        "raw_body_persisted",
    ], [], "payload_binding");
    assertExactKeys(plan.payload_binding.payload_projection, [
        "repository_full_name",
        "head_ref",
        "base_ref",
        "draft",
        "title_sha256",
        "body_sha256",
    ], [], "payload_projection");
    if (plan.payload_binding.payload_projection.repository_full_name
            !== target.repository_full_name
        || plan.payload_binding.payload_projection.head_ref !== target.head_ref
        || plan.payload_binding.payload_projection.base_ref !== target.base_ref) {
        fail(
            "PAYLOAD_TARGET_MISMATCH",
            "Stored payload binding does not match the target.",
        );
    }
    for (const field of ["title_sha256", "body_sha256"]) {
        boundedString(
            plan.payload_binding.payload_projection[field],
            SHA256_PATTERN,
            field,
        );
    }
    exactBoolean(
        plan.payload_binding.payload_projection.draft,
        true,
        "payload_projection.draft",
    );
    boundedString(
        plan.payload_binding.payload_fingerprint_sha256,
        SHA256_PATTERN,
        "payload_fingerprint_sha256",
    );
    boundedString(
        plan.payload_binding.transport_payload_fingerprint_sha256,
        SHA256_PATTERN,
        "transport_payload_fingerprint_sha256",
    );
    exactBoolean(
        plan.payload_binding.raw_title_persisted,
        false,
        "raw_title_persisted",
    );
    exactBoolean(
        plan.payload_binding.raw_body_persisted,
        false,
        "raw_body_persisted",
    );
    const now = normalizeNow(options.now ?? Date.now());
    validateOwnerApproval(plan.owner_approval, now);
    boundedString(plan.approval_id, APPROVAL_ID_PATTERN, "approval_id");
    assertExactKeys(plan.lease, [
        "lease_id",
        "scope",
        "profile_id",
        "approval_policy",
        "max_actions",
        "automatic_write_retry_allowed",
        "shared_lease_allowed",
        "shared_run_secret_allowed",
    ], [], "lease");
    boundedString(plan.lease.lease_id, LEASE_ID_PATTERN, "lease_id");
    if (plan.lease.scope !== GITHUB_DRAFT_PR_E2E_SCOPE
        || plan.lease.profile_id !== GITHUB_DRAFT_PR_E2E_PROFILE_ID
        || plan.lease.approval_policy !== "allow_once") {
        fail("LEASE_SCOPE_INVALID", "Phase 4C lease scope is invalid.");
    }
    exactInteger(plan.lease.max_actions, "max_actions", 1);
    if (plan.lease.max_actions !== 1) {
        fail("LEASE_SCOPE_INVALID", "Phase 4C permits one action only.");
    }
    for (const field of [
        "automatic_write_retry_allowed",
        "shared_lease_allowed",
        "shared_run_secret_allowed",
    ]) {
        exactBoolean(plan.lease[field], false, `lease.${field}`);
    }
    assertExactKeys(plan.intent, [
        "intent_id",
        "reservation_id",
        "max_provider_attempts",
        "reconcile_mode",
        "exactly_once_effect_claimed",
    ], [], "intent");
    boundedString(plan.intent.intent_id, INTENT_ID_PATTERN, "intent_id");
    boundedString(
        plan.intent.reservation_id,
        RESERVATION_ID_PATTERN,
        "reservation_id",
    );
    if (plan.intent.max_provider_attempts !== 1
        || plan.intent.reconcile_mode !== "read_only") {
        fail("INTENT_BOUNDARY_INVALID", "Phase 4C intent boundary is invalid.");
    }
    exactBoolean(
        plan.intent.exactly_once_effect_claimed,
        false,
        "exactly_once_effect_claimed",
    );
    assertExactKeys(plan.boundaries, [
        "direct_main_push_allowed",
        "non_draft_pull_request_allowed",
        "workflow_edit_allowed",
        "secret_access_allowed",
        "credential_persistence_allowed",
        "automatic_write_retry_allowed",
        "read_only_reconcile_required_for_unknown",
        "merge_allowed",
        "publish_allowed",
        "production_change_allowed",
    ], [], "boundaries");
    for (const [field, expected] of Object.entries({
        direct_main_push_allowed: false,
        non_draft_pull_request_allowed: false,
        workflow_edit_allowed: false,
        secret_access_allowed: false,
        credential_persistence_allowed: false,
        automatic_write_retry_allowed: false,
        read_only_reconcile_required_for_unknown: true,
        merge_allowed: false,
        publish_allowed: false,
        production_change_allowed: false,
    })) {
        exactBoolean(plan.boundaries[field], expected, `boundaries.${field}`);
    }
    const createdAt = parseTime(plan.created_at, "created_at");
    const expiresAt = parseTime(plan.expires_at, "expires_at");
    if (expiresAt <= createdAt || expiresAt <= now.getTime()) {
        fail("PROOF_EXPIRED", "Phase 4C plan has expired.");
    }
    boundedString(
        plan.plan_fingerprint_sha256,
        SHA256_PATTERN,
        "plan_fingerprint_sha256",
    );
    if (plan.plan_fingerprint_sha256
        !== githubDraftPrE2EPlanFingerprint(plan)) {
        fail("PLAN_FINGERPRINT_MISMATCH", "Phase 4C plan has drifted.");
    }
    assertNoSensitiveFields(plan);
    return deepFreeze(cloneJson(plan));
}

function initialRecord(plan, now) {
    return {
        contract_version: GITHUB_DRAFT_PR_E2E_CONTRACT_VERSION,
        proof_id: plan.proof_id,
        plan_fingerprint_sha256: plan.plan_fingerprint_sha256,
        state: "armed",
        revision: 1,
        provider_attempt_count: 0,
        approval_consumed: false,
        lease_actions_consumed: 0,
        lease_actions_remaining: 1,
        tool_call_id: null,
        outcome: null,
        receipt: null,
        revocation: {
            revoked: false,
            revoked_at: null,
            reason_code: null,
            sequence: 0,
        },
        created_at: now.toISOString(),
        updated_at: now.toISOString(),
    };
}

function validateReceiptAttestation(receipt, expectedTrustAnchor = null) {
    assertExactKeys(receipt.attestation, [
        "issuer",
        "algorithm",
        "key_id",
        "public_key_jwk",
        "key_thumbprint_sha256",
        "signed_receipt_fingerprint_sha256",
        "signed_at",
        "signature_base64url",
    ], [], "receipt.attestation");
    if (receipt.attestation.issuer !== "noderooms-isolated-proof"
        || receipt.attestation.algorithm !== "Ed25519") {
        fail("RECEIPT_ATTESTATION_INVALID", "Receipt attestation is invalid.");
    }
    boundedString(
        receipt.attestation.key_id,
        KEY_ID_PATTERN,
        "attestation.key_id",
    );
    const publicJwk = validatePublicJwk(
        receipt.attestation.public_key_jwk,
    );
    boundedString(
        receipt.attestation.key_thumbprint_sha256,
        SHA256_PATTERN,
        "attestation.key_thumbprint_sha256",
    );
    if (receipt.attestation.key_thumbprint_sha256
        !== publicJwkThumbprint(publicJwk)
        || receipt.attestation.signed_receipt_fingerprint_sha256
            !== receipt.receipt_fingerprint_sha256) {
        fail(
            "RECEIPT_ATTESTATION_INVALID",
            "Receipt attestation binding is invalid.",
        );
    }
    if (expectedTrustAnchor !== null) {
        const trusted = validateReceiptTrustAnchor(expectedTrustAnchor);
        if (receipt.attestation.issuer !== trusted.issuer
            || receipt.attestation.algorithm !== trusted.algorithm
            || receipt.attestation.key_id !== trusted.key_id
            || receipt.attestation.key_thumbprint_sha256
                !== trusted.key_thumbprint_sha256
            || !sameJson(
                receipt.attestation.public_key_jwk,
                trusted.public_key_jwk,
            )) {
            fail(
                "RECEIPT_TRUST_ANCHOR_MISMATCH",
                "Receipt does not match the approved trust anchor.",
            );
        }
    }
    parseTime(receipt.attestation.signed_at, "attestation.signed_at");
    boundedString(
        receipt.attestation.signature_base64url,
        SIGNATURE_PATTERN,
        "attestation.signature_base64url",
    );
    let verified = false;
    try {
        verified = verify(
            null,
            Buffer.from(
                receiptSignaturePayload(
                    receipt.receipt_fingerprint_sha256,
                ),
                "utf8",
            ),
            createPublicKey({ key: publicJwk, format: "jwk" }),
            Buffer.from(
                receipt.attestation.signature_base64url,
                "base64url",
            ),
        );
    }
    catch {
        verified = false;
    }
    if (!verified) {
        fail("RECEIPT_SIGNATURE_INVALID", "Receipt signature is invalid.");
    }
}

function receiptProjection(receipt) {
    return {
        contract_version: receipt.contract_version,
        receipt_id: receipt.receipt_id,
        proof_id: receipt.proof_id,
        plan_fingerprint_sha256: receipt.plan_fingerprint_sha256,
        intent_id: receipt.intent_id,
        reservation_id: receipt.reservation_id,
        lease_id: receipt.lease_id,
        approval_id: receipt.approval_id,
        tool_call_id: receipt.tool_call_id,
        outcome: receipt.outcome,
        dispatch: receipt.dispatch,
        approval_consumption: receipt.approval_consumption,
        reconciliation: receipt.reconciliation,
        safety: receipt.safety,
        recorded_at: receipt.recorded_at,
    };
}

export function githubDraftPrE2EReceiptFingerprint(receipt) {
    return sha256Fingerprint(receiptProjection(receipt));
}

function createAttestedReceipt(
    plan,
    record,
    outcome,
    now,
    reconciliation,
    receiptSigner,
) {
    const receipt = {
        contract_version:
            GITHUB_DRAFT_PR_E2E_RECEIPT_CONTRACT_VERSION,
        receipt_id: idFor("nrear_", {
            proof_id: plan.proof_id,
            tool_call_id: record.tool_call_id,
            outcome,
            reconciliation,
        }),
        proof_id: plan.proof_id,
        plan_fingerprint_sha256: plan.plan_fingerprint_sha256,
        intent_id: plan.intent.intent_id,
        reservation_id: plan.intent.reservation_id,
        lease_id: plan.lease.lease_id,
        approval_id: plan.approval_id,
        tool_call_id: record.tool_call_id,
        outcome,
        dispatch: {
            provider_attempt_count: 1,
            max_provider_attempts: 1,
            at_most_once_dispatch_enforced: true,
            automatic_write_retry_attempted: false,
            exactly_once_effect_claimed: false,
            provider_tool_id:
                plan.transport_binding.exact_tool_id,
            provider_raw_tool_name:
                plan.transport_binding.raw_tool_name,
            raw_input_schema_fingerprint:
                plan.transport_binding.raw_input_schema_fingerprint,
            transport_adapter:
                plan.transport_binding.adapter_contract,
        },
        approval_consumption: {
            policy: "allow_once",
            consumed: true,
            lease_actions_before: 0,
            lease_actions_after: 1,
        },
        reconciliation,
        safety: {
            raw_title_included: false,
            raw_body_included: false,
            raw_provider_response_included: false,
            provider_credentials_included: false,
            direct_main_push_attempted: false,
            workflow_edit_attempted: false,
            merge_attempted: false,
            publish_attempted: false,
            production_modified: false,
        },
        recorded_at: now.toISOString(),
    };
    receipt.receipt_fingerprint_sha256 =
        githubDraftPrE2EReceiptFingerprint(receipt);
    const trustAnchor = validateReceiptTrustAnchor(
        receiptSigner.trust_anchor,
    );
    if (!sameJson(trustAnchor, plan.receipt_trust_anchor)) {
        fail(
            "RECEIPT_TRUST_ANCHOR_MISMATCH",
            "Receipt signer differs from the approved plan.",
        );
    }
    const signature = receiptSigner.signReceiptFingerprint(
        receipt.receipt_fingerprint_sha256,
    );
    receipt.attestation = {
        issuer: trustAnchor.issuer,
        algorithm: trustAnchor.algorithm,
        key_id: trustAnchor.key_id,
        public_key_jwk: trustAnchor.public_key_jwk,
        key_thumbprint_sha256:
            trustAnchor.key_thumbprint_sha256,
        signed_receipt_fingerprint_sha256:
            receipt.receipt_fingerprint_sha256,
        signed_at: now.toISOString(),
        signature_base64url: signature,
    };
    return validateGitHubDraftPrE2EReceipt(receipt, {
        expectedTrustAnchor: trustAnchor,
    });
}

export function validateGitHubDraftPrE2EReceipt(receipt, options = {}) {
    assertExactKeys(receipt, [
        "contract_version",
        "receipt_id",
        "proof_id",
        "plan_fingerprint_sha256",
        "intent_id",
        "reservation_id",
        "lease_id",
        "approval_id",
        "tool_call_id",
        "outcome",
        "dispatch",
        "approval_consumption",
        "reconciliation",
        "safety",
        "recorded_at",
        "receipt_fingerprint_sha256",
        "attestation",
    ], [], "Phase 4C receipt");
    if (receipt.contract_version
        !== GITHUB_DRAFT_PR_E2E_RECEIPT_CONTRACT_VERSION) {
        fail("RECEIPT_VERSION_INVALID", "Phase 4C receipt is unsupported.");
    }
    boundedString(receipt.receipt_id, RECEIPT_ID_PATTERN, "receipt_id");
    boundedString(receipt.proof_id, PROOF_ID_PATTERN, "proof_id");
    for (const field of ["plan_fingerprint_sha256"]) {
        boundedString(receipt[field], SHA256_PATTERN, field);
    }
    boundedString(receipt.intent_id, INTENT_ID_PATTERN, "intent_id");
    boundedString(
        receipt.reservation_id,
        RESERVATION_ID_PATTERN,
        "reservation_id",
    );
    boundedString(receipt.lease_id, LEASE_ID_PATTERN, "lease_id");
    boundedString(
        receipt.approval_id,
        APPROVAL_ID_PATTERN,
        "approval_id",
    );
    boundedString(
        receipt.tool_call_id,
        CONTEXT_ID_PATTERN,
        "tool_call_id",
    );
    assertExactKeys(receipt.outcome, [
        "status",
        "certainty",
        "provider_object",
        "reason_code",
        "outcome_fingerprint_sha256",
    ], [], "receipt.outcome");
    if (!["committed", "unknown", "no_effect"].includes(
        receipt.outcome.status,
    )) {
        fail("OUTCOME_INVALID", "Phase 4C outcome is invalid.");
    }
    if (!["known", "unknown"].includes(receipt.outcome.certainty)) {
        fail("OUTCOME_INVALID", "Phase 4C certainty is invalid.");
    }
    if (receipt.outcome.status === "committed") {
        if (receipt.outcome.certainty !== "known"
            || !isRecord(receipt.outcome.provider_object)
            || receipt.outcome.reason_code !== null) {
            fail("OUTCOME_INVALID", "Committed outcome is inconsistent.");
        }
    }
    else if (receipt.outcome.status === "unknown") {
        if (receipt.outcome.certainty !== "unknown"
            || receipt.outcome.provider_object !== null) {
            fail("OUTCOME_INVALID", "Unknown outcome is inconsistent.");
        }
        boundedString(
            receipt.outcome.reason_code,
            REASON_PATTERN,
            "receipt.outcome.reason_code",
        );
    }
    else if (receipt.outcome.certainty !== "known"
        || receipt.outcome.provider_object !== null) {
        fail("OUTCOME_INVALID", "No-effect outcome is inconsistent.");
    }
    if (receipt.outcome.status === "no_effect") {
        boundedString(
            receipt.outcome.reason_code,
            REASON_PATTERN,
            "receipt.outcome.reason_code",
        );
    }
    boundedString(
        receipt.outcome.outcome_fingerprint_sha256,
        SHA256_PATTERN,
        "outcome_fingerprint_sha256",
    );
    if (receipt.outcome.outcome_fingerprint_sha256
        !== sha256Fingerprint({
            status: receipt.outcome.status,
            certainty: receipt.outcome.certainty,
            provider_object: receipt.outcome.provider_object,
            reason_code: receipt.outcome.reason_code,
        })) {
        fail("OUTCOME_FINGERPRINT_MISMATCH", "Outcome has drifted.");
    }
    assertExactKeys(receipt.dispatch, [
        "provider_attempt_count",
        "max_provider_attempts",
        "at_most_once_dispatch_enforced",
        "automatic_write_retry_attempted",
        "exactly_once_effect_claimed",
        "provider_tool_id",
        "provider_raw_tool_name",
        "raw_input_schema_fingerprint",
        "transport_adapter",
    ], [], "receipt.dispatch");
    if (receipt.dispatch.provider_attempt_count !== 1
        || receipt.dispatch.max_provider_attempts !== 1) {
        fail("DISPATCH_COUNT_INVALID", "Exactly one provider attempt is required.");
    }
    exactBoolean(
        receipt.dispatch.at_most_once_dispatch_enforced,
        true,
        "at_most_once_dispatch_enforced",
    );
    exactBoolean(
        receipt.dispatch.automatic_write_retry_attempted,
        false,
        "automatic_write_retry_attempted",
    );
    exactBoolean(
        receipt.dispatch.exactly_once_effect_claimed,
        false,
        "exactly_once_effect_claimed",
    );
    if (receipt.dispatch.provider_tool_id
            !== GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID
        || receipt.dispatch.provider_raw_tool_name
            !== GITHUB_DRAFT_PR_E2E_MCP_RAW_TOOL_NAME
        || receipt.dispatch.raw_input_schema_fingerprint
            !== GITHUB_DRAFT_PR_E2E_MCP_RAW_SCHEMA_FINGERPRINT
        || receipt.dispatch.transport_adapter
            !== GITHUB_DRAFT_PR_E2E_TRANSPORT_ADAPTER) {
        fail(
            "RECEIPT_TRANSPORT_BINDING_INVALID",
            "Receipt transport binding is invalid.",
        );
    }
    assertExactKeys(receipt.approval_consumption, [
        "policy",
        "consumed",
        "lease_actions_before",
        "lease_actions_after",
    ], [], "approval_consumption");
    if (receipt.approval_consumption.policy !== "allow_once"
        || receipt.approval_consumption.lease_actions_before !== 0
        || receipt.approval_consumption.lease_actions_after !== 1) {
        fail("APPROVAL_CONSUMPTION_INVALID", "Approval consumption is invalid.");
    }
    exactBoolean(
        receipt.approval_consumption.consumed,
        true,
        "approval_consumption.consumed",
    );
    assertExactKeys(receipt.reconciliation, [
        "mode",
        "attempted",
        "provider_write_attempted",
        "observation_fingerprint_sha256",
    ], [], "reconciliation");
    if (receipt.reconciliation.mode !== "read_only") {
        fail("RECONCILIATION_INVALID", "Reconciliation must be read-only.");
    }
    if (typeof receipt.reconciliation.attempted !== "boolean") {
        fail(
            "RECONCILIATION_INVALID",
            "Reconciliation attempted flag is invalid.",
        );
    }
    exactBoolean(
        receipt.reconciliation.provider_write_attempted,
        false,
        "reconciliation.provider_write_attempted",
    );
    if (receipt.reconciliation.observation_fingerprint_sha256 !== null) {
        boundedString(
            receipt.reconciliation.observation_fingerprint_sha256,
            SHA256_PATTERN,
            "observation_fingerprint_sha256",
        );
    }
    if (receipt.reconciliation.attempted
            !== (receipt.reconciliation
                .observation_fingerprint_sha256 !== null)
        || (receipt.outcome.status === "unknown"
            && receipt.reconciliation.attempted)
        || (receipt.outcome.status === "no_effect"
            && !receipt.reconciliation.attempted)) {
        fail(
            "RECONCILIATION_INVALID",
            "Receipt reconciliation state is inconsistent.",
        );
    }
    assertExactKeys(receipt.safety, [
        "raw_title_included",
        "raw_body_included",
        "raw_provider_response_included",
        "provider_credentials_included",
        "direct_main_push_attempted",
        "workflow_edit_attempted",
        "merge_attempted",
        "publish_attempted",
        "production_modified",
    ], [], "receipt.safety");
    for (const [field, value] of Object.entries(receipt.safety)) {
        exactBoolean(value, false, `receipt.safety.${field}`);
    }
    parseTime(receipt.recorded_at, "receipt.recorded_at");
    boundedString(
        receipt.receipt_fingerprint_sha256,
        SHA256_PATTERN,
        "receipt_fingerprint_sha256",
    );
    if (receipt.receipt_fingerprint_sha256
        !== githubDraftPrE2EReceiptFingerprint(receipt)) {
        fail("RECEIPT_FINGERPRINT_MISMATCH", "Receipt has drifted.");
    }
    validateReceiptAttestation(
        receipt,
        options.expectedTrustAnchor ?? null,
    );
    assertNoSensitiveFields(receipt);
    return deepFreeze(cloneJson(receipt));
}

function validateProofRecord(record) {
    if (record === null) {
        return null;
    }
    assertExactKeys(record, [
        "contract_version",
        "proof_id",
        "plan_fingerprint_sha256",
        "state",
        "revision",
        "provider_attempt_count",
        "approval_consumed",
        "lease_actions_consumed",
        "lease_actions_remaining",
        "tool_call_id",
        "outcome",
        "receipt",
        "revocation",
        "created_at",
        "updated_at",
    ], [], "proof record");
    if (record.contract_version !== GITHUB_DRAFT_PR_E2E_CONTRACT_VERSION) {
        fail("STORE_RECORD_INVALID", "Proof record version is invalid.");
    }
    boundedString(record.proof_id, PROOF_ID_PATTERN, "record.proof_id");
    boundedString(
        record.plan_fingerprint_sha256,
        SHA256_PATTERN,
        "record.plan_fingerprint_sha256",
    );
    if (!["armed", "dispatching", "committed", "unknown", "no_effect", "revoked"]
        .includes(record.state)) {
        fail("STORE_RECORD_INVALID", "Proof record state is invalid.");
    }
    exactInteger(record.revision, "record.revision", 1);
    exactInteger(
        record.provider_attempt_count,
        "record.provider_attempt_count",
    );
    if (record.provider_attempt_count > 1) {
        fail("STORE_RECORD_INVALID", "Provider attempt count exceeded one.");
    }
    exactBoolean(
        record.approval_consumed,
        record.provider_attempt_count === 1,
        "record.approval_consumed",
    );
    if (record.lease_actions_consumed !== record.provider_attempt_count
        || record.lease_actions_remaining
            !== 1 - record.provider_attempt_count) {
        fail("STORE_RECORD_INVALID", "Lease action counters are invalid.");
    }
    if (record.tool_call_id !== null) {
        boundedString(
            record.tool_call_id,
            CONTEXT_ID_PATTERN,
            "record.tool_call_id",
        );
    }
    if (record.receipt !== null) {
        validateGitHubDraftPrE2EReceipt(record.receipt);
    }
    assertExactKeys(record.revocation, [
        "revoked",
        "revoked_at",
        "reason_code",
        "sequence",
    ], [], "record.revocation");
    exactInteger(record.revocation.sequence, "revocation.sequence");
    if (record.revocation.revoked) {
        parseTime(record.revocation.revoked_at, "revocation.revoked_at");
        boundedString(
            record.revocation.reason_code,
            REASON_PATTERN,
            "revocation.reason_code",
        );
        if (record.revocation.sequence < 1) {
            fail("STORE_RECORD_INVALID", "Revocation sequence is invalid.");
        }
    }
    else if (record.revocation.revoked_at !== null
        || record.revocation.reason_code !== null
        || record.revocation.sequence !== 0) {
        fail("STORE_RECORD_INVALID", "Non-revoked record has revocation data.");
    }
    parseTime(record.created_at, "record.created_at");
    parseTime(record.updated_at, "record.updated_at");
    assertNoSensitiveFields(record);
    return deepFreeze(cloneJson(record));
}

export function createInMemoryGitHubDraftPrProofStore(initial = null) {
    let record = initial === null ? null : validateProofRecord(initial);
    return Object.freeze({
        async load() {
            return record === null ? null : cloneJson(record);
        },
        async compareAndSet(expectedRevision, nextRecord) {
            const currentRevision = record?.revision ?? null;
            if (currentRevision !== expectedRevision) {
                return false;
            }
            record = validateProofRecord(nextRecord);
            return true;
        },
    });
}

function sleep(milliseconds) {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function withFileLock(lockPath, operation) {
    let handle;
    for (let attempt = 0; attempt < LOCK_RETRY_COUNT; attempt += 1) {
        try {
            handle = await open(lockPath, "wx", 0o600);
            break;
        }
        catch (error) {
            if (error?.code !== "EEXIST") {
                throw error;
            }
            await sleep(LOCK_RETRY_DELAY_MS);
        }
    }
    if (!handle) {
        fail("STORE_LOCK_UNAVAILABLE", "Phase 4C state lock is unavailable.");
    }
    try {
        return await operation();
    }
    finally {
        await handle.close();
        await unlink(lockPath).catch(() => undefined);
    }
}

async function readStoreDocument(filePath) {
    let raw;
    try {
        raw = await readFile(filePath, "utf8");
    }
    catch (error) {
        if (error?.code === "ENOENT") {
            return null;
        }
        throw error;
    }
    if (Buffer.byteLength(raw) > MAX_STORE_BYTES) {
        fail("STORE_INVALID", "Phase 4C state file is too large.");
    }
    let document;
    try {
        document = JSON.parse(raw);
    }
    catch {
        fail("STORE_INVALID", "Phase 4C state file is invalid JSON.");
    }
    assertExactKeys(document, ["version", "record"], [], "store");
    if (document.version !== STORE_VERSION) {
        fail("STORE_INVALID", "Phase 4C state version is unsupported.");
    }
    return validateProofRecord(document.record);
}

export function createFileGitHubDraftPrProofStore(filePath) {
    const resolved = path.resolve(filePath);
    const lockPath = `${resolved}.lock`;
    return Object.freeze({
        async load() {
            return readStoreDocument(resolved);
        },
        async compareAndSet(expectedRevision, nextRecord) {
            await mkdir(path.dirname(resolved), { recursive: true });
            return withFileLock(lockPath, async () => {
                const current = await readStoreDocument(resolved);
                if ((current?.revision ?? null) !== expectedRevision) {
                    return false;
                }
                const validated = validateProofRecord(nextRecord);
                const temporary = `${resolved}.${process.pid}.tmp`;
                await writeFile(
                    temporary,
                    `${JSON.stringify({
                        version: STORE_VERSION,
                        record: validated,
                    }, null, 2)}\n`,
                    { encoding: "utf8", mode: 0o600 },
                );
                await rename(temporary, resolved);
                return true;
            });
        },
    });
}

function exactContext(plan, context) {
    assertExactKeys(context, [
        "platform",
        "openclaw_version",
        "openclaw_agent_id",
        "session_key_fingerprint_sha256",
        "gateway_instance_fingerprint_sha256",
        "runtime_catalog_fingerprint_sha256",
    ], [], "tool context");
    validateRuntimeBinding(context);
    if (!sameJson(context, plan.runtime_binding)) {
        fail("RUNTIME_BINDING_MISMATCH", "OpenClaw runtime binding has drifted.");
    }
}

function successfulProviderObject(plan, providerObject) {
    assertExactKeys(providerObject, [
        "type",
        "repository_full_name",
        "number",
        "url",
        "state",
        "draft",
        "base_ref",
        "base_sha",
        "head_ref",
        "head_sha",
    ], [], "provider_object");
    if (providerObject.type !== "pull_request"
        || providerObject.repository_full_name
            !== plan.target.repository_full_name
        || providerObject.state !== "open"
        || providerObject.draft !== true
        || providerObject.base_ref !== plan.target.base_ref
        || providerObject.base_sha !== plan.target.base_sha
        || providerObject.head_ref !== plan.target.head_ref
        || providerObject.head_sha !== plan.target.head_sha) {
        fail(
            "PROVIDER_OBJECT_MISMATCH",
            "Created Draft PR does not match the reviewed exact target.",
        );
    }
    exactInteger(providerObject.number, "provider_object.number", 1);
    boundedString(providerObject.url, URL_PATTERN, "provider_object.url");
    const expectedUrl = `https://github.com/${plan.target.repository_full_name}/pull/${providerObject.number}`;
    if (providerObject.url !== expectedUrl) {
        fail("PROVIDER_OBJECT_MISMATCH", "Draft PR URL is invalid.");
    }
    return cloneJson(providerObject);
}

function buildOutcome(plan, outcome) {
    assertExactKeys(outcome, [
        "ok",
        "certainty",
        "provider_object",
        "reason_code",
    ], [], "tool outcome");
    let status;
    let providerObject = null;
    let reasonCode = null;
    if (outcome.ok === true) {
        if (outcome.certainty !== "known" || outcome.reason_code !== null) {
            fail("OUTCOME_INVALID", "Successful outcome must be known.");
        }
        providerObject = successfulProviderObject(
            plan,
            outcome.provider_object,
        );
        status = "committed";
    }
    else {
        exactBoolean(outcome.ok, false, "outcome.ok");
        if (outcome.certainty !== "unknown"
            || outcome.provider_object !== null) {
            fail(
                "OUTCOME_INVALID",
                "A failed provider attempt is conservatively unknown.",
            );
        }
        boundedString(
            outcome.reason_code,
            REASON_PATTERN,
            "outcome.reason_code",
        );
        reasonCode = outcome.reason_code;
        status = "unknown";
    }
    const value = {
        status,
        certainty: outcome.certainty,
        provider_object: providerObject,
        reason_code: reasonCode,
    };
    value.outcome_fingerprint_sha256 = sha256Fingerprint(value);
    return value;
}

function reconciliationValue(attempted, observation = null) {
    return {
        mode: "read_only",
        attempted,
        provider_write_attempted: false,
        observation_fingerprint_sha256: observation === null
            ? null
            : sha256Fingerprint(observation),
    };
}

function safeControllerError(error) {
    return error instanceof GitHubDraftPrE2EError
        ? error
        : new GitHubDraftPrE2EError(
            "PHASE4C_UNAVAILABLE",
            "Phase 4C stopped safely.",
        );
}

function assertRecordMatchesPlan(plan, record) {
    if (record === null) {
        return;
    }
    if (record.proof_id !== plan.proof_id
        || record.plan_fingerprint_sha256
            !== plan.plan_fingerprint_sha256) {
        fail(
            "STORE_PLAN_CONFLICT",
            "Phase 4C state belongs to another plan.",
        );
    }
    if (record.receipt !== null) {
        const receipt = validateGitHubDraftPrE2EReceipt(record.receipt, {
            expectedTrustAnchor: plan.receipt_trust_anchor,
        });
        if (receipt.proof_id !== plan.proof_id
            || receipt.plan_fingerprint_sha256
                !== plan.plan_fingerprint_sha256
            || receipt.intent_id !== plan.intent.intent_id
            || receipt.reservation_id !== plan.intent.reservation_id
            || receipt.lease_id !== plan.lease.lease_id
            || receipt.approval_id !== plan.approval_id
            || receipt.tool_call_id !== record.tool_call_id) {
            fail(
                "RECEIPT_PLAN_MISMATCH",
                "Phase 4C receipt differs from the approved plan.",
            );
        }
        if (receipt.outcome.status === "committed") {
            successfulProviderObject(
                plan,
                receipt.outcome.provider_object,
            );
        }
    }
}

export class GitHubDraftPrE2EController {
    constructor(options = {}) {
        this.plan = validateGitHubDraftPrE2EPlan(options.plan, {
            now: options.now?.() ?? Date.now(),
        });
        if (!isRecord(options.receiptSigner)
            || !isRecord(options.receiptSigner.trust_anchor)
            || typeof options.receiptSigner.signReceiptFingerprint
                !== "function") {
            fail(
                "RECEIPT_SIGNER_REQUIRED",
                "The approved receipt signer is required.",
            );
        }
        const signerTrustAnchor = validateReceiptTrustAnchor(
            options.receiptSigner.trust_anchor,
        );
        if (!sameJson(
            signerTrustAnchor,
            this.plan.receipt_trust_anchor,
        )) {
            fail(
                "RECEIPT_TRUST_ANCHOR_MISMATCH",
                "Receipt signer differs from the approved plan.",
            );
        }
        this.receiptSigner = options.receiptSigner;
        this.store = options.store
            ?? createInMemoryGitHubDraftPrProofStore();
        this.now = typeof options.now === "function"
            ? options.now
            : () => new Date();
    }

    async arm() {
        const now = normalizeNow(this.now());
        validateGitHubDraftPrE2EPlan(this.plan, { now });
        const current = await this.store.load();
        assertRecordMatchesPlan(this.plan, current);
        if (current !== null) {
            if (current.state === "armed") {
                return Object.freeze({
                    armed: true,
                    idempotent: true,
                    proof_id: this.plan.proof_id,
                    state: current.state,
                    revision: current.revision,
                });
            }
            fail(
                "PROOF_ALREADY_CONSUMED",
                "Phase 4C cannot be re-armed after dispatch or revocation.",
            );
        }
        const record = initialRecord(this.plan, now);
        if (!await this.store.compareAndSet(null, record)) {
            fail(
                "STORE_CONFLICT",
                "Phase 4C state changed while arming.",
            );
        }
        return Object.freeze({
            armed: true,
            idempotent: false,
            proof_id: this.plan.proof_id,
            state: record.state,
            revision: record.revision,
        });
    }

    async beforeToolCall(event, context) {
        const now = normalizeNow(this.now());
        validateGitHubDraftPrE2EPlan(this.plan, { now });
        assertExactKeys(event, [
            "tool_name",
            "tool_call_id",
            "params",
        ], [], "before_tool_call event");
        if (event.tool_name !== this.plan.connector_binding.tool_name) {
            fail("TOOL_NAME_MISMATCH", "Unexpected connector tool.");
        }
        boundedString(
            event.tool_call_id,
            CONTEXT_ID_PATTERN,
            "tool_call_id",
        );
        exactContext(this.plan, context);
        const projection = githubDraftPrPayloadProjection(event.params);
        const fingerprint = githubDraftPrPayloadFingerprint(event.params);
        const providerParams =
            githubMcpCreatePullRequestParams(event.params);
        const transportFingerprint =
            githubMcpCreatePullRequestParamsFingerprint(event.params);
        if (!sameJson(
            projection,
            this.plan.payload_binding.payload_projection,
        ) || fingerprint
            !== this.plan.payload_binding.payload_fingerprint_sha256
        || transportFingerprint
            !== this.plan.payload_binding
                .transport_payload_fingerprint_sha256) {
            fail(
                "PAYLOAD_FINGERPRINT_MISMATCH",
                "Draft PR parameters differ from the approved immutable intent.",
            );
        }
        const current = await this.store.load();
        assertRecordMatchesPlan(this.plan, current);
        if (!current) {
            fail("PROOF_NOT_ARMED", "Phase 4C proof is not armed.");
        }
        if (current.revocation.revoked || current.state === "revoked") {
            fail("LEASE_REVOKED", "Phase 4C authority is revoked.");
        }
        if (current.state !== "armed"
            || current.provider_attempt_count !== 0
            || current.approval_consumed
            || current.lease_actions_remaining !== 1) {
            fail(
                "REPLAY_BLOCKED",
                "Phase 4C permits no second provider attempt.",
            );
        }
        const next = {
            ...cloneJson(current),
            state: "dispatching",
            revision: current.revision + 1,
            provider_attempt_count: 1,
            approval_consumed: true,
            lease_actions_consumed: 1,
            lease_actions_remaining: 0,
            tool_call_id: event.tool_call_id,
            updated_at: now.toISOString(),
        };
        if (!await this.store.compareAndSet(current.revision, next)) {
            fail(
                "CONCURRENT_DISPATCH_BLOCKED",
                "A concurrent Phase 4C dispatch was blocked.",
            );
        }
        return Object.freeze({
            allow_once: true,
            proof_id: this.plan.proof_id,
            intent_id: this.plan.intent.intent_id,
            reservation_id: this.plan.intent.reservation_id,
            tool_call_id: event.tool_call_id,
            canonical_params: deepFreeze(cloneJson(event.params)),
            provider_tool_id:
                this.plan.transport_binding.exact_tool_id,
            provider_raw_tool_name:
                this.plan.transport_binding.raw_tool_name,
            provider_params: deepFreeze(cloneJson(providerParams)),
            provider_params_fingerprint_sha256:
                transportFingerprint,
            provider_attempt_count: 1,
            approval_consumed: true,
            automatic_write_retry_allowed: false,
        });
    }

    async afterToolCall(event) {
        const now = normalizeNow(this.now());
        assertExactKeys(event, [
            "tool_name",
            "provider_tool_id",
            "tool_call_id",
            "outcome",
        ], [], "after_tool_call event");
        if (event.tool_name !== this.plan.connector_binding.tool_name) {
            fail("TOOL_NAME_MISMATCH", "Unexpected connector tool.");
        }
        if (event.provider_tool_id
            !== this.plan.transport_binding.exact_tool_id) {
            fail(
                "TRANSPORT_TOOL_MISMATCH",
                "Unexpected GitHub MCP transport tool.",
            );
        }
        const current = await this.store.load();
        assertRecordMatchesPlan(this.plan, current);
        if (!current
            || current.state !== "dispatching"
            || current.provider_attempt_count !== 1
            || current.tool_call_id !== event.tool_call_id) {
            fail(
                "DISPATCH_STATE_INVALID",
                "Phase 4C after-hook has no matching reserved dispatch.",
            );
        }
        const outcome = buildOutcome(this.plan, event.outcome);
        const receipt = createAttestedReceipt(
            this.plan,
            current,
            outcome,
            now,
            reconciliationValue(false),
            this.receiptSigner,
        );
        const next = {
            ...cloneJson(current),
            state: outcome.status,
            revision: current.revision + 1,
            outcome,
            receipt,
            updated_at: now.toISOString(),
        };
        if (!await this.store.compareAndSet(current.revision, next)) {
            fail(
                "STORE_CONFLICT",
                "Phase 4C outcome state changed concurrently.",
            );
        }
        return receipt;
    }

    async reconcileReadOnly(observation) {
        const now = normalizeNow(this.now());
        assertExactKeys(observation, [
            "provider_write_attempted",
            "matching_pull_requests",
        ], [], "reconciliation observation");
        exactBoolean(
            observation.provider_write_attempted,
            false,
            "provider_write_attempted",
        );
        if (!Array.isArray(observation.matching_pull_requests)
            || observation.matching_pull_requests.length > 1) {
            fail(
                "RECONCILIATION_AMBIGUOUS",
                "Read-only reconciliation must find zero or one exact Draft PR.",
            );
        }
        const current = await this.store.load();
        assertRecordMatchesPlan(this.plan, current);
        if (!current || current.state !== "unknown" || current.receipt === null) {
            fail(
                "RECONCILIATION_NOT_ALLOWED",
                "Only an unknown Phase 4C outcome may be reconciled.",
            );
        }
        let providerObject = null;
        let status = "no_effect";
        if (observation.matching_pull_requests.length === 1) {
            providerObject = successfulProviderObject(
                this.plan,
                observation.matching_pull_requests[0],
            );
            status = "committed";
        }
        const outcome = {
            status,
            certainty: "known",
            provider_object: providerObject,
            reason_code: status === "no_effect"
                ? "READ_ONLY_RECONCILE_NO_EFFECT"
                : null,
        };
        outcome.outcome_fingerprint_sha256 = sha256Fingerprint(outcome);
        const receipt = createAttestedReceipt(
            this.plan,
            current,
            outcome,
            now,
            reconciliationValue(true, {
                matching_pull_request_count:
                    observation.matching_pull_requests.length,
                provider_object: providerObject,
            }),
            this.receiptSigner,
        );
        const next = {
            ...cloneJson(current),
            state: status,
            revision: current.revision + 1,
            outcome,
            receipt,
            updated_at: now.toISOString(),
        };
        if (!await this.store.compareAndSet(current.revision, next)) {
            fail(
                "STORE_CONFLICT",
                "Phase 4C reconciliation state changed concurrently.",
            );
        }
        return receipt;
    }

    async revoke(reasonCode = "OWNER_REVOKED") {
        boundedString(reasonCode, REASON_PATTERN, "reason_code");
        const now = normalizeNow(this.now());
        const current = await this.store.load();
        assertRecordMatchesPlan(this.plan, current);
        if (!current) {
            fail("PROOF_NOT_ARMED", "Phase 4C proof is not armed.");
        }
        if (current.revocation.revoked) {
            return Object.freeze({
                revoked: true,
                idempotent: true,
                state: current.state,
                revision: current.revision,
            });
        }
        const next = {
            ...cloneJson(current),
            state: current.state === "armed" ? "revoked" : current.state,
            revision: current.revision + 1,
            revocation: {
                revoked: true,
                revoked_at: now.toISOString(),
                reason_code: reasonCode,
                sequence: 1,
            },
            updated_at: now.toISOString(),
        };
        if (!await this.store.compareAndSet(current.revision, next)) {
            fail("STORE_CONFLICT", "Phase 4C revocation changed concurrently.");
        }
        return Object.freeze({
            revoked: true,
            idempotent: false,
            state: next.state,
            revision: next.revision,
        });
    }

    async status() {
        const current = await this.store.load();
        assertRecordMatchesPlan(this.plan, current);
        if (!current) {
            return Object.freeze({
                contract_version: GITHUB_DRAFT_PR_E2E_CONTRACT_VERSION,
                proof_id: this.plan.proof_id,
                state: "not_armed",
                provider_attempt_count: 0,
                automatic_write_retry_allowed: false,
                receipt: null,
            });
        }
        return Object.freeze({
            contract_version: GITHUB_DRAFT_PR_E2E_CONTRACT_VERSION,
            proof_id: current.proof_id,
            plan_fingerprint_sha256:
                current.plan_fingerprint_sha256,
            state: current.state,
            revision: current.revision,
            provider_attempt_count: current.provider_attempt_count,
            approval_consumed: current.approval_consumed,
            lease_actions_remaining: current.lease_actions_remaining,
            revoked: current.revocation.revoked,
            receipt: current.receipt,
            automatic_write_retry_allowed: false,
            raw_payload_persisted: false,
            provider_credentials_persisted: false,
        });
    }

    async evaluateBeforeToolCall(event, context) {
        try {
            return await this.beforeToolCall(event, context);
        }
        catch (error) {
            const safe = safeControllerError(error);
            return Object.freeze({
                allow_once: false,
                block: true,
                reason_code: safe.code,
                message: safe.message,
                automatic_write_retry_allowed: false,
            });
        }
    }
}
