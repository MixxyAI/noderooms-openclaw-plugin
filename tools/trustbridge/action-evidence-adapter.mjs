import {
    externalActionIntentFingerprint,
    externalActionReceiptFingerprint,
    validateExternalActionIntentV2,
    validateExternalActionReceiptV2,
} from "../../src/external-action-intent-receipt.js";
import {
    capabilityRequestFingerprint,
    leaseAuthorityFingerprint,
    ownerDecisionFingerprint,
    validateCapabilityRequest,
    validateOwnerDecision,
    validateRunLeaseV2,
} from "../../src/owner-capability-run-lease.js";
import {
    sha256Fingerprint,
} from "../../src/passport-runtime-binding.js";
import {
    fingerprintResult,
} from "./artifact-runtime-fingerprint.mjs";

export const ACTION_EVIDENCE_ADAPTER_CONTRACT_VERSION =
    "noderooms-trustbridge-action-evidence-adapter.v1";
export const ACTION_EVIDENCE_ADAPTER_DEVELOPMENT_IDENTITY =
    "1.4.0-alpha.6-dev.2";
export const ACTION_EVIDENCE_ADAPTER_LIVE_AUTHORITY_ALLOWED = false;
export const CLAW_RUNTIME_EVIDENCE_SCHEMA_ID =
    "https://noderooms.com/contracts/claw-runtime-evidence-v0.1.schema.json";
export const CLAW_RUNTIME_EVIDENCE_SCHEMA_FINGERPRINT =
    "sha256:575639855990dad4e8a7d20457e3cd52b7a2266f15b8bef04a4d2862f0416634";

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const EVIDENCE_ID_PATTERN = /^nrevd_[a-f0-9]{32}$/;
const STATUS_RECORD_ID_PATTERN = /^nrevstatus_[a-f0-9]{32}$/;
const HTTPS_URI_PATTERN = /^https:\/\/[^?#\s]+$/;
const SENSITIVE_FIELD_PATTERN =
    /(?:api[_-]?key|oauth[_-]?token|access[_-]?token|refresh[_-]?token|authorization|cookie|credential|run[_-]?secret|invite[_-]?token|raw[_-]?(?:prompt|conversation|message|email|tool|request|response|result|body)|owner[_-]?sender|session[_-]?key|local[_-]?(?:username|path)|home[_-]?path|environment[_-]?value|private[_-]?(?:key|jwk))/i;

const CLAIMS = Object.freeze({
    evidence_available: true,
    absolute_safety_claimed: false,
    exactly_once_effect_claimed: false,
    execution_authority_granted: false,
    reputation_score_generated: false,
    owner_decision_automated: false,
});

const ZERO_SIDE_EFFECTS = Object.freeze({
    NODE_ROOMS_PRODUCTION_NETWORK_CALLS: 0,
    PUBLIC_WRITES: 0,
    PROVIDER_WRITES: 0,
    OWNER_COMMANDS: 0,
    LIVE_LEASE_REQUESTS: 0,
    GATEWAY_STARTS: 0,
    GATEWAY_RESTARTS: 0,
    CLAWHUB_PUBLISH_ATTEMPTS: 0,
    NPM_PUBLISH_ATTEMPTS: 0,
    OPENCLAW_CONFIG_WRITES: 0,
    ARTIFACT_INSTALL_ATTEMPTS: 0,
    ARTIFACT_BLOCK_ATTEMPTS: 0,
});

export class TrustBridgeActionEvidenceError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "TrustBridgeActionEvidenceError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new TrustBridgeActionEvidenceError(code, message);
}

function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, required, optional, label) {
    if (!isRecord(value)) {
        fail("005C_INVALID_OBJECT", `${label} must be an object.`);
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail("005C_UNKNOWN_FIELD", `${label} contains unsupported field ${key}.`);
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail("005C_MISSING_FIELD", `${label} is missing ${key}.`);
        }
    }
}

function assertFingerprint(value, label) {
    if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
        fail("005C_FINGERPRINT_INVALID", `${label} must be lowercase SHA-256.`);
    }
    return value;
}

function parseTime(value, label) {
    const parsed = typeof value === "string" ? Date.parse(value) : Number.NaN;
    if (!Number.isFinite(parsed)) {
        fail("005C_TIMESTAMP_INVALID", `${label} is invalid.`);
    }
    return parsed;
}

function assertPublicSafe(value, path = "$") {
    if (Array.isArray(value)) {
        value.forEach((entry, index) => assertPublicSafe(entry, `${path}[${index}]`));
        return;
    }
    if (!isRecord(value)) {
        return;
    }
    for (const [key, entry] of Object.entries(value)) {
        const safeBoolean = typeof entry === "boolean"
            && /(?:allowed|included|attempted|claimed|required|generated|automated|granted|used)$/i
                .test(key);
        if (!safeBoolean && SENSITIVE_FIELD_PATTERN.test(key)) {
            fail("005C_SENSITIVE_FIELD", `${path}.${key} is not public-safe.`);
        }
        assertPublicSafe(entry, `${path}.${key}`);
    }
}

function validateLifecycle(value) {
    assertExactKeys(value, [
        "issued_at",
        "expires_at",
        "status_checked_at",
        "current_status",
        "active",
        "status_model",
        "status_record_id",
        "status_record_uri",
        "status_record_fingerprint_sha256",
    ], [], "lifecycle");
    const issuedAt = parseTime(value.issued_at, "lifecycle.issued_at");
    const expiresAt = parseTime(value.expires_at, "lifecycle.expires_at");
    const checkedAt = parseTime(
        value.status_checked_at,
        "lifecycle.status_checked_at",
    );
    if (expiresAt <= issuedAt || checkedAt < issuedAt || checkedAt >= expiresAt) {
        fail("005C_LIFECYCLE_INVALID", "Evidence lifecycle ordering is invalid.");
    }
    if (value.current_status !== "active"
        || value.active !== true
        || value.status_model !== "external_signed_status_record"
        || typeof value.status_record_id !== "string"
        || !STATUS_RECORD_ID_PATTERN.test(value.status_record_id)
        || typeof value.status_record_uri !== "string"
        || !HTTPS_URI_PATTERN.test(value.status_record_uri)) {
        fail("005C_LIFECYCLE_INVALID", "Evidence lifecycle is not active and exact.");
    }
    assertFingerprint(
        value.status_record_fingerprint_sha256,
        "lifecycle.status_record_fingerprint_sha256",
    );
    return structuredClone(value);
}

function validateArtifactRuntimeResult(result) {
    if (!isRecord(result)
        || result.contract_version
            !== "noderooms-artifact-runtime-fingerprint.v1"
        || result.fixture !== true
        || result.authority_status !== "evidence_only_no_authority"
        || result.claims?.execution_authority_granted !== false
        || result.claims?.production_enforcement_enabled !== false
        || result.claims?.owner_decision_automated !== false
        || result.claims?.runtime_observation_exactly_fingerprinted !== true) {
        fail(
            "005C_ARTIFACT_RUNTIME_INVALID",
            "005B artifact/runtime evidence is unavailable or authoritative.",
        );
    }
    assertFingerprint(
        result.result_fingerprint_sha256,
        "artifact_runtime_result.result_fingerprint_sha256",
    );
    if (result.result_fingerprint_sha256 !== fingerprintResult(result)) {
        fail(
            "005C_ARTIFACT_RUNTIME_FINGERPRINT_MISMATCH",
            "005B result fingerprint has drifted.",
        );
    }
    if (result.artifact_binding?.package_name
            !== result.runtime_binding?.plugin_package_name
        || result.artifact_binding?.package_version
            !== result.runtime_binding?.plugin_package_version) {
        fail(
            "005C_ARTIFACT_RUNTIME_BINDING_MISMATCH",
            "005B artifact and runtime package identities differ.",
        );
    }
    return result;
}

function validateRuntimeCrossBinding(result, runtimeBinding) {
    const expectedGatewayFingerprint = sha256Fingerprint({
        gateway_id: runtimeBinding.gateway_id,
    });
    const expectedAgentFingerprint = sha256Fingerprint({
        openclaw_agent_id: runtimeBinding.openclaw_agent_id,
    });
    if (result.runtime_binding.gateway_fingerprint_sha256
            !== expectedGatewayFingerprint
        || result.runtime_binding.openclaw_agent_fingerprint_sha256
            !== expectedAgentFingerprint
        || result.runtime_binding.runtime_key_thumbprint_sha256
            !== runtimeBinding.runtime_key_thumbprint) {
        fail(
            "005C_RUNTIME_CROSS_BINDING_MISMATCH",
            "005B runtime identity differs from the authority-chain runtime.",
        );
    }
}

function evidenceProjection(evidence) {
    const {
        $schema: _schema,
        evidence_fingerprint_sha256: _fingerprint,
        attestation: _attestation,
        ...projection
    } = evidence;
    return projection;
}

export function actionEvidenceFingerprint(evidence) {
    return sha256Fingerprint(evidenceProjection(evidence));
}

function makeCheck(checkId, source, sideEffectClass, observedAt, fingerprint,
    resultCode) {
    return Object.freeze({
        check_id: checkId,
        check_version: "v0.1",
        required: true,
        completed: true,
        outcome: "pass",
        source,
        side_effect_class: sideEffectClass,
        observed_at: observedAt,
        evidence_fingerprint_sha256: fingerprint,
        result_code: resultCode,
    });
}

export function buildOwnerApprovedActionEvidenceV01(input, options = {}) {
    assertExactKeys(input, [
        "fixture",
        "evidence_id",
        "artifact_runtime_result",
        "capability_request",
        "owner_decision",
        "run_lease",
        "intent",
        "receipt",
        "lifecycle",
    ], [], "005C input");
    if (input.fixture !== true) {
        fail(
            "005C_EXTERNAL_ATTESTATION_REQUIRED",
            "005C Alpha4 accepts contract fixtures only.",
        );
    }
    if (typeof input.evidence_id !== "string"
        || !EVIDENCE_ID_PATTERN.test(input.evidence_id)) {
        fail("005C_EVIDENCE_ID_INVALID", "evidence_id is invalid.");
    }
    const artifactRuntime = validateArtifactRuntimeResult(
        input.artifact_runtime_result,
    );
    const chainOptions = {
        ...options,
        allowFixture: true,
        allowContractOnly: true,
    };
    validateCapabilityRequest(input.capability_request, chainOptions);
    validateOwnerDecision({
        request: input.capability_request,
        decision: input.owner_decision,
    }, chainOptions);
    validateRunLeaseV2({
        request: input.capability_request,
        decision: input.owner_decision,
        lease: input.run_lease,
    }, chainOptions);
    validateExternalActionIntentV2({
        intent: input.intent,
        lease: input.run_lease,
        request: input.capability_request,
        decision: input.owner_decision,
    }, chainOptions);
    validateExternalActionReceiptV2({
        receipt: input.receipt,
        intent: input.intent,
        lease: input.run_lease,
        request: input.capability_request,
        decision: input.owner_decision,
    }, chainOptions);
    validateRuntimeCrossBinding(artifactRuntime, input.run_lease.runtime_binding);

    const observedAt = input.receipt.recorded_at;
    parseTime(observedAt, "receipt.recorded_at");
    const checks = Object.freeze([
        makeCheck(
            "artifact.runtime.exact-binding",
            "runtime_observation",
            "local_read",
            observedAt,
            artifactRuntime.result_fingerprint_sha256,
            "exact_005b_artifact_runtime_match",
        ),
        makeCheck(
            "authority.owner.allow-once",
            "authority_chain",
            "none",
            observedAt,
            ownerDecisionFingerprint(input.owner_decision),
            "verified_human_owner_allow_once_match",
        ),
        makeCheck(
            "authority.lease.exact-binding",
            "authority_chain",
            "none",
            observedAt,
            leaseAuthorityFingerprint(input.run_lease),
            "exact_active_single_action_lease_match",
        ),
        makeCheck(
            "action.intent.reservation",
            "authority_chain",
            "none",
            observedAt,
            externalActionIntentFingerprint(input.intent),
            "at_most_once_dispatch_reservation_match",
        ),
        makeCheck(
            "provider.outcome.signed-receipt",
            "receipt_projection",
            "none",
            observedAt,
            externalActionReceiptFingerprint(input.receipt),
            "signed_provider_outcome_receipt_match",
        ),
    ]);

    const evidence = {
        $schema: CLAW_RUNTIME_EVIDENCE_SCHEMA_ID,
        contract_version: "claw-runtime-evidence.v0.1",
        fixture: true,
        evidence_id: input.evidence_id,
        evidence_profile: "owner_approved_external_action_outcome",
        authority_status: "evidence_only_no_authority",
        live_enforce_allowed: ACTION_EVIDENCE_ADAPTER_LIVE_AUTHORITY_ALLOWED,
        schema_binding: {
            schema_id: CLAW_RUNTIME_EVIDENCE_SCHEMA_ID,
            schema_fingerprint_sha256:
                CLAW_RUNTIME_EVIDENCE_SCHEMA_FINGERPRINT,
            fingerprint_profile: "raw-utf8-lf-sha256-v1",
            semantic_validation_profile:
                "noderooms-claw-runtime-evidence-semantic-v0.1",
        },
        artifact_binding: structuredClone(artifactRuntime.artifact_binding),
        runtime_binding: structuredClone(artifactRuntime.runtime_binding),
        authority_binding: {
            noderooms_agent_fingerprint_sha256: sha256Fingerprint({
                noderooms_agent_id:
                    input.run_lease.agent_binding.noderooms_agent_id,
            }),
            passport_fingerprint_sha256: sha256Fingerprint({
                passport_id: input.run_lease.agent_binding.passport_id,
            }),
            owner_fingerprint_sha256: sha256Fingerprint({
                owner_binding_id:
                    input.run_lease.agent_binding.owner_binding_id,
            }),
            runtime_binding_record_fingerprint_sha256:
                sha256Fingerprint(input.run_lease.runtime_binding),
            capability_request_fingerprint_sha256:
                capabilityRequestFingerprint(input.capability_request),
            owner_decision_fingerprint_sha256:
                ownerDecisionFingerprint(input.owner_decision),
            run_lease_fingerprint_sha256:
                leaseAuthorityFingerprint(input.run_lease),
            external_action_intent_fingerprint_sha256:
                externalActionIntentFingerprint(input.intent),
            external_action_receipt_fingerprint_sha256:
                externalActionReceiptFingerprint(input.receipt),
            owner_decision_automated: false,
            shared_run_secret_allowed: false,
            shared_lease_allowed: false,
            live_lease_used: true,
            lease_state_at_observation: "active",
        },
        claims: CLAIMS,
        assessment: {
            outcome: "pass",
            completed: true,
            required_check_count: checks.length,
            completed_required_check_count: checks.length,
            passed_required_check_count: checks.length,
            failed_required_check_count: 0,
            inconclusive_required_check_count: 0,
            not_run_required_check_count: 0,
            checks,
        },
        zero_side_effects: ZERO_SIDE_EFFECTS,
        lifecycle: validateLifecycle(input.lifecycle),
        evidence_fingerprint_sha256: "",
        attestation: {
            attestation_status: "not_run",
            external_trust_anchor_required: true,
            reason_code: "contract_fixture",
        },
    };
    evidence.evidence_fingerprint_sha256 = actionEvidenceFingerprint(evidence);
    assertPublicSafe(evidence);
    return Object.freeze(evidence);
}

export function validateOwnerApprovedActionEvidenceV01(evidence) {
    assertExactKeys(evidence, [
        "$schema",
        "contract_version",
        "fixture",
        "evidence_id",
        "evidence_profile",
        "authority_status",
        "live_enforce_allowed",
        "schema_binding",
        "artifact_binding",
        "runtime_binding",
        "authority_binding",
        "claims",
        "assessment",
        "zero_side_effects",
        "lifecycle",
        "evidence_fingerprint_sha256",
        "attestation",
    ], [], "005C evidence");
    if (evidence.$schema !== CLAW_RUNTIME_EVIDENCE_SCHEMA_ID
        || evidence.contract_version !== "claw-runtime-evidence.v0.1"
        || evidence.fixture !== true
        || evidence.evidence_profile
            !== "owner_approved_external_action_outcome"
        || evidence.authority_status !== "evidence_only_no_authority"
        || evidence.live_enforce_allowed !== false
        || evidence.schema_binding?.schema_fingerprint_sha256
            !== CLAW_RUNTIME_EVIDENCE_SCHEMA_FINGERPRINT
        || evidence.attestation?.attestation_status !== "not_run") {
        fail("005C_EVIDENCE_BOUNDARY_INVALID", "005C evidence boundary has drifted.");
    }
    for (const key of [
        "capability_request_fingerprint_sha256",
        "owner_decision_fingerprint_sha256",
        "run_lease_fingerprint_sha256",
        "external_action_intent_fingerprint_sha256",
        "external_action_receipt_fingerprint_sha256",
    ]) {
        assertFingerprint(
            evidence.authority_binding?.[key],
            `authority_binding.${key}`,
        );
    }
    if (evidence.authority_binding.owner_decision_automated !== false
        || evidence.authority_binding.shared_run_secret_allowed !== false
        || evidence.authority_binding.shared_lease_allowed !== false
        || evidence.authority_binding.live_lease_used !== true
        || evidence.authority_binding.lease_state_at_observation !== "active"
        || evidence.claims.execution_authority_granted !== false
        || evidence.claims.exactly_once_effect_claimed !== false
        || evidence.claims.reputation_score_generated !== false
        || evidence.zero_side_effects.PROVIDER_WRITES !== 0) {
        fail("005C_EVIDENCE_BOUNDARY_INVALID", "005C safety claims are invalid.");
    }
    validateLifecycle(evidence.lifecycle);
    assertFingerprint(
        evidence.evidence_fingerprint_sha256,
        "evidence_fingerprint_sha256",
    );
    if (evidence.evidence_fingerprint_sha256
            !== actionEvidenceFingerprint(evidence)) {
        fail(
            "005C_EVIDENCE_FINGERPRINT_MISMATCH",
            "005C evidence fingerprint has drifted.",
        );
    }
    assertPublicSafe(evidence);
    return evidence;
}
