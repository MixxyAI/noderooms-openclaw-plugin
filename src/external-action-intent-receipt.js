import {
    createPublicKey,
    verify,
} from "node:crypto";

import {
    canonicalJson,
    runtimeKeyThumbprint,
    sha256Fingerprint,
} from "./passport-runtime-binding.js";
import {
    leaseAuthorityFingerprint,
    validateRunLeaseV2,
} from "./owner-capability-run-lease.js";

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const INTENT_PATTERN = /^nreai_[a-f0-9]{32}$/;
const RECEIPT_PATTERN = /^nrear_[a-f0-9]{32}$/;
const RESERVATION_PATTERN = /^nrdispatch_[a-f0-9]{32}$/;
const LEASE_PATTERN = /^nrlv2_[a-f0-9]{32}$/;
const DECISION_PATTERN = /^nrcapdec_[a-f0-9]{32}$/;
const KEY_ID_PATTERN = /^nrreceiptkey_[a-z0-9][a-z0-9._-]{2,95}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{2,95}$/;
const PROVIDER_OBJECT_TYPE_PATTERN = /^[a-z][a-z0-9_]{1,63}$/;
const PROVIDER_OBJECT_ID_PATTERN = /^[A-Za-z0-9._:/-]{1,256}$/;
const MAX_INTENT_TTL_MS = 60 * 60 * 1000;
const MAX_ATTESTATION_DELAY_MS = 5 * 60 * 1000;
const MAX_RECEIPT_CHAIN_LENGTH = 2;

export class ExternalActionContractError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "ExternalActionContractError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new ExternalActionContractError(code, message);
}

function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function assertObjectShape(value, required, optional, label) {
    if (!isRecord(value)) {
        fail("INVALID_OBJECT", `${label} must be an object.`);
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail("UNKNOWN_FIELD", `${label} contains unsupported field ${key}.`);
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail("MISSING_FIELD", `${label} is missing ${key}.`);
        }
    }
}

function assertString(value, pattern, label) {
    if (typeof value !== "string" || !pattern.test(value)) {
        fail("INVALID_STRING", `${label} is invalid.`);
    }
    return value;
}

function assertBoundedString(value, label, minimum, maximum) {
    if (typeof value !== "string"
        || value.length < minimum
        || value.length > maximum) {
        fail("INVALID_STRING", `${label} is invalid.`);
    }
    return value;
}

function assertBoolean(value, expected, label) {
    if (typeof value !== "boolean"
        || (expected !== undefined && value !== expected)) {
        fail("INVALID_BOOLEAN", `${label} is invalid.`);
    }
    return value;
}

function assertInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        fail("INVALID_INTEGER", `${label} is invalid.`);
    }
    return value;
}

function parseTime(value, label) {
    const parsed = typeof value === "string" ? Date.parse(value) : Number.NaN;
    if (!Number.isFinite(parsed)) {
        fail("INVALID_TIMESTAMP", `${label} is invalid.`);
    }
    return parsed;
}

function normalizeNow(value) {
    const parsed = value instanceof Date ? value.getTime() : Number(value);
    if (!Number.isFinite(parsed)) {
        fail("INVALID_NOW", "The evaluation time is invalid.");
    }
    return parsed;
}

function sameJson(left, right) {
    return sha256Fingerprint(left) === sha256Fingerprint(right);
}

function fixtureGate(value, allowFixture, label) {
    assertBoolean(value.fixture, undefined, `${label}.fixture`);
    if (value.fixture && !allowFixture) {
        fail("FIXTURE_REJECTED", `${label} is a non-live fixture.`);
    }
}

function contractOnlyGate(value, allowContractOnly, label) {
    if (value.activation_state !== "contract_only") {
        fail("ACTIVATION_STATE_INVALID", `${label} is not contract-only.`);
    }
    assertBoolean(value.live_enforce_allowed, false, `${label}.live_enforce_allowed`);
    if (!allowContractOnly) {
        fail("LIVE_ENFORCE_PROHIBITED", `${label} cannot authorize live execution.`);
    }
}

function assertNoWildcard(value, path = "$") {
    if (typeof value === "string") {
        if (/[*{}[\]]/.test(value)) {
            fail("WILDCARD_FORBIDDEN", `Wildcard-like syntax is forbidden at ${path}.`);
        }
        return;
    }
    if (Array.isArray(value)) {
        value.forEach((entry, index) => assertNoWildcard(entry, `${path}[${index}]`));
        return;
    }
    if (!isRecord(value)) {
        return;
    }
    for (const [key, entry] of Object.entries(value)) {
        if (/[*{}[\]]/.test(key)) {
            fail("WILDCARD_FORBIDDEN", `Wildcard-like key is forbidden at ${path}.${key}.`);
        }
        assertNoWildcard(entry, `${path}.${key}`);
    }
}

function assertNoSensitiveFields(value, path = "$") {
    if (Array.isArray(value)) {
        value.forEach((entry, index) => assertNoSensitiveFields(entry, `${path}[${index}]`));
        return;
    }
    if (!isRecord(value)) {
        return;
    }
    for (const [key, entry] of Object.entries(value)) {
        const safePolicyBoolean = typeof entry === "boolean"
            && /(?:allowed|included|persisted|attempted|claimed|required|supported|forwarded)$/i
                .test(key);
        if (!safePolicyBoolean
            && /(?:secret|token|authorization|cookie|credential|private_key|raw_prompt|raw_request|raw_response|raw_result|raw_body)/i
                .test(key)) {
            fail(
                "SENSITIVE_FIELD_FORBIDDEN",
                `Sensitive field is forbidden at ${path}.${key}.`,
            );
        }
        assertNoSensitiveFields(entry, `${path}.${key}`);
    }
}

function resolveProfile(registry, profileId) {
    if (!isRecord(registry) || !Array.isArray(registry.profiles)) {
        fail("REGISTRY_INVALID", "Connector registry is unavailable.");
    }
    const matches = registry.profiles.filter((profile) => profile.profile_id === profileId);
    if (matches.length !== 1) {
        fail("PROFILE_NOT_FOUND", "Connector profile is missing or duplicated.");
    }
    const [profile] = matches;
    if (profile.status !== "reference_only"
        || profile.replay_semantics !== "at_most_once_dispatch"
        || profile.receipt_profile !== "external_action_receipt_v2") {
        fail("PROFILE_STATE_INVALID", "Connector profile is not a 002D reference profile.");
    }
    return profile;
}

function validateLeaseBinding(value, lease, label = "lease_binding") {
    assertObjectShape(value, [
        "lease_id",
        "lease_authority_fingerprint_sha256",
    ], [], label);
    assertString(value.lease_id, LEASE_PATTERN, `${label}.lease_id`);
    assertString(
        value.lease_authority_fingerprint_sha256,
        SHA256_PATTERN,
        `${label}.lease_authority_fingerprint_sha256`,
    );
    if (value.lease_id !== lease.lease_id
        || value.lease_authority_fingerprint_sha256
            !== lease.lease_authority_fingerprint_sha256
        || value.lease_authority_fingerprint_sha256
            !== leaseAuthorityFingerprint(lease)) {
        fail("LEASE_BINDING_MISMATCH", `${label} does not match the run lease.`);
    }
}

function validateAuthorityBindings(record, lease, profile, label) {
    for (const field of [
        "registry_version",
        "policy_version",
        "profile_id",
        "scope",
        "access_mode",
        "risk",
        "side_effect_class",
        "action",
    ]) {
        if (record[field] !== lease[field]) {
            fail("AUTHORITY_BINDING_MISMATCH", `${label}.${field} has drifted.`);
        }
    }
    if (!sameJson(record.agent_binding, lease.agent_binding)
        || !sameJson(record.runtime_binding, lease.runtime_binding)
        || !sameJson(record.connector_binding, lease.connector_binding)
        || !sameJson(record.resource, lease.resource)) {
        fail("AUTHORITY_BINDING_MISMATCH", `${label} authority has drifted.`);
    }
    if (record.profile_id !== profile.profile_id
        || record.scope !== profile.scope
        || record.action !== profile.action
        || record.risk !== profile.risk
        || record.side_effect_class !== profile.side_effect_class
        || record.connector_binding.provider !== profile.provider
        || record.connector_binding.connector_id !== profile.connector_id
        || record.connector_binding.connector_version !== profile.connector_version
        || record.connector_binding.tool_name !== profile.tool_name
        || record.connector_binding.tool_schema_fingerprint
            !== profile.tool_schema_fingerprint) {
        fail("PROFILE_BINDING_MISMATCH", `${label} does not match the connector profile.`);
    }
}

function validatePayloadProjection(value, resource, profile) {
    if (profile.profile_id !== "nrscp_github_pull_request_draft_v1") {
        fail(
            "PAYLOAD_PROFILE_UNSUPPORTED",
            "002D contains no canonical projection for this connector profile.",
        );
    }
    assertObjectShape(value, [
        "repository_full_name",
        "head_ref",
        "base_ref",
        "draft",
        "title_sha256",
        "body_sha256",
    ], [], "payload_projection");
    assertBoundedString(
        value.repository_full_name,
        "payload_projection.repository_full_name",
        3,
        200,
    );
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value.repository_full_name)) {
        fail("PAYLOAD_PROJECTION_INVALID", "Projected repository is invalid.");
    }
    assertBoundedString(value.head_ref, "payload_projection.head_ref", 1, 255);
    assertBoundedString(value.base_ref, "payload_projection.base_ref", 1, 255);
    assertBoolean(value.draft, true, "payload_projection.draft");
    assertString(value.title_sha256, SHA256_PATTERN, "payload_projection.title_sha256");
    assertString(value.body_sha256, SHA256_PATTERN, "payload_projection.body_sha256");
    assertNoWildcard(value, "payload_projection");
    if (value.repository_full_name !== resource.selector.repository_full_name
        || value.base_ref !== resource.selector.base_ref) {
        fail(
            "PAYLOAD_RESOURCE_MISMATCH",
            "Payload projection does not match the exact resource selector.",
        );
    }
}

function validateProviderIdempotency(value, phase) {
    const forwardingField = phase === "intent"
        ? "forward_on_dispatch"
        : "forwarded";
    assertObjectShape(value, [
        "supported",
        "key_binding_fingerprint_sha256",
        forwardingField,
    ], [], `provider_idempotency.${phase}`);
    assertBoolean(value.supported, undefined, "provider_idempotency.supported");
    assertBoolean(value[forwardingField], undefined, `provider_idempotency.${forwardingField}`);
    if (value.supported) {
        assertString(
            value.key_binding_fingerprint_sha256,
            SHA256_PATTERN,
            "provider_idempotency.key_binding_fingerprint_sha256",
        );
        assertBoolean(value[forwardingField], true, `provider_idempotency.${forwardingField}`);
    } else {
        if (value.key_binding_fingerprint_sha256 !== null) {
            fail(
                "IDEMPOTENCY_KEY_BINDING_INVALID",
                "Unsupported provider idempotency cannot contain a key binding.",
            );
        }
        assertBoolean(value[forwardingField], false, `provider_idempotency.${forwardingField}`);
    }
}

function validateApprovalReservation(value, lease) {
    assertObjectShape(value, [
        "policy",
        "decision_id",
        "decision_fingerprint_sha256",
        "state",
        "consumed",
    ], [], "approval_consumption");
    if (value.policy !== lease.approval.policy
        || value.decision_id !== lease.approval.decision_id
        || value.decision_fingerprint_sha256
            !== lease.approval.decision_fingerprint_sha256) {
        fail(
            "APPROVAL_BINDING_MISMATCH",
            "Intent approval reservation does not match the run lease.",
        );
    }
    assertString(value.decision_id, DECISION_PATTERN, "approval_consumption.decision_id");
    assertString(
        value.decision_fingerprint_sha256,
        SHA256_PATTERN,
        "approval_consumption.decision_fingerprint_sha256",
    );
    if (value.state !== "reserved") {
        fail("APPROVAL_STATE_INVALID", "Intent approval must be atomically reserved.");
    }
    assertBoolean(value.consumed, false, "approval_consumption.consumed");
}

export function dispatchReservationProjection(intent) {
    return {
        contract_version: intent.contract_version,
        intent_id: intent.intent_id,
        lease_binding: intent.lease_binding,
        registry_version: intent.registry_version,
        policy_version: intent.policy_version,
        profile_id: intent.profile_id,
        scope: intent.scope,
        agent_binding: intent.agent_binding,
        runtime_binding: intent.runtime_binding,
        connector_binding: intent.connector_binding,
        access_mode: intent.access_mode,
        risk: intent.risk,
        side_effect_class: intent.side_effect_class,
        action: intent.action,
        resource: intent.resource,
        payload_fingerprint_sha256: intent.payload_fingerprint_sha256,
        approval_consumption: intent.approval_consumption,
        reservation_id: intent.dispatch_reservation?.reservation_id,
        max_attempts: intent.dispatch_reservation?.max_attempts,
        provider_idempotency: intent.dispatch_reservation?.provider_idempotency,
        automatic_write_retry: intent.dispatch_reservation?.automatic_write_retry,
        reconcile_mode: intent.dispatch_reservation?.reconcile_mode,
        created_at: intent.created_at,
        expires_at: intent.expires_at,
    };
}

export function dispatchReservationFingerprint(intent) {
    return sha256Fingerprint(dispatchReservationProjection(intent));
}

export function externalActionIntentProjection(intent) {
    return {
        contract_version: intent.contract_version,
        intent_id: intent.intent_id,
        lease_binding: intent.lease_binding,
        registry_version: intent.registry_version,
        policy_version: intent.policy_version,
        profile_id: intent.profile_id,
        scope: intent.scope,
        agent_binding: intent.agent_binding,
        runtime_binding: intent.runtime_binding,
        connector_binding: intent.connector_binding,
        access_mode: intent.access_mode,
        risk: intent.risk,
        side_effect_class: intent.side_effect_class,
        action: intent.action,
        resource: intent.resource,
        payload_projection: intent.payload_projection,
        payload_fingerprint_sha256: intent.payload_fingerprint_sha256,
        approval_consumption: intent.approval_consumption,
        dispatch_reservation: intent.dispatch_reservation,
        constraints: intent.constraints,
        created_at: intent.created_at,
        expires_at: intent.expires_at,
    };
}

export function externalActionIntentFingerprint(intent) {
    return sha256Fingerprint(externalActionIntentProjection(intent));
}

export function validateExternalActionIntentV2(input, options = {}) {
    const {
        intent,
        lease,
        request,
        decision,
    } = input;
    const allowFixture = options.allowFixture === true;
    const allowContractOnly = options.allowContractOnly === true;
    const now = normalizeNow(options.now ?? Date.now());
    assertObjectShape(intent, [
        "contract_version",
        "fixture",
        "activation_state",
        "live_enforce_allowed",
        "intent_id",
        "lease_binding",
        "registry_version",
        "policy_version",
        "profile_id",
        "scope",
        "agent_binding",
        "runtime_binding",
        "connector_binding",
        "access_mode",
        "risk",
        "side_effect_class",
        "action",
        "resource",
        "payload_projection",
        "payload_fingerprint_sha256",
        "approval_consumption",
        "dispatch_reservation",
        "constraints",
        "created_at",
        "expires_at",
        "intent_fingerprint_sha256",
    ], ["$schema", "$comment"], "external action intent v2");
    fixtureGate(intent, allowFixture, "external action intent v2");
    contractOnlyGate(intent, allowContractOnly, "external action intent v2");
    if (intent.contract_version !== "noderooms-external-action-intent-v2") {
        fail("CONTRACT_VERSION_MISMATCH", "External action intent version is unsupported.");
    }
    assertString(intent.intent_id, INTENT_PATTERN, "intent_id");
    const createdAt = parseTime(intent.created_at, "created_at");
    const expiresAt = parseTime(intent.expires_at, "expires_at");
    validateRunLeaseV2({ lease, request, decision }, {
        ...options,
        allowFixture,
        allowContractOnly,
        now,
        registry: options.registry,
        runtimeBinding: options.runtimeBinding,
    });
    const profile = resolveProfile(options.registry, intent.profile_id);
    validateLeaseBinding(intent.lease_binding, lease);
    validateAuthorityBindings(intent, lease, profile, "intent");
    validatePayloadProjection(intent.payload_projection, intent.resource, profile);
    assertString(
        intent.payload_fingerprint_sha256,
        SHA256_PATTERN,
        "payload_fingerprint_sha256",
    );
    if (intent.payload_fingerprint_sha256
        !== sha256Fingerprint(intent.payload_projection)) {
        fail("PAYLOAD_FINGERPRINT_MISMATCH", "Payload projection fingerprint is invalid.");
    }
    validateApprovalReservation(intent.approval_consumption, lease);
    assertObjectShape(intent.dispatch_reservation, [
        "reservation_id",
        "reservation_fingerprint_sha256",
        "state",
        "attempt_count",
        "max_attempts",
        "provider_idempotency",
        "automatic_write_retry",
        "uncertain_outcome_state",
        "reconcile_mode",
    ], [], "dispatch_reservation");
    assertString(
        intent.dispatch_reservation.reservation_id,
        RESERVATION_PATTERN,
        "dispatch_reservation.reservation_id",
    );
    assertString(
        intent.dispatch_reservation.reservation_fingerprint_sha256,
        SHA256_PATTERN,
        "dispatch_reservation.reservation_fingerprint_sha256",
    );
    if (intent.dispatch_reservation.state !== "reserved"
        || intent.dispatch_reservation.uncertain_outcome_state !== "not_dispatched"
        || intent.dispatch_reservation.reconcile_mode !== "read_only") {
        fail(
            "DISPATCH_RESERVATION_INVALID",
            "Intent must contain one unconsumed at-most-once dispatch reservation.",
        );
    }
    assertInteger(intent.dispatch_reservation.attempt_count, "dispatch.attempt_count", 0, 0);
    assertInteger(intent.dispatch_reservation.max_attempts, "dispatch.max_attempts", 1, 1);
    validateProviderIdempotency(intent.dispatch_reservation.provider_idempotency, "intent");
    const profileSupportsIdempotency =
        profile.replay_semantics === "provider_idempotent";
    if (intent.dispatch_reservation.provider_idempotency.supported
        !== profileSupportsIdempotency) {
        fail(
            "IDEMPOTENCY_PROFILE_MISMATCH",
            "Provider idempotency evidence differs from the connector profile.",
        );
    }
    assertBoolean(
        intent.dispatch_reservation.automatic_write_retry,
        false,
        "dispatch.automatic_write_retry",
    );
    if (intent.dispatch_reservation.reservation_fingerprint_sha256
        !== dispatchReservationFingerprint(intent)) {
        fail(
            "RESERVATION_FINGERPRINT_MISMATCH",
            "Dispatch reservation fingerprint is invalid.",
        );
    }
    assertObjectShape(intent.constraints, [
        "at_most_once_dispatch_required",
        "exactly_once_effect_claimed",
        "raw_payload_persisted",
        "provider_credentials_included",
        "raw_provider_response_persisted",
    ], [], "intent.constraints");
    assertBoolean(
        intent.constraints.at_most_once_dispatch_required,
        true,
        "constraints.at_most_once_dispatch_required",
    );
    for (const field of [
        "exactly_once_effect_claimed",
        "raw_payload_persisted",
        "provider_credentials_included",
        "raw_provider_response_persisted",
    ]) {
        assertBoolean(intent.constraints[field], false, `constraints.${field}`);
    }
    const leaseIssuedAt = parseTime(lease.issued_at, "lease.issued_at");
    const leaseExpiresAt = parseTime(lease.expires_at, "lease.expires_at");
    if (createdAt < leaseIssuedAt
        || createdAt > now
        || expiresAt <= createdAt
        || expiresAt > leaseExpiresAt
        || expiresAt - createdAt > MAX_INTENT_TTL_MS) {
        fail("INTENT_LIFETIME_INVALID", "External action intent lifetime is invalid.");
    }
    if (options.requireLiveIntentWindow !== false && expiresAt <= now) {
        fail("INTENT_EXPIRED", "External action intent has expired.");
    }
    assertString(
        intent.intent_fingerprint_sha256,
        SHA256_PATTERN,
        "intent_fingerprint_sha256",
    );
    if (intent.intent_fingerprint_sha256 !== externalActionIntentFingerprint(intent)) {
        fail("INTENT_FINGERPRINT_MISMATCH", "External action intent fingerprint is invalid.");
    }
    assertNoSensitiveFields(intent);
    return intent;
}

function validateProviderObject(value, receipt) {
    if (value === null) {
        return null;
    }
    assertObjectShape(value, [
        "type",
        "id",
        "url",
        "state",
    ], [], "outcome.provider_object");
    assertString(value.type, PROVIDER_OBJECT_TYPE_PATTERN, "provider_object.type");
    assertString(value.id, PROVIDER_OBJECT_ID_PATTERN, "provider_object.id");
    assertBoundedString(value.url, "provider_object.url", 1, 2048);
    let parsed;
    try {
        parsed = new URL(value.url);
    } catch {
        fail("PROVIDER_OBJECT_URL_INVALID", "Provider object URL is invalid.");
    }
    if (parsed.protocol !== "https:"
        || parsed.username !== ""
        || parsed.password !== ""
        || parsed.hash !== ""
        || parsed.search !== "") {
        fail("PROVIDER_OBJECT_URL_INVALID", "Provider object URL must be public HTTPS.");
    }
    if (receipt.connector_binding.provider === "github") {
        const repository = receipt.resource.selector.repository_full_name;
        if (value.type !== "pull_request"
            || value.state !== "draft"
            || !/^[1-9][0-9]*$/.test(value.id)
            || parsed.hostname !== "github.com"
            || parsed.pathname !== `/${repository}/pull/${value.id}`) {
            fail(
                "PROVIDER_OBJECT_BINDING_MISMATCH",
                "Provider object does not match the exact GitHub action resource.",
            );
        }
    }
    assertBoundedString(value.state, "provider_object.state", 1, 64);
    assertNoWildcard(value, "outcome.provider_object");
    return value;
}

function validateOutcome(value, receipt) {
    assertObjectShape(value, [
        "status",
        "observed_via",
        "provider_object",
        "reason_code",
    ], [], "outcome");
    if (!["committed", "failed", "unknown"].includes(value.status)) {
        fail("OUTCOME_STATUS_INVALID", "External action outcome is invalid.");
    }
    const allowedObservation = receipt.receipt_kind === "dispatch_outcome"
        ? ["dispatch_response", "dispatch_response_lost"]
        : ["read_only_reconcile"];
    if (!allowedObservation.includes(value.observed_via)) {
        fail("OUTCOME_OBSERVATION_INVALID", "Outcome observation source is invalid.");
    }
    validateProviderObject(value.provider_object, receipt);
    if (value.status === "committed") {
        if (value.provider_object === null || value.reason_code !== null) {
            fail("COMMITTED_OUTCOME_INVALID", "Committed outcome evidence is incomplete.");
        }
    } else {
        if (value.provider_object !== null) {
            fail("NONCOMMITTED_OBJECT_INVALID", "Noncommitted outcome cannot assert an object.");
        }
        assertString(value.reason_code, REASON_PATTERN, "outcome.reason_code");
    }
    if (value.status === "unknown"
        && value.observed_via !== "dispatch_response_lost") {
        fail("UNKNOWN_OUTCOME_INVALID", "Unknown outcome requires a lost dispatch response.");
    }
    if (receipt.receipt_kind === "reconciliation_outcome"
        && value.status === "unknown") {
        fail(
            "RECONCILIATION_UNRESOLVED",
            "Canonical reconciliation receipt must resolve an unknown outcome.",
        );
    }
}

export function outcomeFingerprint(receipt) {
    return sha256Fingerprint(receipt.outcome);
}

export function receiptAttributionFingerprint(receipt) {
    return sha256Fingerprint({
        agent_binding: receipt.agent_binding,
        runtime_binding: receipt.runtime_binding,
        lease_binding: receipt.lease_binding,
        intent_binding: receipt.intent_binding,
    });
}

export function externalActionReceiptProjection(receipt) {
    return {
        contract_version: receipt.contract_version,
        receipt_kind: receipt.receipt_kind,
        receipt_id: receipt.receipt_id,
        receipt_sequence: receipt.receipt_sequence,
        previous_receipt_binding: receipt.previous_receipt_binding,
        intent_binding: receipt.intent_binding,
        lease_binding: receipt.lease_binding,
        registry_version: receipt.registry_version,
        policy_version: receipt.policy_version,
        profile_id: receipt.profile_id,
        scope: receipt.scope,
        agent_binding: receipt.agent_binding,
        runtime_binding: receipt.runtime_binding,
        connector_binding: receipt.connector_binding,
        access_mode: receipt.access_mode,
        risk: receipt.risk,
        side_effect_class: receipt.side_effect_class,
        action: receipt.action,
        resource: receipt.resource,
        payload_fingerprint_sha256: receipt.payload_fingerprint_sha256,
        outcome: receipt.outcome,
        outcome_fingerprint_sha256: receipt.outcome_fingerprint_sha256,
        dispatch: receipt.dispatch,
        reconciliation: receipt.reconciliation,
        approval_consumption: receipt.approval_consumption,
        audit_projection: receipt.audit_projection,
        reputation_projection: receipt.reputation_projection,
        recorded_at: receipt.recorded_at,
    };
}

export function externalActionReceiptFingerprint(receipt) {
    return sha256Fingerprint(externalActionReceiptProjection(receipt));
}

export function receiptSignatureProjection(receipt) {
    return {
        domain: "noderooms.external-action-receipt.v2",
        contract_version: receipt.contract_version,
        receipt_id: receipt.receipt_id,
        receipt_fingerprint_sha256: receipt.receipt_fingerprint_sha256,
        issuer: receipt.attestation?.issuer,
        key_id: receipt.attestation?.key_id,
        key_thumbprint_sha256: receipt.attestation?.key_thumbprint_sha256,
        signed_at: receipt.attestation?.signed_at,
    };
}

function validateIntentBinding(value, intent) {
    assertObjectShape(value, [
        "intent_id",
        "intent_fingerprint_sha256",
        "dispatch_reservation_id",
        "dispatch_reservation_fingerprint_sha256",
    ], [], "intent_binding");
    if (value.intent_id !== intent.intent_id
        || value.intent_fingerprint_sha256 !== intent.intent_fingerprint_sha256
        || value.dispatch_reservation_id
            !== intent.dispatch_reservation.reservation_id
        || value.dispatch_reservation_fingerprint_sha256
            !== intent.dispatch_reservation.reservation_fingerprint_sha256) {
        fail("INTENT_BINDING_MISMATCH", "Receipt does not match the external action intent.");
    }
}

function validateReceiptDispatch(value, intent, outcomeStatus) {
    assertObjectShape(value, [
        "state",
        "attempt_count",
        "max_attempts",
        "at_most_once_dispatch_enforced",
        "provider_idempotency",
        "exactly_once_effect_claimed",
        "automatic_write_retry_attempted",
    ], [], "receipt.dispatch");
    if (value.state !== outcomeStatus) {
        fail("DISPATCH_OUTCOME_MISMATCH", "Dispatch state does not match receipt outcome.");
    }
    assertInteger(value.attempt_count, "dispatch.attempt_count", 1, 1);
    assertInteger(value.max_attempts, "dispatch.max_attempts", 1, 1);
    assertBoolean(
        value.at_most_once_dispatch_enforced,
        true,
        "dispatch.at_most_once_dispatch_enforced",
    );
    assertBoolean(
        value.exactly_once_effect_claimed,
        false,
        "dispatch.exactly_once_effect_claimed",
    );
    assertBoolean(
        value.automatic_write_retry_attempted,
        false,
        "dispatch.automatic_write_retry_attempted",
    );
    validateProviderIdempotency(value.provider_idempotency, "receipt");
    const expected = intent.dispatch_reservation.provider_idempotency;
    if (value.provider_idempotency.supported !== expected.supported
        || value.provider_idempotency.key_binding_fingerprint_sha256
            !== expected.key_binding_fingerprint_sha256
        || value.provider_idempotency.forwarded !== expected.forward_on_dispatch) {
        fail(
            "IDEMPOTENCY_BINDING_MISMATCH",
            "Receipt idempotency evidence differs from the reservation.",
        );
    }
}

function validateReconciliation(value, receipt, previousReceipt) {
    assertObjectShape(value, [
        "mode",
        "attempted",
        "provider_write_attempted",
        "observation_fingerprint_sha256",
        "resolved_from_unknown",
    ], [], "reconciliation");
    if (value.mode !== "read_only") {
        fail("RECONCILIATION_MODE_INVALID", "Only read-only reconciliation is allowed.");
    }
    assertBoolean(
        value.provider_write_attempted,
        false,
        "reconciliation.provider_write_attempted",
    );
    if (receipt.receipt_kind === "dispatch_outcome") {
        assertBoolean(value.attempted, false, "reconciliation.attempted");
        assertBoolean(
            value.resolved_from_unknown,
            false,
            "reconciliation.resolved_from_unknown",
        );
        if (value.observation_fingerprint_sha256 !== null
            || receipt.previous_receipt_binding !== null
            || previousReceipt !== undefined) {
            fail(
                "DISPATCH_RECEIPT_HISTORY_INVALID",
                "Initial dispatch receipt cannot contain reconciliation history.",
            );
        }
        return;
    }
    assertBoolean(value.attempted, true, "reconciliation.attempted");
    assertBoolean(
        value.resolved_from_unknown,
        true,
        "reconciliation.resolved_from_unknown",
    );
    assertString(
        value.observation_fingerprint_sha256,
        SHA256_PATTERN,
        "reconciliation.observation_fingerprint_sha256",
    );
    if (value.observation_fingerprint_sha256 !== receipt.outcome_fingerprint_sha256) {
        fail(
            "RECONCILIATION_EVIDENCE_MISMATCH",
            "Read-only observation does not match the resolved outcome.",
        );
    }
    if (!previousReceipt
        || previousReceipt.receipt_kind !== "dispatch_outcome"
        || previousReceipt.outcome.status !== "unknown"
        || !sameJson(previousReceipt.intent_binding, receipt.intent_binding)
        || !sameJson(previousReceipt.lease_binding, receipt.lease_binding)
        || previousReceipt.receipt_sequence + 1 !== receipt.receipt_sequence) {
        fail(
            "RECONCILIATION_HISTORY_INVALID",
            "Reconciliation must directly resolve one unknown dispatch receipt.",
        );
    }
    assertObjectShape(receipt.previous_receipt_binding, [
        "receipt_id",
        "receipt_fingerprint_sha256",
    ], [], "previous_receipt_binding");
    if (receipt.previous_receipt_binding.receipt_id !== previousReceipt.receipt_id
        || receipt.previous_receipt_binding.receipt_fingerprint_sha256
            !== previousReceipt.receipt_fingerprint_sha256) {
        fail(
            "PREVIOUS_RECEIPT_MISMATCH",
            "Reconciliation previous-receipt binding is invalid.",
        );
    }
}

function validateApprovalConsumption(value, lease) {
    assertObjectShape(value, [
        "policy",
        "decision_id",
        "decision_fingerprint_sha256",
        "consumed",
        "lease_actions_before",
        "lease_actions_after",
    ], [], "receipt.approval_consumption");
    if (value.policy !== lease.approval.policy
        || value.decision_id !== lease.approval.decision_id
        || value.decision_fingerprint_sha256
            !== lease.approval.decision_fingerprint_sha256) {
        fail("APPROVAL_BINDING_MISMATCH", "Receipt approval differs from the run lease.");
    }
    assertBoolean(value.consumed, true, "approval_consumption.consumed");
    assertInteger(
        value.lease_actions_before,
        "approval_consumption.lease_actions_before",
        lease.limits.actions_consumed,
        lease.limits.actions_consumed,
    );
    assertInteger(
        value.lease_actions_after,
        "approval_consumption.lease_actions_after",
        lease.limits.actions_consumed + 1,
        lease.limits.actions_consumed + 1,
    );
    if (value.lease_actions_after > lease.limits.max_actions) {
        fail("LEASE_ACTION_LIMIT_EXCEEDED", "Receipt exceeds the run-lease action limit.");
    }
}

function validateAuditProjection(value, receipt) {
    assertObjectShape(value, [
        "event_type",
        "outcome_status",
        "attribution_fingerprint_sha256",
        "evidence_fingerprint_sha256",
        "raw_content_included",
    ], [], "audit_projection");
    if (value.event_type !== "external_action_receipt"
        || value.outcome_status !== receipt.outcome.status
        || value.attribution_fingerprint_sha256
            !== receiptAttributionFingerprint(receipt)
        || value.evidence_fingerprint_sha256
            !== receipt.outcome_fingerprint_sha256) {
        fail("AUDIT_PROJECTION_MISMATCH", "Receipt audit projection is invalid.");
    }
    assertBoolean(value.raw_content_included, false, "audit_projection.raw_content_included");
}

function validateReputationProjection(value) {
    assertObjectShape(value, [
        "state",
        "eligible_for_reputation",
        "score_delta_applied",
        "score_delta",
        "reason_code",
    ], [], "reputation_projection");
    if (value.state !== "contract_only"
        || value.reason_code !== "LIVE_REPUTATION_UPDATE_PROHIBITED") {
        fail(
            "REPUTATION_PROJECTION_INVALID",
            "Contract fixture cannot update live reputation.",
        );
    }
    assertBoolean(
        value.eligible_for_reputation,
        false,
        "reputation_projection.eligible_for_reputation",
    );
    assertBoolean(
        value.score_delta_applied,
        false,
        "reputation_projection.score_delta_applied",
    );
    assertInteger(value.score_delta, "reputation_projection.score_delta", 0, 0);
}

function validateReceiptAttestation(receipt, options, recordedAt) {
    const value = receipt.attestation;
    assertObjectShape(value, [
        "issuer",
        "algorithm",
        "key_id",
        "public_key_jwk",
        "key_thumbprint_sha256",
        "signed_receipt_fingerprint_sha256",
        "signed_at",
        "signature_base64url",
    ], [], "receipt.attestation");
    const expectedIssuer = options.expectedReceiptIssuer ?? "noderooms";
    if (value.issuer !== expectedIssuer || value.algorithm !== "Ed25519") {
        fail("RECEIPT_ISSUER_INVALID", "Receipt attestation issuer or algorithm is invalid.");
    }
    assertString(value.key_id, KEY_ID_PATTERN, "attestation.key_id");
    assertObjectShape(value.public_key_jwk, [
        "kty",
        "crv",
        "x",
    ], [], "attestation.public_key_jwk");
    if (value.public_key_jwk.kty !== "OKP"
        || value.public_key_jwk.crv !== "Ed25519") {
        fail("RECEIPT_KEY_INVALID", "Receipt attestation key must be Ed25519.");
    }
    assertBoundedString(value.public_key_jwk.x, "attestation.public_key_jwk.x", 43, 43);
    assertString(
        value.key_thumbprint_sha256,
        SHA256_PATTERN,
        "attestation.key_thumbprint_sha256",
    );
    const embeddedThumbprint = runtimeKeyThumbprint(value.public_key_jwk);
    if (value.key_thumbprint_sha256 !== embeddedThumbprint) {
        fail("RECEIPT_KEY_THUMBPRINT_MISMATCH", "Receipt key thumbprint is invalid.");
    }
    if (typeof options.trustedReceiptKeyThumbprint !== "string"
        || options.trustedReceiptKeyThumbprint !== embeddedThumbprint) {
        fail("RECEIPT_TRUST_ANCHOR_MISMATCH", "Receipt signing key is not trusted.");
    }
    if (options.trustedReceiptPublicKeyJwk
        && !sameJson(options.trustedReceiptPublicKeyJwk, value.public_key_jwk)) {
        fail("RECEIPT_TRUST_ANCHOR_MISMATCH", "Receipt public key has drifted.");
    }
    if (value.signed_receipt_fingerprint_sha256
        !== receipt.receipt_fingerprint_sha256) {
        fail(
            "SIGNED_RECEIPT_FINGERPRINT_MISMATCH",
            "Attestation signs another receipt fingerprint.",
        );
    }
    const signedAt = parseTime(value.signed_at, "attestation.signed_at");
    if (signedAt < recordedAt
        || signedAt - recordedAt > MAX_ATTESTATION_DELAY_MS) {
        fail("ATTESTATION_TIME_INVALID", "Receipt attestation time is invalid.");
    }
    assertString(
        value.signature_base64url,
        SIGNATURE_PATTERN,
        "attestation.signature_base64url",
    );
    let valid = false;
    try {
        const publicKey = createPublicKey({
            key: value.public_key_jwk,
            format: "jwk",
        });
        valid = verify(
            null,
            Buffer.from(canonicalJson(receiptSignatureProjection(receipt)), "utf8"),
            publicKey,
            Buffer.from(value.signature_base64url, "base64url"),
        );
    } catch {
        valid = false;
    }
    if (!valid) {
        fail("RECEIPT_SIGNATURE_INVALID", "Receipt Ed25519 signature is invalid.");
    }
}

export function validateExternalActionReceiptV2(input, options = {}) {
    const {
        receipt,
        intent,
        lease,
        request,
        decision,
        previousReceipt,
    } = input;
    const allowFixture = options.allowFixture === true;
    const allowContractOnly = options.allowContractOnly === true;
    assertObjectShape(receipt, [
        "contract_version",
        "fixture",
        "activation_state",
        "live_enforce_allowed",
        "receipt_kind",
        "receipt_id",
        "receipt_sequence",
        "previous_receipt_binding",
        "intent_binding",
        "lease_binding",
        "registry_version",
        "policy_version",
        "profile_id",
        "scope",
        "agent_binding",
        "runtime_binding",
        "connector_binding",
        "access_mode",
        "risk",
        "side_effect_class",
        "action",
        "resource",
        "payload_fingerprint_sha256",
        "outcome",
        "outcome_fingerprint_sha256",
        "dispatch",
        "reconciliation",
        "approval_consumption",
        "audit_projection",
        "reputation_projection",
        "recorded_at",
        "receipt_fingerprint_sha256",
        "attestation",
    ], ["$schema", "$comment"], "external action receipt v2");
    fixtureGate(receipt, allowFixture, "external action receipt v2");
    contractOnlyGate(receipt, allowContractOnly, "external action receipt v2");
    if (receipt.contract_version !== "noderooms-external-action-receipt-v2") {
        fail("CONTRACT_VERSION_MISMATCH", "External action receipt version is unsupported.");
    }
    if (!["dispatch_outcome", "reconciliation_outcome"].includes(receipt.receipt_kind)) {
        fail("RECEIPT_KIND_INVALID", "External action receipt kind is invalid.");
    }
    assertString(receipt.receipt_id, RECEIPT_PATTERN, "receipt_id");
    assertInteger(
        receipt.receipt_sequence,
        "receipt_sequence",
        1,
        MAX_RECEIPT_CHAIN_LENGTH,
    );
    const recordedAt = parseTime(receipt.recorded_at, "recorded_at");
    const intentEvaluationTime = receipt.receipt_kind === "dispatch_outcome"
        ? recordedAt
        : (previousReceipt
            ? parseTime(previousReceipt.recorded_at, "previous.recorded_at")
            : parseTime(intent.created_at, "intent.created_at"));
    validateExternalActionIntentV2({ intent, lease, request, decision }, {
        ...options,
        allowFixture,
        allowContractOnly,
        now: intentEvaluationTime,
        requireLiveIntentWindow: true,
    });
    const profile = resolveProfile(options.registry, receipt.profile_id);
    validateIntentBinding(receipt.intent_binding, intent);
    validateLeaseBinding(receipt.lease_binding, lease, "receipt.lease_binding");
    validateAuthorityBindings(receipt, lease, profile, "receipt");
    if (receipt.payload_fingerprint_sha256
        !== intent.payload_fingerprint_sha256) {
        fail("PAYLOAD_FINGERPRINT_MISMATCH", "Receipt payload differs from the intent.");
    }
    validateOutcome(receipt.outcome, receipt);
    assertString(
        receipt.outcome_fingerprint_sha256,
        SHA256_PATTERN,
        "outcome_fingerprint_sha256",
    );
    if (receipt.outcome_fingerprint_sha256 !== outcomeFingerprint(receipt)) {
        fail("OUTCOME_FINGERPRINT_MISMATCH", "Receipt outcome fingerprint is invalid.");
    }
    if (receipt.receipt_kind === "reconciliation_outcome" && previousReceipt) {
        validateExternalActionReceiptV2({
            receipt: previousReceipt,
            intent,
            lease,
            request,
            decision,
        }, options);
    }
    validateReceiptDispatch(receipt.dispatch, intent, receipt.outcome.status);
    validateReconciliation(receipt.reconciliation, receipt, previousReceipt);
    validateApprovalConsumption(receipt.approval_consumption, lease);
    validateAuditProjection(receipt.audit_projection, receipt);
    validateReputationProjection(receipt.reputation_projection);
    const intentCreatedAt = parseTime(intent.created_at, "intent.created_at");
    if (recordedAt < intentCreatedAt) {
        fail("RECEIPT_TIME_INVALID", "Receipt predates its intent.");
    }
    if (receipt.receipt_kind === "dispatch_outcome"
        && recordedAt >= parseTime(intent.expires_at, "intent.expires_at")) {
        fail("DISPATCH_AFTER_EXPIRY", "Dispatch receipt was recorded after intent expiry.");
    }
    if (receipt.receipt_kind === "reconciliation_outcome"
        && recordedAt <= parseTime(previousReceipt.recorded_at, "previous.recorded_at")) {
        fail("RECONCILIATION_TIME_INVALID", "Reconciliation receipt time is invalid.");
    }
    assertString(
        receipt.receipt_fingerprint_sha256,
        SHA256_PATTERN,
        "receipt_fingerprint_sha256",
    );
    if (receipt.receipt_fingerprint_sha256 !== externalActionReceiptFingerprint(receipt)) {
        fail("RECEIPT_FINGERPRINT_MISMATCH", "External action receipt fingerprint is invalid.");
    }
    validateReceiptAttestation(receipt, options, recordedAt);
    assertNoSensitiveFields(receipt);
    return receipt;
}

export function evaluateExternalActionReceiptV2(input, options = {}) {
    try {
        validateExternalActionReceiptV2(input, options);
    } catch (error) {
        const reasonCode = error instanceof ExternalActionContractError
            ? error.code
            : "EXTERNAL_ACTION_VALIDATION_FAILED";
        return Object.freeze({
            decision: "block_invalid_external_action",
            reason_code: reasonCode,
        });
    }
    return Object.freeze({
        decision: "contract_match_not_authorized",
        reason_code: "LIVE_ENFORCE_PROHIBITED",
        receipt_id: input.receipt.receipt_id,
        intent_id: input.intent.intent_id,
        lease_id: input.lease.lease_id,
        receipt_fingerprint_sha256:
            input.receipt.receipt_fingerprint_sha256,
    });
}

export function validateIntentReservationSet(records, options = {}) {
    if (!Array.isArray(records) || records.length === 0 || records.length > 256) {
        fail("INTENT_SET_INVALID", "External action intent set is invalid.");
    }
    const unique = {
        intent: new Set(),
        intentFingerprint: new Set(),
        lease: new Set(),
        reservation: new Set(),
        reservationFingerprint: new Set(),
    };
    for (const record of records) {
        assertObjectShape(record, [
            "intent",
            "lease",
            "request",
            "decision",
            "registry",
            "runtimeBinding",
        ], [], "intent reservation record");
        validateExternalActionIntentV2(record, {
            ...options,
            registry: record.registry,
            runtimeBinding: record.runtimeBinding,
        });
        const values = [
            [unique.intent, record.intent.intent_id, "DUPLICATE_INTENT_ID"],
            [
                unique.intentFingerprint,
                record.intent.intent_fingerprint_sha256,
                "DUPLICATE_INTENT_FINGERPRINT",
            ],
            [unique.lease, record.lease.lease_id, "LEASE_ACTION_REPLAY"],
            [
                unique.reservation,
                record.intent.dispatch_reservation.reservation_id,
                "DUPLICATE_RESERVATION_ID",
            ],
            [
                unique.reservationFingerprint,
                record.intent.dispatch_reservation.reservation_fingerprint_sha256,
                "DUPLICATE_RESERVATION_FINGERPRINT",
            ],
        ];
        for (const [set, value, code] of values) {
            if (set.has(value)) {
                fail(code, "External action intent or lease authority was reused.");
            }
            set.add(value);
        }
    }
    return Object.freeze({
        intent_count: records.length,
        unique_lease_count: unique.lease.size,
        at_most_once_dispatch_required: true,
        automatic_write_retry_allowed: false,
        live_enforce_allowed: false,
    });
}

export function validateReceiptChain(records, options = {}) {
    if (!Array.isArray(records)
        || records.length === 0
        || records.length > MAX_RECEIPT_CHAIN_LENGTH) {
        fail("RECEIPT_CHAIN_INVALID", "External action receipt chain is invalid.");
    }
    const sorted = [...records].sort(
        (left, right) => left.receipt.receipt_sequence - right.receipt.receipt_sequence,
    );
    const receiptIds = new Set();
    const receiptFingerprints = new Set();
    let previousReceipt;
    for (let index = 0; index < sorted.length; index += 1) {
        const record = sorted[index];
        assertObjectShape(record, [
            "receipt",
            "intent",
            "lease",
            "request",
            "decision",
            "registry",
            "runtimeBinding",
        ], [], "receipt chain record");
        if (record.receipt.receipt_sequence !== index + 1) {
            fail("RECEIPT_SEQUENCE_INVALID", "Receipt chain sequence is not contiguous.");
        }
        validateExternalActionReceiptV2({
            ...record,
            previousReceipt,
        }, {
            ...options,
            registry: record.registry,
            runtimeBinding: record.runtimeBinding,
        });
        if (receiptIds.has(record.receipt.receipt_id)
            || receiptFingerprints.has(record.receipt.receipt_fingerprint_sha256)) {
            fail("RECEIPT_REPLAY", "Receipt id or fingerprint was replayed.");
        }
        receiptIds.add(record.receipt.receipt_id);
        receiptFingerprints.add(record.receipt.receipt_fingerprint_sha256);
        previousReceipt = record.receipt;
    }
    if (sorted.length > 1
        && sorted.at(-1).receipt.outcome.status === "unknown") {
        fail("RECEIPT_CHAIN_UNRESOLVED", "Receipt chain remains unresolved.");
    }
    return Object.freeze({
        receipt_count: sorted.length,
        dispatch_attempt_count: 1,
        automatic_write_retry_attempted: false,
        reconciliation_mode: "read_only",
        terminal_status: sorted.at(-1).receipt.outcome.status,
        exactly_once_effect_claimed: false,
    });
}
