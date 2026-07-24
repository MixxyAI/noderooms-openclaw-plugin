import {
    sha256Fingerprint,
    validateRuntimeBindingRecord,
} from "./passport-runtime-binding.js";

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const REQUEST_PATTERN = /^nrcapreq_[a-f0-9]{32}$/;
const DECISION_PATTERN = /^nrcapdec_[a-f0-9]{32}$/;
const LEASE_PATTERN = /^nrlv2_[a-f0-9]{32}$/;
const BINDING_PATTERN = /^nrbind_[a-f0-9]{32}$/;
const PASSPORT_PATTERN = /^NRP-[0-9]{6}-AGENT$/;
const OWNER_BINDING_PATTERN = /^NRPB-[A-F0-9]{24}$/;
const GATEWAY_PATTERN = /^ocgw_[a-f0-9]{32}$/;
const RUNTIME_INSTANCE_PATTERN = /^ocruntime_[a-f0-9]{32}$/;
const OPENCLAW_AGENT_PATTERN = /^[A-Za-z0-9._:-]{1,160}$/;
const REGISTRY_VERSION_PATTERN = /^nrcr_[a-z0-9][a-z0-9._-]{2,63}$/;
const POLICY_VERSION_PATTERN = /^nrp_[a-z0-9][a-z0-9._-]{2,63}$/;
const PROFILE_PATTERN = /^nrscp_[a-z0-9][a-z0-9_]{2,95}$/;
const SCOPE_PATTERN = /^connector\.[a-z][a-z0-9_]{1,31}\.[a-z][a-z0-9_]{1,47}\.[a-z][a-z0-9_]{1,47}$/;
const PROVIDER_PATTERN = /^[a-z][a-z0-9_]{1,31}$/;
const CONNECTOR_PATTERN = /^[a-z][a-z0-9._:-]{2,127}$/;
const CONNECTOR_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/;
const TOOL_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const ACTION_PATTERN = /^[a-z][a-z0-9_]{1,63}$/;
const RESOURCE_TYPE_PATTERN = /^[a-z][a-z0-9_]{1,63}$/;
const CONTEXT_ID_PATTERN = /^[A-Za-z0-9._:/-]{1,200}$/;
const CHANNEL_PATTERN = /^[a-z][a-z0-9._:-]{1,63}$/;
const GOAL_PATTERN = /^nrgoal_[a-f0-9]{32}$/;
const REASON_PATTERN = /^[a-z][a-z0-9_]{2,63}$/;
const MAX_REVIEW_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_LEASE_TTL_SECONDS = 24 * 60 * 60;
const MAX_WRITE_TTL_SECONDS = 60 * 60;
const MAX_HIGH_RISK_TTL_SECONDS = 15 * 60;
const MAX_ACTIONS = 100;
const MAX_WRITE_ACTIONS = 10;

export class OwnerCapabilityLeaseError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "OwnerCapabilityLeaseError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new OwnerCapabilityLeaseError(code, message);
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
        fail("INVALID_IDENTIFIER", `${label} is invalid.`);
    }
    return value;
}

function assertBoolean(value, expected, label) {
    if (typeof value !== "boolean" || (expected !== undefined && value !== expected)) {
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

function fixtureGate(value, allowFixture, label) {
    assertBoolean(value.fixture, undefined, `${label}.fixture`);
    if (value.fixture && !allowFixture) {
        fail("FIXTURE_REJECTED", `${label} is a non-live fixture.`);
    }
}

function sameJson(left, right) {
    return sha256Fingerprint(left) === sha256Fingerprint(right);
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
            && /(?:allowed|included|persisted|exposed|required|automated)$/i.test(key);
        if (!safePolicyBoolean
            && /(?:secret|token|authorization|cookie|credential|private_key|raw_prompt|raw_request|raw_response|raw_result)/i.test(key)) {
            fail("SENSITIVE_FIELD_FORBIDDEN", `Sensitive field is forbidden at ${path}.${key}.`);
        }
        assertNoSensitiveFields(entry, `${path}.${key}`);
    }
}

function validateAgentBinding(value, label = "agent_binding") {
    assertObjectShape(value, [
        "noderooms_agent_id",
        "passport_id",
        "owner_binding_id",
        "verified_owner_required",
    ], [], label);
    assertInteger(value.noderooms_agent_id, `${label}.noderooms_agent_id`, 1);
    assertString(value.passport_id, PASSPORT_PATTERN, `${label}.passport_id`);
    assertString(value.owner_binding_id, OWNER_BINDING_PATTERN, `${label}.owner_binding_id`);
    assertBoolean(value.verified_owner_required, true, `${label}.verified_owner_required`);
    return value;
}

function validateRuntimeReference(value, label = "runtime_binding") {
    assertObjectShape(value, [
        "binding_id",
        "platform",
        "gateway_id",
        "runtime_instance_id",
        "openclaw_agent_id",
        "runtime_key_thumbprint",
        "session_id",
        "run_id",
        "channel",
        "owner_sender_binding_sha256",
    ], [], label);
    assertString(value.binding_id, BINDING_PATTERN, `${label}.binding_id`);
    if (value.platform !== "openclaw") {
        fail("PLATFORM_MISMATCH", `${label}.platform must be openclaw.`);
    }
    assertString(value.gateway_id, GATEWAY_PATTERN, `${label}.gateway_id`);
    assertString(
        value.runtime_instance_id,
        RUNTIME_INSTANCE_PATTERN,
        `${label}.runtime_instance_id`,
    );
    assertString(value.openclaw_agent_id, OPENCLAW_AGENT_PATTERN, `${label}.openclaw_agent_id`);
    assertString(
        value.runtime_key_thumbprint,
        SHA256_PATTERN,
        `${label}.runtime_key_thumbprint`,
    );
    assertString(value.session_id, CONTEXT_ID_PATTERN, `${label}.session_id`);
    assertString(value.run_id, CONTEXT_ID_PATTERN, `${label}.run_id`);
    assertString(value.channel, CHANNEL_PATTERN, `${label}.channel`);
    assertString(
        value.owner_sender_binding_sha256,
        SHA256_PATTERN,
        `${label}.owner_sender_binding_sha256`,
    );
    assertNoWildcard(value, label);
    return value;
}

function validateRuntimeCrossBinding(reference, binding, options) {
    validateRuntimeBindingRecord(binding, {
        allowFixture: options.allowFixture,
        allowContractOnly: true,
        now: options.now,
    });
    if (reference.binding_id !== binding.binding_id) {
        fail("RUNTIME_BINDING_MISMATCH", "Runtime binding id does not match.");
    }
    for (const field of ["platform", "gateway_id", "runtime_instance_id", "openclaw_agent_id"]) {
        if (reference[field] !== binding.runtime_binding[field]) {
            fail("RUNTIME_BINDING_MISMATCH", `Runtime ${field} does not match.`);
        }
    }
    if (reference.runtime_key_thumbprint !== binding.runtime_key.thumbprint_sha256) {
        fail("RUNTIME_BINDING_MISMATCH", "Runtime key thumbprint does not match.");
    }
}

function validateRegistry(registry, allowContractOnly) {
    assertObjectShape(registry, [
        "contract_version",
        "registry_version",
        "policy_version",
        "activation_state",
        "live_enforce_allowed",
        "source_provenance",
        "profiles",
    ], ["$schema"], "connector registry");
    if (registry.contract_version !== "noderooms-connector-scope-registry-v1") {
        fail("REGISTRY_VERSION_MISMATCH", "Connector registry contract is unsupported.");
    }
    assertString(registry.registry_version, REGISTRY_VERSION_PATTERN, "registry_version");
    assertString(registry.policy_version, POLICY_VERSION_PATTERN, "policy_version");
    if (registry.activation_state !== "contract_only") {
        fail("REGISTRY_STATE_INVALID", "002C accepts only the reviewed contract-only registry.");
    }
    assertBoolean(registry.live_enforce_allowed, false, "registry.live_enforce_allowed");
    if (!allowContractOnly) {
        fail("CONTRACT_ONLY_REGISTRY", "Contract-only registry cannot authorize execution.");
    }
    if (!Array.isArray(registry.profiles) || registry.profiles.length === 0) {
        fail("REGISTRY_PROFILES_INVALID", "Connector registry has no profiles.");
    }
    return registry;
}

function validateProfile(profile) {
    assertObjectShape(profile, [
        "profile_id",
        "scope",
        "status",
        "provider",
        "connector_id",
        "connector_version",
        "tool_name",
        "tool_schema_fingerprint",
        "tool_input_schema",
        "action",
        "resource_type",
        "resource_selector",
        "risk",
        "side_effect_class",
        "replay_semantics",
        "approval_policy",
        "receipt_profile",
        "description",
    ], [], "connector profile");
    assertString(profile.profile_id, PROFILE_PATTERN, "profile_id");
    assertString(profile.scope, SCOPE_PATTERN, "scope");
    assertString(profile.provider, PROVIDER_PATTERN, "provider");
    assertString(profile.connector_id, CONNECTOR_PATTERN, "connector_id");
    assertString(profile.connector_version, CONNECTOR_VERSION_PATTERN, "connector_version");
    assertString(profile.tool_name, TOOL_PATTERN, "tool_name");
    assertString(profile.tool_schema_fingerprint, SHA256_PATTERN, "tool_schema_fingerprint");
    if (!isRecord(profile.tool_input_schema)
        || profile.tool_schema_fingerprint !== sha256Fingerprint(profile.tool_input_schema)) {
        fail("TOOL_SCHEMA_DRIFT", "Tool input schema fingerprint does not match.");
    }
    assertString(profile.action, ACTION_PATTERN, "action");
    assertString(profile.resource_type, RESOURCE_TYPE_PATTERN, "resource_type");
    if (!["reference_only", "active"].includes(profile.status)) {
        fail("PROFILE_STATE_INVALID", "Connector profile is not reviewable.");
    }
    if (!["low", "medium", "high", "critical"].includes(profile.risk)) {
        fail("RISK_INVALID", "Connector profile risk is invalid.");
    }
    if (!["read", "write", "destructive", "admin"].includes(profile.side_effect_class)) {
        fail("SIDE_EFFECT_INVALID", "Connector profile side-effect class is invalid.");
    }
    if (!["none", "allow_once"].includes(profile.approval_policy)) {
        fail("APPROVAL_POLICY_INVALID", "Connector profile approval policy is invalid.");
    }
    if (["high", "critical"].includes(profile.risk)
        && profile.approval_policy !== "allow_once") {
        fail("ALLOW_ONCE_REQUIRED", "High and critical profiles require allow-once.");
    }
    assertObjectShape(profile.resource_selector, [
        "strategy",
        "required_claims",
        "wildcards_allowed",
    ], [], "resource selector policy");
    if (profile.resource_selector.strategy !== "exact") {
        fail("EXACT_RESOURCE_REQUIRED", "Resource selector strategy must be exact.");
    }
    assertBoolean(
        profile.resource_selector.wildcards_allowed,
        false,
        "resource_selector.wildcards_allowed",
    );
    if (!Array.isArray(profile.resource_selector.required_claims)
        || profile.resource_selector.required_claims.length === 0
        || new Set(profile.resource_selector.required_claims).size
            !== profile.resource_selector.required_claims.length) {
        fail("RESOURCE_CLAIMS_INVALID", "Resource selector claims are invalid.");
    }
    profile.resource_selector.required_claims.forEach((claim) => {
        assertString(claim, RESOURCE_TYPE_PATTERN, "resource selector claim");
    });
    return profile;
}

function resolveProfile(registry, profileId, allowContractOnly) {
    validateRegistry(registry, allowContractOnly);
    const matches = registry.profiles.filter((profile) => profile.profile_id === profileId);
    if (matches.length !== 1) {
        fail("PROFILE_NOT_FOUND", "Exact connector profile was not found.");
    }
    return validateProfile(matches[0]);
}

function registryBindingProjection(registry, profile) {
    return {
        registry_version: registry.registry_version,
        policy_version: registry.policy_version,
        profile_id: profile.profile_id,
        scope: profile.scope,
        provider: profile.provider,
        connector_id: profile.connector_id,
        connector_version: profile.connector_version,
        tool_name: profile.tool_name,
        tool_schema_fingerprint: profile.tool_schema_fingerprint,
        action: profile.action,
        resource_type: profile.resource_type,
        risk: profile.risk,
        side_effect_class: profile.side_effect_class,
        approval_policy: profile.approval_policy,
    };
}

function validateRegistryBinding(value, registry, profile) {
    assertObjectShape(value, [
        "registry_version",
        "policy_version",
        "profile_id",
        "scope",
        "provider",
        "connector_id",
        "connector_version",
        "tool_name",
        "tool_schema_fingerprint",
        "action",
        "resource_type",
        "risk",
        "side_effect_class",
        "approval_policy",
    ], [], "registry_binding");
    if (!sameJson(value, registryBindingProjection(registry, profile))) {
        fail("REGISTRY_BINDING_MISMATCH", "Capability registry binding has drifted.");
    }
    return value;
}

function validateSelectorScalar(value, label) {
    if (typeof value === "string") {
        if (value.length === 0 || value.length > 512) {
            fail("RESOURCE_SELECTOR_INVALID", `${label} is invalid.`);
        }
        assertNoWildcard(value, label);
        return;
    }
    if (typeof value === "boolean") {
        return;
    }
    if (Number.isSafeInteger(value) && value >= 0) {
        return;
    }
    fail("RESOURCE_SELECTOR_INVALID", `${label} must be an exact scalar.`);
}

function validateResource(value, profile, label = "resource") {
    assertObjectShape(value, [
        "resource_type",
        "selector",
        "selector_fingerprint_sha256",
    ], [], label);
    if (value.resource_type !== profile.resource_type || !isRecord(value.selector)) {
        fail("RESOURCE_MISMATCH", `${label} does not match the connector profile.`);
    }
    const actualClaims = Object.keys(value.selector).sort();
    const requiredClaims = [...profile.resource_selector.required_claims].sort();
    if (!sameJson(actualClaims, requiredClaims)) {
        fail("RESOURCE_CLAIMS_MISMATCH", `${label} claims are not the exact required claims.`);
    }
    for (const [claim, selectorValue] of Object.entries(value.selector)) {
        validateSelectorScalar(selectorValue, `${label}.selector.${claim}`);
    }
    assertString(
        value.selector_fingerprint_sha256,
        SHA256_PATTERN,
        `${label}.selector_fingerprint_sha256`,
    );
    if (value.selector_fingerprint_sha256 !== sha256Fingerprint(value.selector)) {
        fail("RESOURCE_FINGERPRINT_MISMATCH", `${label} selector fingerprint is invalid.`);
    }
    return value;
}

function validateCostLimit(value, label) {
    if (value === null) {
        return null;
    }
    assertObjectShape(value, ["currency", "max_minor_units"], [], label);
    assertString(value.currency, /^[A-Z]{3}$/, `${label}.currency`);
    assertInteger(value.max_minor_units, `${label}.max_minor_units`, 1, 1_000_000_000);
    return value;
}

function validateGoalLimit(value, label) {
    if (value === null) {
        return null;
    }
    assertObjectShape(value, [
        "goal_id",
        "objective_fingerprint_sha256",
    ], [], label);
    assertString(value.goal_id, GOAL_PATTERN, `${label}.goal_id`);
    assertString(
        value.objective_fingerprint_sha256,
        SHA256_PATTERN,
        `${label}.objective_fingerprint_sha256`,
    );
    return value;
}

function validateResourceLimit(value, selectorFingerprint, label) {
    if (value === null) {
        return null;
    }
    assertObjectShape(value, [
        "max_distinct_resources",
        "selector_fingerprint_sha256",
    ], [], label);
    assertInteger(
        value.max_distinct_resources,
        `${label}.max_distinct_resources`,
        1,
        16,
    );
    assertString(
        value.selector_fingerprint_sha256,
        SHA256_PATTERN,
        `${label}.selector_fingerprint_sha256`,
    );
    if (value.selector_fingerprint_sha256 !== selectorFingerprint) {
        fail("RESOURCE_LIMIT_MISMATCH", `${label} is not bound to the exact selector.`);
    }
    return value;
}

function validateLimits(value, profile, selectorFingerprint, label) {
    assertObjectShape(value, [
        "ttl_seconds",
        "max_actions",
        "cost_limit",
        "goal_limit",
        "resource_limit",
    ], [], label);
    assertInteger(value.ttl_seconds, `${label}.ttl_seconds`, 1, MAX_LEASE_TTL_SECONDS);
    assertInteger(value.max_actions, `${label}.max_actions`, 1, MAX_ACTIONS);
    validateCostLimit(value.cost_limit, `${label}.cost_limit`);
    validateGoalLimit(value.goal_limit, `${label}.goal_limit`);
    validateResourceLimit(
        value.resource_limit,
        selectorFingerprint,
        `${label}.resource_limit`,
    );
    if (profile.side_effect_class !== "read") {
        if (value.ttl_seconds > MAX_WRITE_TTL_SECONDS
            || value.max_actions > MAX_WRITE_ACTIONS) {
            fail("WRITE_LIMIT_EXCEEDED", `${label} exceeds write safety limits.`);
        }
    }
    if (["high", "critical"].includes(profile.risk)) {
        if (value.ttl_seconds > MAX_HIGH_RISK_TTL_SECONDS || value.max_actions !== 1) {
            fail("HIGH_RISK_LIMIT_EXCEEDED", `${label} exceeds high-risk safety limits.`);
        }
    }
    if (profile.approval_policy === "allow_once" && value.max_actions !== 1) {
        fail("ALLOW_ONCE_LIMIT_MISMATCH", `${label} must permit one action.`);
    }
    return value;
}

function assertLimitsNarrower(granted, requested) {
    if (granted.ttl_seconds > requested.ttl_seconds
        || granted.max_actions > requested.max_actions) {
        fail("OWNER_GRANT_EXPANDED", "Owner grant exceeds the requested limits.");
    }
    if (requested.cost_limit === null) {
        if (granted.cost_limit !== null) {
            fail("OWNER_GRANT_EXPANDED", "Owner grant introduced a cost limit.");
        }
    } else if (granted.cost_limit !== null
        && (granted.cost_limit.currency !== requested.cost_limit.currency
            || granted.cost_limit.max_minor_units > requested.cost_limit.max_minor_units)) {
        fail("OWNER_GRANT_EXPANDED", "Owner grant expanded the cost limit.");
    }
    if (!sameJson(granted.goal_limit, requested.goal_limit)) {
        fail("OWNER_GRANT_DRIFT", "Owner grant changed the requested goal binding.");
    }
    if (!sameJson(granted.resource_limit, requested.resource_limit)) {
        fail("OWNER_GRANT_DRIFT", "Owner grant changed the requested resource limit.");
    }
}

export function capabilityRequestProjection(request) {
    return {
        contract_version: request.contract_version,
        request_id: request.request_id,
        agent_binding: request.agent_binding,
        runtime_binding: request.runtime_binding,
        registry_binding: request.registry_binding,
        access_mode: request.access_mode,
        resource: request.resource,
        requested_limits: request.requested_limits,
        requested_at: request.requested_at,
        expires_at: request.expires_at,
    };
}

export function capabilityRequestFingerprint(request) {
    return sha256Fingerprint(capabilityRequestProjection(request));
}

export function validateCapabilityRequest(request, options = {}) {
    const allowFixture = options.allowFixture === true;
    const allowContractOnly = options.allowContractOnly === true;
    const now = normalizeNow(options.now ?? Date.now());
    assertObjectShape(request, [
        "contract_version",
        "fixture",
        "request_id",
        "activation_state",
        "live_enforce_allowed",
        "agent_binding",
        "runtime_binding",
        "registry_binding",
        "access_mode",
        "resource",
        "requested_limits",
        "review_state",
        "requested_at",
        "expires_at",
        "request_fingerprint_sha256",
    ], ["$schema", "$comment"], "capability request");
    fixtureGate(request, allowFixture, "capability request");
    if (request.contract_version !== "noderooms-external-capability-request-v2") {
        fail("CONTRACT_VERSION_MISMATCH", "Capability request contract is unsupported.");
    }
    assertString(request.request_id, REQUEST_PATTERN, "request_id");
    if (request.activation_state !== "contract_only" || !allowContractOnly) {
        fail("CONTRACT_ONLY_REQUEST", "Capability request cannot authorize execution.");
    }
    assertBoolean(request.live_enforce_allowed, false, "live_enforce_allowed");
    if (request.review_state !== "pending_owner_review") {
        fail("REVIEW_STATE_INVALID", "Capability request is not pending Owner review.");
    }
    validateAgentBinding(request.agent_binding);
    validateRuntimeReference(request.runtime_binding);
    const profile = resolveProfile(
        options.registry,
        request.registry_binding?.profile_id,
        allowContractOnly,
    );
    validateRegistryBinding(request.registry_binding, options.registry, profile);
    const expectedAccessMode = profile.side_effect_class === "read" ? "read" : "write";
    if (request.access_mode !== expectedAccessMode) {
        fail("ACCESS_MODE_MISMATCH", "Capability access mode does not match side effects.");
    }
    validateResource(request.resource, profile);
    validateLimits(
        request.requested_limits,
        profile,
        request.resource.selector_fingerprint_sha256,
        "requested_limits",
    );
    const requestedAt = parseTime(request.requested_at, "requested_at");
    const expiresAt = parseTime(request.expires_at, "expires_at");
    if (requestedAt > now || expiresAt <= requestedAt
        || expiresAt - requestedAt > MAX_REVIEW_TTL_MS) {
        fail("REQUEST_LIFETIME_INVALID", "Capability request lifetime is invalid.");
    }
    if (options.requireLiveReviewWindow !== false && expiresAt <= now) {
        fail("REQUEST_EXPIRED", "Capability request review window has expired.");
    }
    if (options.runtimeBinding) {
        if (!sameJson(request.agent_binding, options.runtimeBinding.agent_binding)) {
            fail("AGENT_BINDING_MISMATCH", "Capability Agent binding does not match runtime.");
        }
        validateRuntimeCrossBinding(request.runtime_binding, options.runtimeBinding, {
            allowFixture,
            now,
        });
    }
    assertString(
        request.request_fingerprint_sha256,
        SHA256_PATTERN,
        "request_fingerprint_sha256",
    );
    if (request.request_fingerprint_sha256 !== capabilityRequestFingerprint(request)) {
        fail("REQUEST_FINGERPRINT_MISMATCH", "Capability request fingerprint is invalid.");
    }
    assertNoSensitiveFields(request);
    return request;
}

export function ownerDecisionProjection(decision) {
    return {
        contract_version: decision.contract_version,
        decision_id: decision.decision_id,
        request_id: decision.request_id,
        request_fingerprint_sha256: decision.request_fingerprint_sha256,
        registry_binding_fingerprint_sha256:
            decision.registry_binding_fingerprint_sha256,
        resource_selector_fingerprint_sha256:
            decision.resource_selector_fingerprint_sha256,
        decision: decision.decision,
        reviewer: decision.reviewer,
        granted_limits: decision.granted_limits,
        reason_code: decision.reason_code,
        decided_at: decision.decided_at,
        expires_at: decision.expires_at,
    };
}

export function ownerDecisionFingerprint(decision) {
    return sha256Fingerprint(ownerDecisionProjection(decision));
}

export function validateOwnerDecision(input, options = {}) {
    const { request, decision } = input;
    const allowFixture = options.allowFixture === true;
    const allowContractOnly = options.allowContractOnly === true;
    const now = normalizeNow(options.now ?? Date.now());
    assertObjectShape(decision, [
        "contract_version",
        "fixture",
        "decision_id",
        "activation_state",
        "live_enforce_allowed",
        "request_id",
        "request_fingerprint_sha256",
        "registry_binding_fingerprint_sha256",
        "resource_selector_fingerprint_sha256",
        "decision",
        "reviewer",
        "granted_limits",
        "reason_code",
        "decided_at",
        "expires_at",
        "decision_fingerprint_sha256",
    ], ["$schema", "$comment"], "Owner capability decision");
    fixtureGate(decision, allowFixture, "Owner capability decision");
    if (decision.contract_version !== "noderooms-owner-capability-decision-v2") {
        fail("CONTRACT_VERSION_MISMATCH", "Owner capability decision is unsupported.");
    }
    assertString(decision.decision_id, DECISION_PATTERN, "decision_id");
    if (decision.activation_state !== "contract_only" || !allowContractOnly) {
        fail("CONTRACT_ONLY_DECISION", "Owner decision cannot authorize execution.");
    }
    assertBoolean(decision.live_enforce_allowed, false, "live_enforce_allowed");
    if (!["approved_once", "approved_bounded", "denied"].includes(decision.decision)) {
        fail("OWNER_DECISION_INVALID", "Owner decision is invalid.");
    }
    const decidedAt = parseTime(decision.decided_at, "decided_at");
    const decisionExpiresAt = parseTime(decision.expires_at, "expires_at");
    validateCapabilityRequest(request, {
        ...options,
        now: decidedAt,
        requireLiveReviewWindow: true,
    });
    if (decidedAt > now || decisionExpiresAt <= decidedAt
        || decisionExpiresAt > parseTime(request.expires_at, "request.expires_at")) {
        fail("DECISION_LIFETIME_INVALID", "Owner decision lifetime is invalid.");
    }
    if (options.requireLiveDecision !== false && decisionExpiresAt <= now) {
        fail("DECISION_EXPIRED", "Owner decision has expired.");
    }
    if (decision.request_id !== request.request_id
        || decision.request_fingerprint_sha256 !== request.request_fingerprint_sha256) {
        fail("DECISION_REQUEST_MISMATCH", "Owner decision references another request.");
    }
    if (decision.registry_binding_fingerprint_sha256
            !== sha256Fingerprint(request.registry_binding)
        || decision.resource_selector_fingerprint_sha256
            !== request.resource.selector_fingerprint_sha256) {
        fail("DECISION_SCOPE_MISMATCH", "Owner decision scope fingerprint has drifted.");
    }
    assertObjectShape(decision.reviewer, [
        "kind",
        "owner_binding_id",
        "decision_automated",
        "channel",
        "owner_sender_binding_sha256",
    ], [], "reviewer");
    if (decision.reviewer.kind !== "verified_human_owner") {
        fail("HUMAN_OWNER_REQUIRED", "Capability decision requires a Verified Human Owner.");
    }
    assertString(
        decision.reviewer.owner_binding_id,
        OWNER_BINDING_PATTERN,
        "reviewer.owner_binding_id",
    );
    assertBoolean(decision.reviewer.decision_automated, false, "reviewer.decision_automated");
    assertString(decision.reviewer.channel, CHANNEL_PATTERN, "reviewer.channel");
    assertString(
        decision.reviewer.owner_sender_binding_sha256,
        SHA256_PATTERN,
        "reviewer.owner_sender_binding_sha256",
    );
    if (decision.reviewer.owner_binding_id !== request.agent_binding.owner_binding_id
        || decision.reviewer.channel !== request.runtime_binding.channel
        || decision.reviewer.owner_sender_binding_sha256
            !== request.runtime_binding.owner_sender_binding_sha256) {
        fail("OWNER_BINDING_MISMATCH", "Owner reviewer does not match the request.");
    }
    const profile = resolveProfile(
        options.registry,
        request.registry_binding.profile_id,
        allowContractOnly,
    );
    if (decision.decision === "denied") {
        if (decision.granted_limits !== null) {
            fail("DENIED_GRANT_INVALID", "Denied decision cannot grant limits.");
        }
    } else {
        validateLimits(
            decision.granted_limits,
            profile,
            request.resource.selector_fingerprint_sha256,
            "granted_limits",
        );
        assertLimitsNarrower(decision.granted_limits, request.requested_limits);
        if ((profile.approval_policy === "allow_once"
                || ["high", "critical"].includes(profile.risk))
            && decision.decision !== "approved_once") {
            fail("ALLOW_ONCE_REQUIRED", "Exact scope requires one-time Owner approval.");
        }
        if (decision.decision === "approved_once"
            && decision.granted_limits.max_actions !== 1) {
            fail("ALLOW_ONCE_LIMIT_MISMATCH", "One-time approval must grant one action.");
        }
    }
    assertString(decision.reason_code, REASON_PATTERN, "reason_code");
    assertString(
        decision.decision_fingerprint_sha256,
        SHA256_PATTERN,
        "decision_fingerprint_sha256",
    );
    if (decision.decision_fingerprint_sha256 !== ownerDecisionFingerprint(decision)) {
        fail("DECISION_FINGERPRINT_MISMATCH", "Owner decision fingerprint is invalid.");
    }
    assertNoSensitiveFields(decision);
    return decision;
}

export function leaseAuthorityProjection(lease) {
    return {
        contract_version: lease.contract_version,
        lease_id: lease.lease_id,
        request_binding: lease.request_binding,
        owner_decision_binding: lease.owner_decision_binding,
        registry_version: lease.registry_version,
        policy_version: lease.policy_version,
        profile_id: lease.profile_id,
        scope: lease.scope,
        agent_binding: lease.agent_binding,
        runtime_binding: lease.runtime_binding,
        connector_binding: lease.connector_binding,
        access_mode: lease.access_mode,
        risk: lease.risk,
        side_effect_class: lease.side_effect_class,
        action: lease.action,
        resource: lease.resource,
        approval: {
            policy: lease.approval.policy,
            decision: lease.approval.decision,
            decision_id: lease.approval.decision_id,
            decision_fingerprint_sha256: lease.approval.decision_fingerprint_sha256,
            approved_by: lease.approval.approved_by,
            owner_binding_id: lease.approval.owner_binding_id,
            decision_automated: lease.approval.decision_automated,
            approved_at: lease.approval.approved_at,
        },
        limits: {
            ttl_seconds: lease.limits.ttl_seconds,
            max_actions: lease.limits.max_actions,
            cost_limit: lease.limits.cost_limit,
            goal_limit: lease.limits.goal_limit,
            resource_limit: lease.limits.resource_limit,
        },
        issuance: lease.issuance,
        issued_at: lease.issued_at,
        expires_at: lease.expires_at,
        constraints: lease.constraints,
    };
}

export function leaseAuthorityFingerprint(lease) {
    return sha256Fingerprint(leaseAuthorityProjection(lease));
}

function validateLeaseApproval(approval, decision, profile) {
    assertObjectShape(approval, [
        "policy",
        "decision",
        "decision_id",
        "decision_fingerprint_sha256",
        "approved_by",
        "owner_binding_id",
        "decision_automated",
        "approved_at",
        "consumed",
    ], [], "approval");
    if (approval.policy !== profile.approval_policy
        || approval.decision !== decision.decision
        || approval.decision_id !== decision.decision_id
        || approval.decision_fingerprint_sha256 !== decision.decision_fingerprint_sha256
        || approval.approved_by !== "verified_human_owner"
        || approval.owner_binding_id !== decision.reviewer.owner_binding_id
        || approval.approved_at !== decision.decided_at) {
        fail("LEASE_APPROVAL_MISMATCH", "Lease approval does not match the Owner decision.");
    }
    assertBoolean(approval.decision_automated, false, "approval.decision_automated");
    assertBoolean(approval.consumed, false, "approval.consumed");
}

function validateLeaseLimits(limits, decision, profile, selectorFingerprint) {
    assertObjectShape(limits, [
        "ttl_seconds",
        "max_actions",
        "actions_consumed",
        "actions_remaining",
        "cost_limit",
        "goal_limit",
        "resource_limit",
    ], [], "limits");
    const grant = {
        ttl_seconds: limits.ttl_seconds,
        max_actions: limits.max_actions,
        cost_limit: limits.cost_limit,
        goal_limit: limits.goal_limit,
        resource_limit: limits.resource_limit,
    };
    validateLimits(grant, profile, selectorFingerprint, "limits");
    if (!sameJson(grant, decision.granted_limits)) {
        fail("LEASE_LIMIT_MISMATCH", "Lease limits do not equal the Owner grant.");
    }
    assertInteger(limits.actions_consumed, "limits.actions_consumed", 0, limits.max_actions);
    assertInteger(limits.actions_remaining, "limits.actions_remaining", 0, limits.max_actions);
    if (limits.actions_consumed + limits.actions_remaining !== limits.max_actions) {
        fail("LEASE_COUNTER_MISMATCH", "Lease action counters are inconsistent.");
    }
    if (limits.actions_remaining === 0) {
        fail("LEASE_EXHAUSTED", "Run lease has no remaining action.");
    }
}

export function validateRunLeaseV2(input, options = {}) {
    const {
        lease,
        request,
        decision,
    } = input;
    const allowFixture = options.allowFixture === true;
    const allowContractOnly = options.allowContractOnly === true;
    const now = normalizeNow(options.now ?? Date.now());
    assertObjectShape(lease, [
        "contract_version",
        "fixture",
        "lease_id",
        "activation_state",
        "live_enforce_allowed",
        "request_binding",
        "owner_decision_binding",
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
        "approval",
        "limits",
        "issuance",
        "issued_at",
        "expires_at",
        "revocation",
        "constraints",
        "lease_authority_fingerprint_sha256",
    ], ["$schema", "$comment"], "run lease v2");
    fixtureGate(lease, allowFixture, "run lease v2");
    if (lease.contract_version !== "noderooms-run-lease-v2") {
        fail("CONTRACT_VERSION_MISMATCH", "Run lease v2 contract is unsupported.");
    }
    assertString(lease.lease_id, LEASE_PATTERN, "lease_id");
    if (lease.activation_state !== "contract_only" || !allowContractOnly) {
        fail("CONTRACT_ONLY_LEASE", "Contract-only run lease cannot authorize execution.");
    }
    assertBoolean(lease.live_enforce_allowed, false, "live_enforce_allowed");
    const issuedAt = parseTime(lease.issued_at, "issued_at");
    const expiresAt = parseTime(lease.expires_at, "expires_at");
    validateOwnerDecision({ request, decision }, {
        ...options,
        now: issuedAt,
        requireLiveDecision: true,
    });
    if (decision.decision === "denied") {
        fail("OWNER_DENIED", "Denied Owner decision cannot issue a lease.");
    }
    const profile = resolveProfile(options.registry, lease.profile_id, allowContractOnly);
    assertObjectShape(lease.request_binding, [
        "request_id",
        "request_fingerprint_sha256",
    ], [], "request_binding");
    if (lease.request_binding.request_id !== request.request_id
        || lease.request_binding.request_fingerprint_sha256
            !== request.request_fingerprint_sha256) {
        fail("LEASE_REQUEST_MISMATCH", "Lease does not match the capability request.");
    }
    assertObjectShape(lease.owner_decision_binding, [
        "decision_id",
        "decision_fingerprint_sha256",
    ], [], "owner_decision_binding");
    if (lease.owner_decision_binding.decision_id !== decision.decision_id
        || lease.owner_decision_binding.decision_fingerprint_sha256
            !== decision.decision_fingerprint_sha256) {
        fail("LEASE_DECISION_MISMATCH", "Lease does not match the Owner decision.");
    }
    const registryBinding = registryBindingProjection(options.registry, profile);
    for (const field of ["registry_version", "policy_version", "profile_id", "scope"]) {
        if (lease[field] !== registryBinding[field]) {
            fail("LEASE_REGISTRY_MISMATCH", `Lease ${field} has drifted.`);
        }
    }
    if (!sameJson(lease.agent_binding, request.agent_binding)
        || !sameJson(lease.runtime_binding, request.runtime_binding)) {
        fail("LEASE_AUTHORITY_MISMATCH", "Lease Agent or runtime authority has drifted.");
    }
    validateAgentBinding(lease.agent_binding);
    validateRuntimeReference(lease.runtime_binding);
    if (options.runtimeBinding) {
        validateRuntimeCrossBinding(lease.runtime_binding, options.runtimeBinding, {
            allowFixture,
            now,
        });
    }
    assertObjectShape(lease.connector_binding, [
        "provider",
        "connector_id",
        "connector_version",
        "tool_name",
        "tool_schema_fingerprint",
    ], [], "connector_binding");
    for (const field of [
        "provider",
        "connector_id",
        "connector_version",
        "tool_name",
        "tool_schema_fingerprint",
    ]) {
        if (lease.connector_binding[field] !== registryBinding[field]) {
            fail("LEASE_CONNECTOR_MISMATCH", `Lease connector ${field} has drifted.`);
        }
    }
    if (lease.access_mode !== request.access_mode
        || lease.risk !== profile.risk
        || lease.side_effect_class !== profile.side_effect_class
        || lease.action !== profile.action) {
        fail("LEASE_SCOPE_MISMATCH", "Lease access, risk, side effect, or action has drifted.");
    }
    validateResource(lease.resource, profile);
    if (!sameJson(lease.resource, request.resource)) {
        fail("LEASE_RESOURCE_MISMATCH", "Lease resource differs from the reviewed request.");
    }
    validateLeaseApproval(lease.approval, decision, profile);
    validateLeaseLimits(
        lease.limits,
        decision,
        profile,
        lease.resource.selector_fingerprint_sha256,
    );
    assertObjectShape(lease.issuance, [
        "issuer",
        "decision_consumed_atomically",
        "issued_once",
    ], [], "issuance");
    if (lease.issuance.issuer !== "noderooms") {
        fail("LEASE_ISSUER_INVALID", "Run lease issuer is invalid.");
    }
    assertBoolean(
        lease.issuance.decision_consumed_atomically,
        true,
        "issuance.decision_consumed_atomically",
    );
    assertBoolean(lease.issuance.issued_once, true, "issuance.issued_once");
    if (issuedAt > now || expiresAt <= issuedAt
        || expiresAt - issuedAt !== lease.limits.ttl_seconds * 1000
        || expiresAt > parseTime(decision.expires_at, "decision.expires_at")) {
        fail("LEASE_LIFETIME_INVALID", "Run lease lifetime is invalid.");
    }
    if (expiresAt <= now) {
        fail("LEASE_EXPIRED", "Run lease has expired.");
    }
    assertObjectShape(lease.revocation, [
        "state",
        "revoked",
        "revoked_at",
        "reason_code",
        "sequence",
    ], [], "revocation");
    assertInteger(lease.revocation.sequence, "revocation.sequence", 0);
    if (lease.revocation.state === "not_revoked") {
        assertBoolean(lease.revocation.revoked, false, "revocation.revoked");
        if (lease.revocation.revoked_at !== null || lease.revocation.reason_code !== null) {
            fail("REVOCATION_STATE_INVALID", "Non-revoked lease contains revocation data.");
        }
    } else if (lease.revocation.state === "revoked") {
        assertBoolean(lease.revocation.revoked, true, "revocation.revoked");
        const revokedAt = parseTime(lease.revocation.revoked_at, "revocation.revoked_at");
        assertString(lease.revocation.reason_code, REASON_PATTERN, "revocation.reason_code");
        if (revokedAt < issuedAt || revokedAt > now || lease.revocation.sequence < 1) {
            fail("REVOCATION_STATE_INVALID", "Run lease revocation is invalid.");
        }
        fail("LEASE_REVOKED", "Run lease has been revoked.");
    } else {
        fail("REVOCATION_STATE_INVALID", "Run lease revocation state is invalid.");
    }
    assertObjectShape(lease.constraints, [
        "wildcard_authorization_allowed",
        "shared_lease_allowed",
        "shared_run_secret_allowed",
        "provider_credentials_included",
        "owner_decision_automatable",
    ], [], "constraints");
    assertBoolean(
        lease.constraints.wildcard_authorization_allowed,
        false,
        "constraints.wildcard_authorization_allowed",
    );
    assertBoolean(
        lease.constraints.shared_lease_allowed,
        false,
        "constraints.shared_lease_allowed",
    );
    assertBoolean(
        lease.constraints.shared_run_secret_allowed,
        false,
        "constraints.shared_run_secret_allowed",
    );
    assertBoolean(
        lease.constraints.provider_credentials_included,
        false,
        "constraints.provider_credentials_included",
    );
    assertBoolean(
        lease.constraints.owner_decision_automatable,
        false,
        "constraints.owner_decision_automatable",
    );
    assertString(
        lease.lease_authority_fingerprint_sha256,
        SHA256_PATTERN,
        "lease_authority_fingerprint_sha256",
    );
    if (lease.lease_authority_fingerprint_sha256 !== leaseAuthorityFingerprint(lease)) {
        fail("LEASE_FINGERPRINT_MISMATCH", "Run lease authority fingerprint is invalid.");
    }
    assertNoSensitiveFields(lease);
    return lease;
}

export function evaluateRunLeaseV2(input, options = {}) {
    try {
        validateRunLeaseV2(input, options);
    } catch (error) {
        const reasonCode = error instanceof OwnerCapabilityLeaseError
            ? error.code
            : "LEASE_VALIDATION_FAILED";
        return Object.freeze({
            decision: "block_invalid_lease",
            reason_code: reasonCode,
        });
    }
    return Object.freeze({
        decision: "contract_match_not_authorized",
        reason_code: "LIVE_ENFORCE_PROHIBITED",
        lease_id: input.lease.lease_id,
        request_id: input.request.request_id,
        decision_id: input.decision.decision_id,
        lease_authority_fingerprint_sha256:
            input.lease.lease_authority_fingerprint_sha256,
    });
}

export function validateLeaseIssuanceSet(records, options = {}) {
    if (!Array.isArray(records) || records.length === 0 || records.length > 256) {
        fail("LEASE_SET_INVALID", "Lease issuance set is invalid.");
    }
    const leaseIds = new Set();
    const requestIds = new Set();
    const decisionIds = new Set();
    const authorityFingerprints = new Set();
    for (const record of records) {
        assertObjectShape(record, [
            "lease",
            "request",
            "decision",
            "registry",
            "runtimeBinding",
        ], [], "lease issuance record");
        validateRunLeaseV2(record, {
            ...options,
            registry: record.registry,
            runtimeBinding: record.runtimeBinding,
        });
        for (const [set, value, code] of [
            [leaseIds, record.lease.lease_id, "DUPLICATE_LEASE_ID"],
            [requestIds, record.request.request_id, "REQUEST_REPLAY"],
            [decisionIds, record.decision.decision_id, "DECISION_REPLAY"],
            [
                authorityFingerprints,
                record.lease.lease_authority_fingerprint_sha256,
                "DUPLICATE_LEASE_AUTHORITY",
            ],
        ]) {
            if (set.has(value)) {
                fail(code, "One Owner decision or lease authority was reused.");
            }
            set.add(value);
        }
    }
    return Object.freeze({
        lease_count: records.length,
        unique_request_count: requestIds.size,
        unique_decision_count: decisionIds.size,
        owner_decision_automatable: false,
        shared_lease_allowed: false,
        shared_run_secret_allowed: false,
    });
}
