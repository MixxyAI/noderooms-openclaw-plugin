import { createHash, createPublicKey, verify } from "node:crypto";

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const BINDING_REQUEST_PATTERN = /^nrbreq_[a-f0-9]{32}$/;
const CHALLENGE_PATTERN = /^nrbch_[a-f0-9]{32}$/;
const ASSERTION_PATTERN = /^nrbassert_[a-f0-9]{32}$/;
const BINDING_PATTERN = /^nrbind_[a-f0-9]{32}$/;
const RECOVERY_PATTERN = /^nrrecovery_[a-f0-9]{32}$/;
const PASSPORT_PATTERN = /^NRP-[0-9]{6}-AGENT$/;
const OWNER_BINDING_PATTERN = /^NRPB-[A-F0-9]{24}$/;
const GATEWAY_PATTERN = /^ocgw_[a-f0-9]{32}$/;
const RUNTIME_INSTANCE_PATTERN = /^ocruntime_[a-f0-9]{32}$/;
const OPENCLAW_AGENT_PATTERN = /^[A-Za-z0-9._:-]{1,160}$/;
const BASE64URL_32_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const BASE64URL_ED25519_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const MAX_PAIRING_TTL_MS = 5 * 60 * 1000;

export class PassportRuntimeBindingError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "PassportRuntimeBindingError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new PassportRuntimeBindingError(code, message);
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

function assertInteger(value, label) {
    if (!Number.isSafeInteger(value) || value <= 0) {
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
    return canonicalJson(left) === canonicalJson(right);
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
            && /(?:allowed|reused|required|persisted|exposed)$/i.test(key);
        if (!safePolicyBoolean
            && /(?:secret|token|authorization|cookie|private_key|raw_prompt|raw_request|raw_response)/i.test(key)) {
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
    assertInteger(value.noderooms_agent_id, `${label}.noderooms_agent_id`);
    assertString(value.passport_id, PASSPORT_PATTERN, `${label}.passport_id`);
    assertString(value.owner_binding_id, OWNER_BINDING_PATTERN, `${label}.owner_binding_id`);
    assertBoolean(value.verified_owner_required, true, `${label}.verified_owner_required`);
    return value;
}

function validateRuntimeIdentity(value, label = "runtime_binding") {
    assertObjectShape(value, [
        "platform",
        "gateway_id",
        "runtime_instance_id",
        "openclaw_agent_id",
    ], [], label);
    if (value.platform !== "openclaw") {
        fail("PLATFORM_MISMATCH", `${label}.platform must be openclaw.`);
    }
    assertString(value.gateway_id, GATEWAY_PATTERN, `${label}.gateway_id`);
    assertString(value.runtime_instance_id, RUNTIME_INSTANCE_PATTERN, `${label}.runtime_instance_id`);
    assertString(value.openclaw_agent_id, OPENCLAW_AGENT_PATTERN, `${label}.openclaw_agent_id`);
    return value;
}

function validateRuntimeContext(value, label = "runtime_context") {
    assertObjectShape(value, [
        "platform",
        "gateway_id",
        "runtime_instance_id",
        "openclaw_agent_id",
        "runtime_key_thumbprint",
    ], [], label);
    validateRuntimeIdentity({
        platform: value.platform,
        gateway_id: value.gateway_id,
        runtime_instance_id: value.runtime_instance_id,
        openclaw_agent_id: value.openclaw_agent_id,
    }, label);
    assertString(value.runtime_key_thumbprint, SHA256_PATTERN, `${label}.runtime_key_thumbprint`);
    return value;
}

function validatePublicKeyJwk(value, label = "runtime_public_key_jwk") {
    assertObjectShape(value, ["kty", "crv", "x"], [], label);
    if (value.kty !== "OKP" || value.crv !== "Ed25519") {
        fail("UNSUPPORTED_RUNTIME_KEY", `${label} must be an Ed25519 OKP public key.`);
    }
    assertString(value.x, BASE64URL_32_PATTERN, `${label}.x`);
    return value;
}

function fixtureGate(value, allowFixture, label) {
    assertBoolean(value.fixture, undefined, `${label}.fixture`);
    if (value.fixture && !allowFixture) {
        fail("FIXTURE_REJECTED", `${label} is a non-live fixture.`);
    }
}

export function canonicalJson(value) {
    if (Array.isArray(value)) {
        return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
    }
    if (isRecord(value)) {
        return `{${Object.keys(value).sort().map(
            (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
        ).join(",")}}`;
    }
    return JSON.stringify(value);
}

export function sha256Fingerprint(value) {
    return `sha256:${createHash("sha256").update(canonicalJson(value), "utf8").digest("hex")}`;
}

export function runtimeKeyThumbprint(publicKeyJwk) {
    const validated = validatePublicKeyJwk(publicKeyJwk);
    return sha256Fingerprint({
        crv: validated.crv,
        kty: validated.kty,
        x: validated.x,
    });
}

export function pairingChallengeProjection(challenge) {
    return {
        contract_version: challenge.contract_version,
        binding_request_id: challenge.binding_request_id,
        challenge_id: challenge.challenge_id,
        agent_binding: challenge.agent_binding,
        runtime_binding: challenge.runtime_binding,
        runtime_public_key_jwk: challenge.runtime_public_key_jwk,
        runtime_key_thumbprint: challenge.runtime_key_thumbprint,
        nonce: challenge.nonce,
        one_time: challenge.one_time,
        issued_at: challenge.issued_at,
        expires_at: challenge.expires_at,
    };
}

export function pairingChallengeFingerprint(challenge) {
    return sha256Fingerprint(pairingChallengeProjection(challenge));
}

export function validatePairingChallenge(challenge, options = {}) {
    const allowFixture = options.allowFixture === true;
    const now = normalizeNow(options.now ?? Date.now());
    assertObjectShape(challenge, [
        "contract_version",
        "fixture",
        "binding_request_id",
        "challenge_id",
        "agent_binding",
        "runtime_binding",
        "runtime_public_key_jwk",
        "runtime_key_thumbprint",
        "nonce",
        "one_time",
        "state",
        "issued_at",
        "expires_at",
        "consumed_at",
        "challenge_fingerprint_sha256",
    ], ["$comment"], "pairing challenge");
    fixtureGate(challenge, allowFixture, "pairing challenge");
    if (challenge.contract_version !== "noderooms-runtime-pairing-challenge-v1") {
        fail("CONTRACT_VERSION_MISMATCH", "Pairing challenge contract version is unsupported.");
    }
    assertString(challenge.binding_request_id, BINDING_REQUEST_PATTERN, "binding_request_id");
    assertString(challenge.challenge_id, CHALLENGE_PATTERN, "challenge_id");
    validateAgentBinding(challenge.agent_binding);
    validateRuntimeIdentity(challenge.runtime_binding);
    validatePublicKeyJwk(challenge.runtime_public_key_jwk);
    assertString(challenge.runtime_key_thumbprint, SHA256_PATTERN, "runtime_key_thumbprint");
    if (challenge.runtime_key_thumbprint !== runtimeKeyThumbprint(challenge.runtime_public_key_jwk)) {
        fail("RUNTIME_KEY_THUMBPRINT_MISMATCH", "Runtime key thumbprint does not match its public key.");
    }
    assertString(challenge.nonce, BASE64URL_32_PATTERN, "nonce");
    assertBoolean(challenge.one_time, true, "one_time");
    if (challenge.state !== "issued" || challenge.consumed_at !== null) {
        fail("CHALLENGE_ALREADY_CONSUMED", "Pairing challenge is not an unconsumed issued challenge.");
    }
    const issuedAt = parseTime(challenge.issued_at, "issued_at");
    const expiresAt = parseTime(challenge.expires_at, "expires_at");
    if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_PAIRING_TTL_MS) {
        fail("CHALLENGE_TTL_INVALID", "Pairing challenge lifetime is invalid.");
    }
    if (issuedAt > now || expiresAt <= now) {
        fail("CHALLENGE_EXPIRED", "Pairing challenge is not live.");
    }
    assertString(
        challenge.challenge_fingerprint_sha256,
        SHA256_PATTERN,
        "challenge_fingerprint_sha256",
    );
    if (challenge.challenge_fingerprint_sha256 !== pairingChallengeFingerprint(challenge)) {
        fail("CHALLENGE_FINGERPRINT_MISMATCH", "Pairing challenge fingerprint is invalid.");
    }
    assertNoSensitiveFields(challenge);
    return challenge;
}

export function validatePairingAssertion(assertion, options = {}) {
    const allowFixture = options.allowFixture === true;
    assertObjectShape(assertion, [
        "contract_version",
        "fixture",
        "assertion_id",
        "binding_request_id",
        "challenge_id",
        "challenge_fingerprint_sha256",
        "runtime_binding",
        "runtime_key_thumbprint",
        "signature_algorithm",
        "signature_base64url",
        "state",
        "asserted_at",
    ], ["$comment"], "pairing assertion");
    fixtureGate(assertion, allowFixture, "pairing assertion");
    if (assertion.contract_version !== "noderooms-runtime-pairing-assertion-v1") {
        fail("CONTRACT_VERSION_MISMATCH", "Pairing assertion contract version is unsupported.");
    }
    assertString(assertion.assertion_id, ASSERTION_PATTERN, "assertion_id");
    assertString(assertion.binding_request_id, BINDING_REQUEST_PATTERN, "binding_request_id");
    assertString(assertion.challenge_id, CHALLENGE_PATTERN, "challenge_id");
    assertString(
        assertion.challenge_fingerprint_sha256,
        SHA256_PATTERN,
        "challenge_fingerprint_sha256",
    );
    validateRuntimeIdentity(assertion.runtime_binding);
    assertString(assertion.runtime_key_thumbprint, SHA256_PATTERN, "runtime_key_thumbprint");
    if (assertion.signature_algorithm !== "Ed25519") {
        fail("SIGNATURE_ALGORITHM_MISMATCH", "Pairing assertion must use Ed25519.");
    }
    assertString(
        assertion.signature_base64url,
        BASE64URL_ED25519_SIGNATURE_PATTERN,
        "signature_base64url",
    );
    if (assertion.state !== "submitted") {
        fail("ASSERTION_STATE_INVALID", "Pairing assertion is not submitted.");
    }
    parseTime(assertion.asserted_at, "asserted_at");
    assertNoSensitiveFields(assertion);
    return assertion;
}

export function verifyPairingAssertion({ challenge, assertion, now, allowFixture = false }) {
    const evaluationTime = normalizeNow(now ?? Date.now());
    validatePairingChallenge(challenge, { allowFixture, now: evaluationTime });
    validatePairingAssertion(assertion, { allowFixture });
    if (assertion.binding_request_id !== challenge.binding_request_id
        || assertion.challenge_id !== challenge.challenge_id
        || assertion.challenge_fingerprint_sha256 !== challenge.challenge_fingerprint_sha256) {
        fail("PAIRING_REFERENCE_MISMATCH", "Pairing assertion references a different challenge.");
    }
    if (!sameJson(assertion.runtime_binding, challenge.runtime_binding)
        || assertion.runtime_key_thumbprint !== challenge.runtime_key_thumbprint) {
        fail("PAIRING_RUNTIME_MISMATCH", "Pairing assertion runtime identity does not match the challenge.");
    }
    const assertedAt = parseTime(assertion.asserted_at, "asserted_at");
    const issuedAt = parseTime(challenge.issued_at, "issued_at");
    const expiresAt = parseTime(challenge.expires_at, "expires_at");
    if (assertedAt < issuedAt || assertedAt >= expiresAt || assertedAt > evaluationTime) {
        fail("ASSERTION_TIME_INVALID", "Pairing assertion time is outside the challenge lifetime.");
    }
    let validSignature = false;
    try {
        const publicKey = createPublicKey({
            key: challenge.runtime_public_key_jwk,
            format: "jwk",
        });
        validSignature = verify(
            null,
            Buffer.from(challenge.challenge_fingerprint_sha256, "utf8"),
            publicKey,
            Buffer.from(assertion.signature_base64url, "base64url"),
        );
    } catch {
        fail("ASSERTION_SIGNATURE_INVALID", "Pairing assertion signature could not be verified.");
    }
    if (!validSignature) {
        fail("ASSERTION_SIGNATURE_INVALID", "Pairing assertion signature is invalid.");
    }
    return Object.freeze({
        verified: true,
        binding_request_id: challenge.binding_request_id,
        challenge_id: challenge.challenge_id,
        assertion_id: assertion.assertion_id,
        challenge_fingerprint_sha256: challenge.challenge_fingerprint_sha256,
        runtime_key_thumbprint: challenge.runtime_key_thumbprint,
        atomic_challenge_consumption_required: true,
    });
}

export function validateRuntimeBindingRecord(binding, options = {}) {
    const allowFixture = options.allowFixture === true;
    const allowContractOnly = options.allowContractOnly === true;
    const now = normalizeNow(options.now ?? Date.now());
    assertObjectShape(binding, [
        "contract_version",
        "fixture",
        "binding_id",
        "binding_version",
        "activation_state",
        "live_enforce_allowed",
        "agent_binding",
        "runtime_binding",
        "runtime_key",
        "proof",
        "lifecycle",
        "constraints",
    ], ["$schema", "$comment"], "runtime binding");
    fixtureGate(binding, allowFixture, "runtime binding");
    if (binding.contract_version !== "noderooms-agent-passport-runtime-binding-v1") {
        fail("CONTRACT_VERSION_MISMATCH", "Runtime binding contract version is unsupported.");
    }
    assertString(binding.binding_id, BINDING_PATTERN, "binding_id");
    if (binding.binding_version !== 1) {
        fail("BINDING_VERSION_MISMATCH", "Runtime binding version is unsupported.");
    }
    if (!["contract_only", "active", "revoked", "expired"].includes(binding.activation_state)) {
        fail("ACTIVATION_STATE_INVALID", "Runtime binding activation state is invalid.");
    }
    assertBoolean(binding.live_enforce_allowed, false, "live_enforce_allowed");
    if (binding.activation_state === "contract_only" && !allowContractOnly) {
        fail("CONTRACT_ONLY_BINDING", "Contract-only runtime binding cannot authorize execution.");
    }
    validateAgentBinding(binding.agent_binding);
    validateRuntimeIdentity(binding.runtime_binding);
    assertObjectShape(binding.runtime_key, [
        "algorithm",
        "thumbprint_sha256",
        "public_key_jwk",
    ], [], "runtime_key");
    if (binding.runtime_key.algorithm !== "Ed25519") {
        fail("UNSUPPORTED_RUNTIME_KEY", "Runtime binding key algorithm is unsupported.");
    }
    validatePublicKeyJwk(binding.runtime_key.public_key_jwk, "runtime_key.public_key_jwk");
    assertString(binding.runtime_key.thumbprint_sha256, SHA256_PATTERN, "runtime_key.thumbprint_sha256");
    if (binding.runtime_key.thumbprint_sha256 !== runtimeKeyThumbprint(binding.runtime_key.public_key_jwk)) {
        fail("RUNTIME_KEY_THUMBPRINT_MISMATCH", "Runtime binding key thumbprint is invalid.");
    }
    assertObjectShape(binding.proof, [
        "binding_request_id",
        "challenge_id",
        "assertion_id",
        "challenge_fingerprint_sha256",
        "assertion_verified_at",
    ], [], "proof");
    assertString(binding.proof.binding_request_id, BINDING_REQUEST_PATTERN, "proof.binding_request_id");
    assertString(binding.proof.challenge_id, CHALLENGE_PATTERN, "proof.challenge_id");
    assertString(binding.proof.assertion_id, ASSERTION_PATTERN, "proof.assertion_id");
    assertString(
        binding.proof.challenge_fingerprint_sha256,
        SHA256_PATTERN,
        "proof.challenge_fingerprint_sha256",
    );
    const assertionVerifiedAt = parseTime(
        binding.proof.assertion_verified_at,
        "proof.assertion_verified_at",
    );
    assertObjectShape(binding.lifecycle, [
        "status",
        "issued_at",
        "expires_at",
        "revoked_at",
        "revocation_reason",
        "supersedes_binding_id",
    ], [], "lifecycle");
    if (!["paired", "revoked", "expired"].includes(binding.lifecycle.status)) {
        fail("BINDING_STATUS_INVALID", "Runtime binding lifecycle status is invalid.");
    }
    const issuedAt = parseTime(binding.lifecycle.issued_at, "lifecycle.issued_at");
    const expiresAt = parseTime(binding.lifecycle.expires_at, "lifecycle.expires_at");
    if (expiresAt <= issuedAt || issuedAt > now || assertionVerifiedAt > issuedAt) {
        fail("BINDING_LIFETIME_INVALID", "Runtime binding lifetime is invalid.");
    }
    if (binding.lifecycle.status === "paired") {
        if (binding.lifecycle.revoked_at !== null || binding.lifecycle.revocation_reason !== null) {
            fail("BINDING_REVOCATION_MISMATCH", "Paired runtime binding contains revocation state.");
        }
        if (expiresAt <= now) {
            fail("BINDING_EXPIRED", "Runtime binding has expired.");
        }
    } else if (binding.lifecycle.status === "revoked") {
        const revokedAt = parseTime(binding.lifecycle.revoked_at, "lifecycle.revoked_at");
        if (revokedAt < issuedAt || revokedAt > now) {
            fail("BINDING_REVOCATION_MISMATCH", "Runtime binding revocation time is invalid.");
        }
        if (typeof binding.lifecycle.revocation_reason !== "string"
            || !/^[a-z][a-z0-9_]{2,63}$/.test(binding.lifecycle.revocation_reason)) {
            fail("BINDING_REVOCATION_MISMATCH", "Revoked runtime binding has no valid reason.");
        }
    } else if (expiresAt > now) {
        fail("BINDING_EXPIRY_MISMATCH", "Expired runtime binding has a live expiry time.");
    }
    if (binding.lifecycle.supersedes_binding_id !== null) {
        assertString(
            binding.lifecycle.supersedes_binding_id,
            BINDING_PATTERN,
            "lifecycle.supersedes_binding_id",
        );
        if (binding.lifecycle.supersedes_binding_id === binding.binding_id) {
            fail("BINDING_SELF_SUPERSESSION", "Runtime binding cannot supersede itself.");
        }
    }
    assertObjectShape(binding.constraints, [
        "one_time_pairing_required",
        "multi_agent_gateway_allowed",
        "shared_run_secret_allowed",
        "shared_lease_allowed",
        "cross_agent_binding_allowed",
        "owner_revalidation_on_recovery",
    ], [], "constraints");
    assertBoolean(binding.constraints.one_time_pairing_required, true, "constraints.one_time_pairing_required");
    assertBoolean(binding.constraints.multi_agent_gateway_allowed, true, "constraints.multi_agent_gateway_allowed");
    assertBoolean(binding.constraints.shared_run_secret_allowed, false, "constraints.shared_run_secret_allowed");
    assertBoolean(binding.constraints.shared_lease_allowed, false, "constraints.shared_lease_allowed");
    assertBoolean(binding.constraints.cross_agent_binding_allowed, false, "constraints.cross_agent_binding_allowed");
    assertBoolean(
        binding.constraints.owner_revalidation_on_recovery,
        true,
        "constraints.owner_revalidation_on_recovery",
    );
    if (binding.activation_state === "revoked" && binding.lifecycle.status !== "revoked") {
        fail("ACTIVATION_LIFECYCLE_MISMATCH", "Revoked activation state requires revoked lifecycle.");
    }
    if (binding.activation_state === "expired" && binding.lifecycle.status !== "expired") {
        fail("ACTIVATION_LIFECYCLE_MISMATCH", "Expired activation state requires expired lifecycle.");
    }
    if (binding.activation_state === "active" && binding.lifecycle.status !== "paired") {
        fail("ACTIVATION_LIFECYCLE_MISMATCH", "Active runtime binding must be paired.");
    }
    if (binding.activation_state === "contract_only" && binding.lifecycle.status !== "paired") {
        fail("ACTIVATION_LIFECYCLE_MISMATCH", "Contract-only runtime binding must be paired.");
    }
    assertNoSensitiveFields(binding);
    return binding;
}

export function evaluateRuntimeBinding({
    binding,
    expectedAgentBinding,
    runtimeContext,
    now = Date.now(),
    allowFixture = false,
    allowContractOnly = false,
}) {
    try {
        validateRuntimeBindingRecord(binding, {
            allowFixture,
            allowContractOnly,
            now,
        });
        validateAgentBinding(expectedAgentBinding, "expected_agent_binding");
        validateRuntimeContext(runtimeContext);
    } catch (error) {
        const code = error instanceof PassportRuntimeBindingError ? error.code : "BINDING_VALIDATION_FAILED";
        return Object.freeze({ decision: "block_invalid_binding", reason_code: code });
    }
    if (binding.activation_state !== "active"
        && !(allowContractOnly && binding.activation_state === "contract_only")) {
        return Object.freeze({
            decision: "block_inactive_binding",
            reason_code: `BINDING_${binding.activation_state.toUpperCase()}`,
        });
    }
    for (const field of [
        "noderooms_agent_id",
        "passport_id",
        "owner_binding_id",
        "verified_owner_required",
    ]) {
        if (expectedAgentBinding[field] !== binding.agent_binding[field]) {
            return Object.freeze({
                decision: "block_agent_binding_mismatch",
                reason_code: `MISMATCH_${field.toUpperCase()}`,
            });
        }
    }
    for (const field of ["platform", "gateway_id", "runtime_instance_id", "openclaw_agent_id"]) {
        if (runtimeContext[field] !== binding.runtime_binding[field]) {
            return Object.freeze({
                decision: "block_runtime_mismatch",
                reason_code: `MISMATCH_${field.toUpperCase()}`,
            });
        }
    }
    if (runtimeContext.runtime_key_thumbprint !== binding.runtime_key.thumbprint_sha256) {
        return Object.freeze({
            decision: "block_runtime_mismatch",
            reason_code: "MISMATCH_RUNTIME_KEY_THUMBPRINT",
        });
    }
    return Object.freeze({
        decision: allowContractOnly && binding.activation_state === "contract_only"
            ? "contract_match_not_authorized"
            : "binding_match",
        reason_code: allowContractOnly && binding.activation_state === "contract_only"
            ? "LIVE_ENFORCE_PROHIBITED"
            : "EXACT_BINDING_MATCH",
        binding_id: binding.binding_id,
        noderooms_agent_id: binding.agent_binding.noderooms_agent_id,
        passport_id: binding.agent_binding.passport_id,
        owner_binding_id: binding.agent_binding.owner_binding_id,
        openclaw_agent_id: binding.runtime_binding.openclaw_agent_id,
        runtime_key_thumbprint: binding.runtime_key.thumbprint_sha256,
    });
}

export function validateBindingSet(bindings, options = {}) {
    if (!Array.isArray(bindings) || bindings.length === 0 || bindings.length > 256) {
        fail("BINDING_SET_INVALID", "Runtime binding set is invalid.");
    }
    const bindingIds = new Set();
    const agentAuthorities = new Set();
    const runtimeAuthorities = new Set();
    const keyAuthorities = new Set();
    const proofAuthorities = new Set();
    const gateways = new Set();
    for (const binding of bindings) {
        validateRuntimeBindingRecord(binding, options);
        if (bindingIds.has(binding.binding_id)) {
            fail("DUPLICATE_BINDING_ID", "Runtime binding id is duplicated.");
        }
        bindingIds.add(binding.binding_id);
        const agentAuthority = `${binding.runtime_binding.gateway_id}\n${binding.runtime_binding.openclaw_agent_id}`;
        if (agentAuthorities.has(agentAuthority)) {
            fail("SHARED_AGENT_AUTHORITY", "One Gateway has duplicate live authority for an OpenClaw Agent.");
        }
        agentAuthorities.add(agentAuthority);
        const runtimeAuthority = [
            binding.runtime_binding.gateway_id,
            binding.runtime_binding.runtime_instance_id,
            binding.runtime_binding.openclaw_agent_id,
        ].join("\n");
        if (runtimeAuthorities.has(runtimeAuthority)) {
            fail("SHARED_RUNTIME_AUTHORITY", "Runtime authority tuple is duplicated.");
        }
        runtimeAuthorities.add(runtimeAuthority);
        if (keyAuthorities.has(binding.runtime_key.thumbprint_sha256)) {
            fail("SHARED_RUNTIME_KEY", "Runtime key authority is shared across bindings.");
        }
        keyAuthorities.add(binding.runtime_key.thumbprint_sha256);
        const proofAuthority = [
            binding.proof.binding_request_id,
            binding.proof.challenge_id,
            binding.proof.assertion_id,
            binding.proof.challenge_fingerprint_sha256,
        ].join("\n");
        if (proofAuthorities.has(proofAuthority)) {
            fail("SHARED_PAIRING_PROOF", "One-use pairing proof is shared across bindings.");
        }
        proofAuthorities.add(proofAuthority);
        gateways.add(binding.runtime_binding.gateway_id);
    }
    return Object.freeze({
        binding_count: bindings.length,
        gateway_count: gateways.size,
        multi_agent_gateway_safe: bindings.length > gateways.size,
        shared_run_secret_allowed: false,
        shared_lease_allowed: false,
    });
}

export function validateRecoveryRecord(recovery, options = {}) {
    const allowFixture = options.allowFixture === true;
    const now = normalizeNow(options.now ?? Date.now());
    assertObjectShape(recovery, [
        "contract_version",
        "fixture",
        "recovery_id",
        "reason",
        "agent_binding",
        "previous_binding",
        "replacement_binding",
        "owner_revalidation",
        "passport_continuity",
        "lease_transition",
        "completed_at",
    ], ["$comment"], "runtime binding recovery");
    fixtureGate(recovery, allowFixture, "runtime binding recovery");
    if (recovery.contract_version !== "noderooms-runtime-binding-recovery-v1") {
        fail("CONTRACT_VERSION_MISMATCH", "Runtime binding recovery contract version is unsupported.");
    }
    assertString(recovery.recovery_id, RECOVERY_PATTERN, "recovery_id");
    if (!["runtime_reinstalled", "runtime_key_rotated", "gateway_replaced"].includes(recovery.reason)) {
        fail("RECOVERY_REASON_INVALID", "Runtime binding recovery reason is invalid.");
    }
    validateAgentBinding(recovery.agent_binding);
    for (const [label, value] of [
        ["previous_binding", recovery.previous_binding],
        ["replacement_binding", recovery.replacement_binding],
    ]) {
        assertObjectShape(value, [
            "binding_id",
            "gateway_id",
            "runtime_instance_id",
            "openclaw_agent_id",
            "runtime_key_thumbprint",
            "status",
            "changed_at",
        ], [], label);
        assertString(value.binding_id, BINDING_PATTERN, `${label}.binding_id`);
        assertString(value.gateway_id, GATEWAY_PATTERN, `${label}.gateway_id`);
        assertString(value.runtime_instance_id, RUNTIME_INSTANCE_PATTERN, `${label}.runtime_instance_id`);
        assertString(value.openclaw_agent_id, OPENCLAW_AGENT_PATTERN, `${label}.openclaw_agent_id`);
        assertString(value.runtime_key_thumbprint, SHA256_PATTERN, `${label}.runtime_key_thumbprint`);
        parseTime(value.changed_at, `${label}.changed_at`);
    }
    if (recovery.previous_binding.status !== "revoked"
        || recovery.replacement_binding.status !== "paired") {
        fail("RECOVERY_BINDING_STATE_INVALID", "Recovery must revoke the old binding before pairing the replacement.");
    }
    if (recovery.previous_binding.binding_id === recovery.replacement_binding.binding_id
        || recovery.previous_binding.runtime_instance_id === recovery.replacement_binding.runtime_instance_id
        || recovery.previous_binding.runtime_key_thumbprint === recovery.replacement_binding.runtime_key_thumbprint) {
        fail("RECOVERY_AUTHORITY_REUSED", "Recovery reused old binding authority.");
    }
    if (recovery.previous_binding.openclaw_agent_id !== recovery.replacement_binding.openclaw_agent_id) {
        fail("RECOVERY_AGENT_MISMATCH", "Recovery changed the OpenClaw Agent identity.");
    }
    assertObjectShape(recovery.owner_revalidation, [
        "required",
        "decision",
        "owner_binding_id",
        "approved_at",
    ], [], "owner_revalidation");
    assertBoolean(recovery.owner_revalidation.required, true, "owner_revalidation.required");
    if (recovery.owner_revalidation.decision !== "approved") {
        fail("OWNER_REVALIDATION_REQUIRED", "Runtime recovery lacks explicit Owner approval.");
    }
    assertString(
        recovery.owner_revalidation.owner_binding_id,
        OWNER_BINDING_PATTERN,
        "owner_revalidation.owner_binding_id",
    );
    if (recovery.owner_revalidation.owner_binding_id !== recovery.agent_binding.owner_binding_id) {
        fail("OWNER_BINDING_MISMATCH", "Runtime recovery Owner binding does not match the Agent.");
    }
    parseTime(recovery.owner_revalidation.approved_at, "owner_revalidation.approved_at");
    assertObjectShape(recovery.passport_continuity, [
        "noderooms_agent_id_preserved",
        "passport_id_preserved",
    ], [], "passport_continuity");
    assertBoolean(
        recovery.passport_continuity.noderooms_agent_id_preserved,
        true,
        "passport_continuity.noderooms_agent_id_preserved",
    );
    assertBoolean(
        recovery.passport_continuity.passport_id_preserved,
        true,
        "passport_continuity.passport_id_preserved",
    );
    assertObjectShape(recovery.lease_transition, [
        "previous_lease_reused",
        "previous_run_secret_reused",
        "new_lease_required",
    ], [], "lease_transition");
    assertBoolean(recovery.lease_transition.previous_lease_reused, false, "lease_transition.previous_lease_reused");
    assertBoolean(
        recovery.lease_transition.previous_run_secret_reused,
        false,
        "lease_transition.previous_run_secret_reused",
    );
    assertBoolean(recovery.lease_transition.new_lease_required, true, "lease_transition.new_lease_required");
    if (parseTime(recovery.completed_at, "completed_at") > now) {
        fail("RECOVERY_TIME_INVALID", "Runtime binding recovery completion time is in the future.");
    }
    assertNoSensitiveFields(recovery);
    return recovery;
}
