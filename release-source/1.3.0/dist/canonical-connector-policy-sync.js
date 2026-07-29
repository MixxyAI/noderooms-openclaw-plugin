import { createPublicKey, verify } from "node:crypto";

import {
    canonicalJson,
    sha256Fingerprint,
} from "./passport-runtime-binding.js";
import {
    validateRuntimeToolInventoryV1,
} from "./universal-connector-engine.js";

export const CANONICAL_CONNECTOR_POLICY_BUNDLE_CONTRACT_VERSION =
    "noderooms-canonical-connector-policy-bundle-v1";
export const CANONICAL_POLICY_TRUST_ANCHOR_CONTRACT_VERSION =
    "noderooms-canonical-policy-trust-anchor-v1";
export const CANONICAL_POLICY_SYNC_CHECKPOINT_CONTRACT_VERSION =
    "noderooms-canonical-policy-sync-checkpoint-v1";
export const CANONICAL_POLICY_INVENTORY_BINDING_CONTRACT_VERSION =
    "noderooms-canonical-policy-inventory-binding-v1";
export const CANONICAL_POLICY_SYNC_LIVE_FETCH_ALLOWED = false;
export const CANONICAL_POLICY_SYNC_GRANTS_TOOL_AUTHORITY = false;

const CANONICAL_ORIGIN = "https://noderooms.com";
const CANONICAL_PATH =
    "/.well-known/noderooms/connector-policy-v1.json";
const MAX_BUNDLE_BYTES = 524_288;
const MAX_POLICY_WINDOW_MS = 24 * 60 * 60 * 1_000;
const MAX_PROFILES = 256;

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const BUNDLE_ID_PATTERN = /^nrpolicy_[a-f0-9]{32}$/;
const KEY_ID_PATTERN = /^nrpk_[a-z0-9][a-z0-9._-]{2,63}$/;
const PROFILE_ID_PATTERN = /^nrscp_[a-z0-9][a-z0-9_]{2,95}$/;
const SCOPE_PATTERN =
    /^connector\.[a-z][a-z0-9_]{1,31}\.[a-z][a-z0-9_]{1,47}\.[a-z][a-z0-9_]{1,47}$/;
const PROVIDER_PATTERN = /^[a-z][a-z0-9_]{1,31}$/;
const CONNECTOR_PATTERN = /^[a-z][a-z0-9._:-]{2,127}$/;
const CONNECTOR_VERSION_PATTERN =
    /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/;
const TOOL_NAME_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const OWNER_ID_PATTERN = /^[A-Za-z0-9._:@/-]{1,160}$/;
const ACTION_PATTERN = /^[a-z][a-z0-9_]{1,63}$/;
const REGISTRY_VERSION_PATTERN =
    /^nrcr_[a-z0-9][a-z0-9._-]{2,63}$/;
const POLICY_VERSION_PATTERN =
    /^nrp_[a-z0-9][a-z0-9._-]{2,63}$/;
const COMMIT_PATTERN = /^[a-f0-9]{40}$/;
const BASE64URL_32_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const BASE64URL_ED25519_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const CLAIM_PATTERN = /^[a-z][a-z0-9_]{1,63}$/;
const SCHEMA_PROPERTY_PATTERN = /^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$/;

const SYNC_REASONS = new Set([
    "gateway_start",
    "owner_inspection",
    "manual_owner_sync",
    "contract_test",
    "before_phase4c_proof",
]);
const RISKS = new Set(["low", "medium", "high", "critical"]);
const SIDE_EFFECT_CLASSES = new Set([
    "read",
    "write",
    "destructive",
    "admin",
]);
const REPLAY_SEMANTICS = new Set([
    "replay_safe_read",
    "at_most_once_dispatch",
    "provider_idempotent",
]);
const RECEIPT_PROFILES = new Set([
    "read_observation_v1",
    "external_action_receipt_v2",
]);
const OWNER_KINDS = new Set(["core", "plugin", "channel", "mcp"]);

export class CanonicalConnectorPolicySyncError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "CanonicalConnectorPolicySyncError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new CanonicalConnectorPolicySyncError(code, message);
}

function isRecord(value) {
    return Boolean(value) && typeof value === "object"
        && !Array.isArray(value);
}

function assertExactKeys(value, required, optional, label) {
    if (!isRecord(value)) {
        fail("POLICY_CONTRACT_INVALID", `${label} must be an object.`);
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail(
                "POLICY_CONTRACT_INVALID",
                `${label} contains unsupported field ${key}.`,
            );
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail(
                "POLICY_CONTRACT_INVALID",
                `${label} is missing ${key}.`,
            );
        }
    }
}

function assertString(value, pattern, label, maxLength = 512) {
    if (typeof value !== "string"
        || value.length < 1
        || value.length > maxLength
        || !pattern.test(value)) {
        fail("POLICY_CONTRACT_INVALID", `${label} is invalid.`);
    }
    return value;
}

function parseTime(value, label) {
    const parsed = typeof value === "string"
        ? Date.parse(value)
        : Number.NaN;
    if (!Number.isFinite(parsed)) {
        fail("POLICY_TIME_INVALID", `${label} is invalid.`);
    }
    return parsed;
}

function normalizeNow(value) {
    const parsed = value instanceof Date ? value.getTime() : Number(value);
    if (!Number.isFinite(parsed)) {
        fail("POLICY_TIME_INVALID", "Policy evaluation time is invalid.");
    }
    return parsed;
}

function cloneJson(value, label, maximumBytes = MAX_BUNDLE_BYTES) {
    let serialized;
    try {
        serialized = JSON.stringify(value);
    }
    catch {
        fail("POLICY_CONTRACT_INVALID", `${label} is not JSON-compatible.`);
    }
    if (!serialized
        || Buffer.byteLength(serialized, "utf8") > maximumBytes) {
        fail(
            "POLICY_SIZE_LIMIT_EXCEEDED",
            `${label} exceeds the bounded size.`,
        );
    }
    try {
        return JSON.parse(serialized);
    }
    catch {
        fail("POLICY_CONTRACT_INVALID", `${label} is not valid JSON.`);
    }
}

function deepFreeze(value) {
    if (Array.isArray(value)) {
        value.forEach(deepFreeze);
        return Object.freeze(value);
    }
    if (isRecord(value)) {
        Object.values(value).forEach(deepFreeze);
        return Object.freeze(value);
    }
    return value;
}

function fixtureGate(value, allowFixture, label) {
    if (typeof value.fixture !== "boolean") {
        fail("POLICY_CONTRACT_INVALID", `${label}.fixture is invalid.`);
    }
    if (value.fixture && !allowFixture) {
        fail("POLICY_FIXTURE_REJECTED", `${label} is a non-live fixture.`);
    }
}

function assertNoSensitiveFields(value, path = "$") {
    if (Array.isArray(value)) {
        value.forEach((entry, index) =>
            assertNoSensitiveFields(entry, `${path}[${index}]`));
        return;
    }
    if (!isRecord(value)) {
        return;
    }
    for (const [key, entry] of Object.entries(value)) {
        const safePolicyBoolean = typeof entry === "boolean";
        if (!safePolicyBoolean
            && /(?:secret|token|authorization|cookie|private_key|credential|raw_prompt|raw_request|raw_response|raw_result)/i
                .test(key)) {
            fail(
                "POLICY_SENSITIVE_FIELD_FORBIDDEN",
                `Sensitive field is forbidden at ${path}.${key}.`,
            );
        }
        assertNoSensitiveFields(entry, `${path}.${key}`);
    }
}

function validatePublicKeyJwk(value) {
    assertExactKeys(
        value,
        ["kty", "crv", "x"],
        [],
        "policy trust anchor public_key_jwk",
    );
    if (value.kty !== "OKP" || value.crv !== "Ed25519") {
        fail(
            "POLICY_KEY_INVALID",
            "Policy trust anchor must be an Ed25519 OKP public key.",
        );
    }
    assertString(
        value.x,
        BASE64URL_32_PATTERN,
        "policy trust anchor public_key_jwk.x",
        43,
    );
    return value;
}

function policyKeyThumbprint(publicKeyJwk) {
    return sha256Fingerprint({
        crv: publicKeyJwk.crv,
        kty: publicKeyJwk.kty,
        x: publicKeyJwk.x,
    });
}

function validateResourceSelector(value, profileIndex) {
    const label = `registry.profiles[${profileIndex}].resource_selector`;
    assertExactKeys(
        value,
        ["strategy", "required_claims", "wildcards_allowed"],
        [],
        label,
    );
    if (value.strategy !== "exact"
        || value.wildcards_allowed !== false
        || !Array.isArray(value.required_claims)
        || value.required_claims.length < 1
        || value.required_claims.length > 16) {
        fail("POLICY_RESOURCE_INVALID", `${label} is invalid.`);
    }
    const claims = value.required_claims.map((claim, claimIndex) =>
        assertString(
            claim,
            CLAIM_PATTERN,
            `${label}.required_claims[${claimIndex}]`,
            64,
        ));
    if (new Set(claims).size !== claims.length) {
        fail(
            "POLICY_RESOURCE_INVALID",
            `${label} contains duplicate claims.`,
        );
    }
    return claims;
}

function validateCanonicalConnectorRegistryV1(registry) {
    assertExactKeys(
        registry,
        [
            "contract_version",
            "registry_version",
            "policy_version",
            "activation_state",
            "live_enforce_allowed",
            "source_provenance",
            "profiles",
        ],
        ["$schema"],
        "registry",
    );
    if (registry.contract_version
            !== "noderooms-connector-scope-registry-v1") {
        fail(
            "POLICY_REGISTRY_INVALID",
            "Connector registry version is unsupported.",
        );
    }
    assertString(
        registry.registry_version,
        REGISTRY_VERSION_PATTERN,
        "registry.registry_version",
        68,
    );
    assertString(
        registry.policy_version,
        POLICY_VERSION_PATTERN,
        "registry.policy_version",
        67,
    );
    if (registry.activation_state !== "contract_only"
        || registry.live_enforce_allowed !== false) {
        fail(
            "POLICY_LIVE_AUTHORITY_FORBIDDEN",
            "Phase 4B accepts only a contract-only, non-live registry.",
        );
    }
    assertExactKeys(
        registry.source_provenance,
        ["repository", "commit", "tree"],
        [],
        "registry.source_provenance",
    );
    if (registry.source_provenance.repository
            !== "MixxyAI/noderooms-openclaw-plugin") {
        fail(
            "POLICY_PROVENANCE_INVALID",
            "Registry repository provenance is invalid.",
        );
    }
    assertString(
        registry.source_provenance.commit,
        COMMIT_PATTERN,
        "registry.source_provenance.commit",
        40,
    );
    assertString(
        registry.source_provenance.tree,
        COMMIT_PATTERN,
        "registry.source_provenance.tree",
        40,
    );
    if (!Array.isArray(registry.profiles)
        || registry.profiles.length < 1
        || registry.profiles.length > MAX_PROFILES) {
        fail(
            "POLICY_REGISTRY_INVALID",
            "Connector registry profiles are invalid.",
        );
    }

    const profileIds = new Set();
    const scopes = new Set();
    const toolNames = new Set();
    for (const [index, profile] of registry.profiles.entries()) {
        const label = `registry.profiles[${index}]`;
        assertExactKeys(
            profile,
            [
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
            ],
            [],
            label,
        );
        assertString(
            profile.profile_id,
            PROFILE_ID_PATTERN,
            `${label}.profile_id`,
            100,
        );
        assertString(profile.scope, SCOPE_PATTERN, `${label}.scope`, 150);
        assertString(
            profile.provider,
            PROVIDER_PATTERN,
            `${label}.provider`,
            32,
        );
        assertString(
            profile.connector_id,
            CONNECTOR_PATTERN,
            `${label}.connector_id`,
            128,
        );
        assertString(
            profile.connector_version,
            CONNECTOR_VERSION_PATTERN,
            `${label}.connector_version`,
            128,
        );
        assertString(
            profile.tool_name,
            TOOL_NAME_PATTERN,
            `${label}.tool_name`,
            128,
        );
        assertString(
            profile.tool_schema_fingerprint,
            SHA256_PATTERN,
            `${label}.tool_schema_fingerprint`,
            71,
        );
        assertString(
            profile.action,
            ACTION_PATTERN,
            `${label}.action`,
            64,
        );
        assertString(
            profile.resource_type,
            ACTION_PATTERN,
            `${label}.resource_type`,
            64,
        );
        assertString(
            profile.description,
            /^.{1,512}$/s,
            `${label}.description`,
            512,
        );
        if (profile.status !== "reference_only") {
            fail(
                "POLICY_LIVE_AUTHORITY_FORBIDDEN",
                `${label} must remain reference_only in Phase 4B.`,
            );
        }
        if (!RISKS.has(profile.risk)
            || !SIDE_EFFECT_CLASSES.has(profile.side_effect_class)
            || !REPLAY_SEMANTICS.has(profile.replay_semantics)
            || !RECEIPT_PROFILES.has(profile.receipt_profile)
            || !["none", "allow_once"].includes(profile.approval_policy)) {
            fail(
                "POLICY_PROFILE_INVALID",
                `${label} policy metadata is invalid.`,
            );
        }
        const selectorClaims = validateResourceSelector(
            profile.resource_selector,
            index,
        );
        const schema = cloneJson(
            profile.tool_input_schema,
            `${label}.tool_input_schema`,
            262_144,
        );
        if (!isRecord(schema)
            || schema.type !== "object"
            || schema.additionalProperties !== false
            || !isRecord(schema.properties)
            || !Array.isArray(schema.required)
            || schema.required.length < 1
            || schema.required.length > 64) {
            fail(
                "POLICY_SCHEMA_INVALID",
                `${label} input schema is not exact.`,
            );
        }
        const requiredProperties = schema.required.map(
            (property, requiredIndex) =>
                assertString(
                    property,
                    SCHEMA_PROPERTY_PATTERN,
                    `${label}.tool_input_schema.required[${requiredIndex}]`,
                    128,
                ),
        );
        if (new Set(requiredProperties).size
                !== requiredProperties.length
            || requiredProperties.some((property) =>
                !Object.hasOwn(schema.properties, property))) {
            fail(
                "POLICY_SCHEMA_INVALID",
                `${label} required schema properties are invalid.`,
            );
        }
        if (sha256Fingerprint(schema)
                !== profile.tool_schema_fingerprint) {
            fail(
                "POLICY_SCHEMA_DRIFT",
                `${label} input schema fingerprint has drifted.`,
            );
        }
        for (const claim of selectorClaims) {
            if (!Object.hasOwn(schema.properties, claim)
                || !requiredProperties.includes(claim)) {
                fail(
                    "POLICY_RESOURCE_INVALID",
                    `${label} schema does not require resource claim ${claim}.`,
                );
            }
        }
        const sideEffecting = profile.side_effect_class !== "read";
        if ((profile.risk === "high" || profile.risk === "critical"
                || sideEffecting)
            && profile.approval_policy !== "allow_once") {
            fail(
                "POLICY_APPROVAL_INVALID",
                `${label} requires allow-once Owner approval.`,
            );
        }
        if (sideEffecting
            && profile.replay_semantics === "replay_safe_read") {
            fail(
                "POLICY_REPLAY_INVALID",
                `${label} cannot mark a write as replay-safe read.`,
            );
        }
        if (sideEffecting
            && profile.receipt_profile
                !== "external_action_receipt_v2") {
            fail(
                "POLICY_RECEIPT_INVALID",
                `${label} requires a canonical external-action receipt.`,
            );
        }
        if (profileIds.has(profile.profile_id)
            || scopes.has(profile.scope)
            || toolNames.has(profile.tool_name)) {
            fail(
                "POLICY_REGISTRY_DUPLICATE",
                "Registry profile, scope, and tool bindings must be unique.",
            );
        }
        profileIds.add(profile.profile_id);
        scopes.add(profile.scope);
        toolNames.add(profile.tool_name);
    }
    assertNoSensitiveFields(registry);
    return deepFreeze(cloneJson(registry, "registry"));
}

function validateRuntimeToolBindings(value, registry) {
    if (!Array.isArray(value)
        || value.length !== registry.profiles.length
        || value.length > MAX_PROFILES) {
        fail(
            "POLICY_OWNER_BINDING_INVALID",
            "Runtime tool owner bindings are incomplete.",
        );
    }
    const profiles = new Map(
        registry.profiles.map((profile) => [
            profile.profile_id,
            profile,
        ]),
    );
    const profileIds = new Set();
    const toolNames = new Set();
    const bindings = value.map((binding, index) => {
        const label = `runtime_tool_bindings[${index}]`;
        assertExactKeys(
            binding,
            ["profile_id", "tool_name", "owner"],
            [],
            label,
        );
        assertString(
            binding.profile_id,
            PROFILE_ID_PATTERN,
            `${label}.profile_id`,
            100,
        );
        assertString(
            binding.tool_name,
            TOOL_NAME_PATTERN,
            `${label}.tool_name`,
            128,
        );
        assertExactKeys(
            binding.owner,
            ["kind", "owner_id", "resolution"],
            [],
            `${label}.owner`,
        );
        if (!OWNER_KINDS.has(binding.owner.kind)
            || binding.owner.resolution !== "exact") {
            fail(
                "POLICY_OWNER_BINDING_INVALID",
                `${label} owner must be exact.`,
            );
        }
        assertString(
            binding.owner.owner_id,
            OWNER_ID_PATTERN,
            `${label}.owner.owner_id`,
            160,
        );
        const profile = profiles.get(binding.profile_id);
        if (!profile || profile.tool_name !== binding.tool_name) {
            fail(
                "POLICY_OWNER_BINDING_INVALID",
                `${label} does not match its canonical profile.`,
            );
        }
        if (profileIds.has(binding.profile_id)
            || toolNames.has(binding.tool_name)) {
            fail(
                "POLICY_OWNER_BINDING_DUPLICATE",
                "Runtime tool owner bindings must be unique.",
            );
        }
        profileIds.add(binding.profile_id);
        toolNames.add(binding.tool_name);
        return deepFreeze(cloneJson(binding, label, 4_096));
    });
    return deepFreeze(bindings);
}

export function validateCanonicalPolicyTrustAnchorV1(
    trustAnchor,
    options = {},
) {
    assertExactKeys(
        trustAnchor,
        [
            "contract_version",
            "fixture",
            "activation_state",
            "canonical_origin",
            "key_id",
            "algorithm",
            "public_key_jwk",
            "key_thumbprint_sha256",
            "valid_from",
            "valid_until",
        ],
        ["$schema", "$comment"],
        "policy trust anchor",
    );
    fixtureGate(
        trustAnchor,
        options.allowFixture === true,
        "policy trust anchor",
    );
    if (trustAnchor.contract_version
            !== CANONICAL_POLICY_TRUST_ANCHOR_CONTRACT_VERSION
        || trustAnchor.activation_state !== "contract_only"
        || trustAnchor.canonical_origin !== CANONICAL_ORIGIN
        || trustAnchor.algorithm !== "Ed25519") {
        fail(
            "POLICY_TRUST_ANCHOR_INVALID",
            "Policy trust anchor metadata is invalid.",
        );
    }
    assertString(
        trustAnchor.key_id,
        KEY_ID_PATTERN,
        "policy trust anchor key_id",
        68,
    );
    const publicKeyJwk = validatePublicKeyJwk(
        trustAnchor.public_key_jwk,
    );
    assertString(
        trustAnchor.key_thumbprint_sha256,
        SHA256_PATTERN,
        "policy trust anchor key_thumbprint_sha256",
        71,
    );
    if (policyKeyThumbprint(publicKeyJwk)
            !== trustAnchor.key_thumbprint_sha256) {
        fail(
            "POLICY_TRUST_ANCHOR_DRIFT",
            "Policy trust anchor thumbprint has drifted.",
        );
    }
    const validFrom = parseTime(
        trustAnchor.valid_from,
        "policy trust anchor valid_from",
    );
    const validUntil = parseTime(
        trustAnchor.valid_until,
        "policy trust anchor valid_until",
    );
    const now = normalizeNow(options.now ?? Date.now());
    if (validUntil <= validFrom || now < validFrom || now >= validUntil) {
        fail(
            "POLICY_TRUST_ANCHOR_EXPIRED",
            "Policy trust anchor is outside its validity window.",
        );
    }
    assertNoSensitiveFields(trustAnchor);
    return deepFreeze(cloneJson(trustAnchor, "policy trust anchor"));
}

function policyBundleProjection(bundle) {
    return {
        contract_version: bundle.contract_version,
        fixture: bundle.fixture,
        activation_state: bundle.activation_state,
        live_policy_sync_allowed: bundle.live_policy_sync_allowed,
        live_enforce_allowed: bundle.live_enforce_allowed,
        bundle_id: bundle.bundle_id,
        sequence: bundle.sequence,
        canonical_source: bundle.canonical_source,
        issued_at: bundle.issued_at,
        not_before: bundle.not_before,
        expires_at: bundle.expires_at,
        previous_bundle_fingerprint_sha256:
            bundle.previous_bundle_fingerprint_sha256,
        registry: bundle.registry,
        registry_fingerprint_sha256:
            bundle.registry_fingerprint_sha256,
        runtime_tool_bindings: bundle.runtime_tool_bindings,
        safety: bundle.safety,
    };
}

function policyBundleSignatureProjection(bundle) {
    return {
        domain:
            "noderooms-canonical-connector-policy-bundle-signature-v1",
        bundle_id: bundle.bundle_id,
        sequence: bundle.sequence,
        bundle_fingerprint_sha256:
            bundle.bundle_fingerprint_sha256,
        key_id: bundle.attestation.key_id,
        key_thumbprint_sha256:
            bundle.attestation.key_thumbprint_sha256,
        signed_at: bundle.attestation.signed_at,
    };
}

export function canonicalPolicyBundleFingerprint(bundle) {
    return sha256Fingerprint(policyBundleProjection(bundle));
}

export function canonicalPolicyBundleSignaturePayload(bundle) {
    return canonicalJson(policyBundleSignatureProjection(bundle));
}

function validateBundleSafety(value) {
    assertExactKeys(
        value,
        [
            "grants_tool_authority",
            "grants_connector_execution_authority",
            "performs_network_request",
            "invokes_connector",
            "performs_external_write",
            "automates_owner_decision",
            "persists_provider_credentials",
        ],
        [],
        "policy bundle safety",
    );
    for (const [key, entry] of Object.entries(value)) {
        if (entry !== false) {
            fail(
                "POLICY_LIVE_AUTHORITY_FORBIDDEN",
                `Policy bundle safety flag ${key} must remain false.`,
            );
        }
    }
}

export function validateCanonicalConnectorPolicyBundleV1(
    bundle,
    options = {},
) {
    const now = normalizeNow(options.now ?? Date.now());
    const trustAnchor = validateCanonicalPolicyTrustAnchorV1(
        options.trustAnchor,
        {
            allowFixture: options.allowFixture === true,
            now,
        },
    );
    const boundedBundle = cloneJson(bundle, "policy bundle");
    assertExactKeys(
        boundedBundle,
        [
            "contract_version",
            "fixture",
            "activation_state",
            "live_policy_sync_allowed",
            "live_enforce_allowed",
            "bundle_id",
            "sequence",
            "canonical_source",
            "issued_at",
            "not_before",
            "expires_at",
            "previous_bundle_fingerprint_sha256",
            "registry",
            "registry_fingerprint_sha256",
            "runtime_tool_bindings",
            "safety",
            "bundle_fingerprint_sha256",
            "attestation",
        ],
        ["$schema", "$comment"],
        "policy bundle",
    );
    fixtureGate(
        boundedBundle,
        options.allowFixture === true,
        "policy bundle",
    );
    if (boundedBundle.contract_version
            !== CANONICAL_CONNECTOR_POLICY_BUNDLE_CONTRACT_VERSION
        || boundedBundle.activation_state !== "contract_only"
        || boundedBundle.live_policy_sync_allowed !== false
        || boundedBundle.live_enforce_allowed !== false) {
        fail(
            "POLICY_LIVE_AUTHORITY_FORBIDDEN",
            "Phase 4B accepts only a contract-only, non-live policy bundle.",
        );
    }
    assertString(
        boundedBundle.bundle_id,
        BUNDLE_ID_PATTERN,
        "policy bundle_id",
        41,
    );
    if (!Number.isSafeInteger(boundedBundle.sequence)
        || boundedBundle.sequence < 1) {
        fail("POLICY_SEQUENCE_INVALID", "Policy sequence is invalid.");
    }
    assertExactKeys(
        boundedBundle.canonical_source,
        ["origin", "path", "transport", "redirects_allowed"],
        [],
        "policy canonical_source",
    );
    if (boundedBundle.canonical_source.origin !== CANONICAL_ORIGIN
        || boundedBundle.canonical_source.path !== CANONICAL_PATH
        || boundedBundle.canonical_source.transport !== "contract_fixture"
        || boundedBundle.canonical_source.redirects_allowed !== false) {
        fail(
            "POLICY_SOURCE_INVALID",
            "Canonical policy source is not exact.",
        );
    }
    const issuedAt = parseTime(
        boundedBundle.issued_at,
        "policy issued_at",
    );
    const notBefore = parseTime(
        boundedBundle.not_before,
        "policy not_before",
    );
    const expiresAt = parseTime(
        boundedBundle.expires_at,
        "policy expires_at",
    );
    if (notBefore < issuedAt
        || expiresAt <= notBefore
        || expiresAt - notBefore > MAX_POLICY_WINDOW_MS
        || now < notBefore
        || now >= expiresAt) {
        fail(
            "POLICY_BUNDLE_EXPIRED",
            "Policy bundle is outside its bounded validity window.",
        );
    }
    if (boundedBundle.sequence === 1) {
        if (boundedBundle.previous_bundle_fingerprint_sha256 !== null) {
            fail(
                "POLICY_CHAIN_INVALID",
                "Genesis policy bundle cannot name a predecessor.",
            );
        }
    }
    else {
        assertString(
            boundedBundle.previous_bundle_fingerprint_sha256,
            SHA256_PATTERN,
            "previous_bundle_fingerprint_sha256",
            71,
        );
    }
    const registry = validateCanonicalConnectorRegistryV1(
        boundedBundle.registry,
    );
    assertString(
        boundedBundle.registry_fingerprint_sha256,
        SHA256_PATTERN,
        "registry_fingerprint_sha256",
        71,
    );
    if (sha256Fingerprint(registry)
            !== boundedBundle.registry_fingerprint_sha256) {
        fail(
            "POLICY_REGISTRY_FINGERPRINT_DRIFT",
            "Policy registry fingerprint has drifted.",
        );
    }
    validateRuntimeToolBindings(
        boundedBundle.runtime_tool_bindings,
        registry,
    );
    validateBundleSafety(boundedBundle.safety);
    assertString(
        boundedBundle.bundle_fingerprint_sha256,
        SHA256_PATTERN,
        "bundle_fingerprint_sha256",
        71,
    );
    if (canonicalPolicyBundleFingerprint(boundedBundle)
            !== boundedBundle.bundle_fingerprint_sha256) {
        fail(
            "POLICY_BUNDLE_FINGERPRINT_DRIFT",
            "Policy bundle fingerprint has drifted.",
        );
    }
    assertExactKeys(
        boundedBundle.attestation,
        [
            "key_id",
            "algorithm",
            "key_thumbprint_sha256",
            "signed_at",
            "signature_base64url",
        ],
        [],
        "policy attestation",
    );
    if (boundedBundle.attestation.algorithm !== "Ed25519"
        || boundedBundle.attestation.key_id !== trustAnchor.key_id
        || boundedBundle.attestation.key_thumbprint_sha256
            !== trustAnchor.key_thumbprint_sha256) {
        fail(
            "POLICY_ATTESTATION_TRUST_MISMATCH",
            "Policy attestation does not match the external trust anchor.",
        );
    }
    const signedAt = parseTime(
        boundedBundle.attestation.signed_at,
        "policy attestation signed_at",
    );
    if (signedAt < issuedAt || signedAt >= expiresAt
        || signedAt < parseTime(
            trustAnchor.valid_from,
            "policy trust anchor valid_from",
        )
        || signedAt >= parseTime(
            trustAnchor.valid_until,
            "policy trust anchor valid_until",
        )) {
        fail(
            "POLICY_ATTESTATION_TIME_INVALID",
            "Policy attestation time is invalid.",
        );
    }
    assertString(
        boundedBundle.attestation.signature_base64url,
        BASE64URL_ED25519_SIGNATURE_PATTERN,
        "policy attestation signature_base64url",
        86,
    );
    const signature = Buffer.from(
        boundedBundle.attestation.signature_base64url,
        "base64url",
    );
    if (signature.length !== 64
        || signature.toString("base64url")
            !== boundedBundle.attestation.signature_base64url) {
        fail(
            "POLICY_SIGNATURE_INVALID",
            "Policy signature encoding is invalid.",
        );
    }
    let publicKey;
    try {
        publicKey = createPublicKey({
            key: trustAnchor.public_key_jwk,
            format: "jwk",
        });
    }
    catch {
        fail(
            "POLICY_KEY_INVALID",
            "Policy trust anchor public key is invalid.",
        );
    }
    const verified = verify(
        null,
        Buffer.from(
            canonicalPolicyBundleSignaturePayload(boundedBundle),
            "utf8",
        ),
        publicKey,
        signature,
    );
    if (!verified) {
        fail(
            "POLICY_SIGNATURE_INVALID",
            "Policy bundle signature is invalid.",
        );
    }
    assertNoSensitiveFields(boundedBundle);
    return deepFreeze(boundedBundle);
}

function checkpointProjection(checkpoint) {
    return {
        contract_version: checkpoint.contract_version,
        canonical_origin: checkpoint.canonical_origin,
        sequence: checkpoint.sequence,
        bundle_id: checkpoint.bundle_id,
        bundle_fingerprint_sha256:
            checkpoint.bundle_fingerprint_sha256,
        registry_version: checkpoint.registry_version,
        policy_version: checkpoint.policy_version,
        registry_fingerprint_sha256:
            checkpoint.registry_fingerprint_sha256,
        accepted_at: checkpoint.accepted_at,
    };
}

export function canonicalPolicyCheckpointFingerprint(checkpoint) {
    return sha256Fingerprint(checkpointProjection(checkpoint));
}

export function createCanonicalPolicySyncCheckpointV1(
    bundle,
    acceptedAt,
) {
    const accepted = new Date(normalizeNow(acceptedAt)).toISOString();
    const checkpoint = {
        contract_version:
            CANONICAL_POLICY_SYNC_CHECKPOINT_CONTRACT_VERSION,
        canonical_origin: CANONICAL_ORIGIN,
        sequence: bundle.sequence,
        bundle_id: bundle.bundle_id,
        bundle_fingerprint_sha256:
            bundle.bundle_fingerprint_sha256,
        registry_version: bundle.registry.registry_version,
        policy_version: bundle.registry.policy_version,
        registry_fingerprint_sha256:
            bundle.registry_fingerprint_sha256,
        accepted_at: accepted,
    };
    checkpoint.checkpoint_fingerprint_sha256 =
        canonicalPolicyCheckpointFingerprint(checkpoint);
    return deepFreeze(checkpoint);
}

export function validateCanonicalPolicySyncCheckpointV1(checkpoint) {
    assertExactKeys(
        checkpoint,
        [
            "contract_version",
            "canonical_origin",
            "sequence",
            "bundle_id",
            "bundle_fingerprint_sha256",
            "registry_version",
            "policy_version",
            "registry_fingerprint_sha256",
            "accepted_at",
            "checkpoint_fingerprint_sha256",
        ],
        [],
        "policy checkpoint",
    );
    if (checkpoint.contract_version
            !== CANONICAL_POLICY_SYNC_CHECKPOINT_CONTRACT_VERSION
        || checkpoint.canonical_origin !== CANONICAL_ORIGIN
        || !Number.isSafeInteger(checkpoint.sequence)
        || checkpoint.sequence < 1) {
        fail(
            "POLICY_CHECKPOINT_INVALID",
            "Policy checkpoint metadata is invalid.",
        );
    }
    assertString(
        checkpoint.bundle_id,
        BUNDLE_ID_PATTERN,
        "policy checkpoint bundle_id",
        41,
    );
    for (const key of [
        "bundle_fingerprint_sha256",
        "registry_fingerprint_sha256",
        "checkpoint_fingerprint_sha256",
    ]) {
        assertString(
            checkpoint[key],
            SHA256_PATTERN,
            `policy checkpoint ${key}`,
            71,
        );
    }
    assertString(
        checkpoint.registry_version,
        REGISTRY_VERSION_PATTERN,
        "policy checkpoint registry_version",
        68,
    );
    assertString(
        checkpoint.policy_version,
        POLICY_VERSION_PATTERN,
        "policy checkpoint policy_version",
        67,
    );
    parseTime(checkpoint.accepted_at, "policy checkpoint accepted_at");
    if (canonicalPolicyCheckpointFingerprint(checkpoint)
            !== checkpoint.checkpoint_fingerprint_sha256) {
        fail(
            "POLICY_CHECKPOINT_DRIFT",
            "Policy checkpoint fingerprint has drifted.",
        );
    }
    assertNoSensitiveFields(checkpoint);
    return deepFreeze(cloneJson(checkpoint, "policy checkpoint"));
}

export function createInMemoryCanonicalPolicyCheckpointStore(
    initialCheckpoint = null,
) {
    let current = initialCheckpoint === null
        ? null
        : validateCanonicalPolicySyncCheckpointV1(initialCheckpoint);
    return Object.freeze({
        async load() {
            return current === null ? null : structuredClone(current);
        },
        async compareAndSet(expectedFingerprint, nextCheckpoint) {
            const currentFingerprint =
                current?.checkpoint_fingerprint_sha256 ?? null;
            if (currentFingerprint !== expectedFingerprint) {
                return false;
            }
            current = validateCanonicalPolicySyncCheckpointV1(
                nextCheckpoint,
            );
            return true;
        },
    });
}

function policyInventoryBindingProjection(binding) {
    return {
        contract_version: binding.contract_version,
        activation_state: binding.activation_state,
        live_enforce_allowed: binding.live_enforce_allowed,
        policy_bundle_binding: binding.policy_bundle_binding,
        inventory_binding: binding.inventory_binding,
        profiles: binding.profiles,
        metrics: binding.metrics,
        phase4c_contract_prerequisite_ready:
            binding.phase4c_contract_prerequisite_ready,
        phase4c_external_write_authority_granted:
            binding.phase4c_external_write_authority_granted,
        authority_status: binding.authority_status,
        safety: binding.safety,
    };
}

function samePolicyBinding(tool, profile, registry) {
    const binding = tool?.policy_binding;
    if (!isRecord(binding)) {
        return false;
    }
    return binding.registry_version === registry.registry_version
        && binding.policy_version === registry.policy_version
        && binding.profile_id === profile.profile_id
        && binding.scope === profile.scope
        && binding.profile_status === profile.status
        && binding.provider === profile.provider
        && binding.connector_id === profile.connector_id
        && binding.connector_version === profile.connector_version
        && binding.action === profile.action
        && binding.resource_type === profile.resource_type
        && binding.approval_policy === profile.approval_policy;
}

function buildPolicyInventoryBinding(bundle, inventory) {
    const snapshot = validateRuntimeToolInventoryV1(inventory);
    const registry = bundle.registry;
    const inventoryTools = new Map(
        snapshot.tools.map((tool) => [tool.tool_name, tool]),
    );
    const ownerBindings = new Map(
        bundle.runtime_tool_bindings.map((binding) => [
            binding.profile_id,
            binding,
        ]),
    );
    const profiles = registry.profiles.map((profile) => {
        const tool = inventoryTools.get(profile.tool_name);
        const ownerBinding = ownerBindings.get(profile.profile_id);
        const discovered = Boolean(tool);
        const ownerExact = tool?.owner?.resolution === "exact"
            && tool?.owner?.kind === ownerBinding?.owner?.kind
            && tool?.owner?.owner_id === ownerBinding?.owner?.owner_id
            && ownerBinding?.owner?.resolution === "exact";
        const schemaMatches = tool
            ?.actual_input_schema_fingerprint_sha256
            === profile.tool_schema_fingerprint
            && tool?.expected_input_schema_fingerprint_sha256
                === profile.tool_schema_fingerprint;
        const policyMatches = samePolicyBinding(
            tool,
            profile,
            registry,
        );
        const coverageStatus =
            tool?.coverage_status ?? "not_discovered";
        const prerequisiteReady = discovered
            && ownerExact
            && schemaMatches
            && policyMatches
            && coverageStatus === "covered_contract_only"
            && tool.enforce_eligible === false
            && tool.authority_status
                === "inventory_only_no_authority";
        return deepFreeze({
            profile_id: profile.profile_id,
            scope: profile.scope,
            tool_name: profile.tool_name,
            discovered,
            owner_exact: ownerExact,
            schema_matches: schemaMatches,
            policy_matches: policyMatches,
            coverage_status: coverageStatus,
            phase4c_contract_prerequisite_ready: prerequisiteReady,
        });
    });
    const readyCount = profiles.filter((profile) =>
        profile.phase4c_contract_prerequisite_ready).length;
    const versionMatches =
        snapshot.registry_binding.registry_version
            === registry.registry_version
        && snapshot.registry_binding.policy_version
            === registry.policy_version
        && snapshot.registry_binding.activation_state
            === registry.activation_state
        && snapshot.registry_binding.live_enforce_allowed === false;
    const ready = versionMatches
        && readyCount === profiles.length
        && snapshot.metrics.drifted_tool_count === 0
        && snapshot.metrics.side_effecting_unclassified_tool_count === 0
        && snapshot.live_enforce_allowed === false;
    const binding = {
        contract_version:
            CANONICAL_POLICY_INVENTORY_BINDING_CONTRACT_VERSION,
        activation_state: "policy_synced_contract_only",
        live_enforce_allowed: false,
        policy_bundle_binding: deepFreeze({
            bundle_id: bundle.bundle_id,
            sequence: bundle.sequence,
            bundle_fingerprint_sha256:
                bundle.bundle_fingerprint_sha256,
            registry_version: registry.registry_version,
            policy_version: registry.policy_version,
            registry_fingerprint_sha256:
                bundle.registry_fingerprint_sha256,
        }),
        inventory_binding: deepFreeze({
            snapshot_fingerprint_sha256:
                snapshot.snapshot_fingerprint_sha256,
            registry_version:
                snapshot.registry_binding.registry_version,
            policy_version:
                snapshot.registry_binding.policy_version,
            version_matches: versionMatches,
        }),
        profiles: deepFreeze(profiles),
        metrics: deepFreeze({
            required_profile_count: profiles.length,
            ready_profile_count: readyCount,
            blocked_profile_count: profiles.length - readyCount,
            drifted_tool_count: snapshot.metrics.drifted_tool_count,
            side_effecting_unclassified_tool_count:
                snapshot.metrics.side_effecting_unclassified_tool_count,
        }),
        phase4c_contract_prerequisite_ready: ready,
        phase4c_external_write_authority_granted: false,
        authority_status: "verified_policy_no_execution_authority",
        safety: deepFreeze({
            grants_tool_authority: false,
            invokes_connectors: false,
            performs_network_request: false,
            performs_external_write: false,
            automates_owner_decision: false,
            exposes_provider_credentials: false,
        }),
    };
    binding.binding_fingerprint_sha256 = sha256Fingerprint(
        policyInventoryBindingProjection(binding),
    );
    return deepFreeze(binding);
}

function safeSyncError(error) {
    if (error instanceof CanonicalConnectorPolicySyncError) {
        return Object.freeze({
            code: error.code,
            message: error.message,
            failed_closed: true,
        });
    }
    return Object.freeze({
        code: "POLICY_SYNC_UNAVAILABLE",
        message: "Canonical connector policy sync stopped safely.",
        failed_closed: true,
    });
}

export class CanonicalConnectorPolicySyncController {
    constructor(options = {}) {
        this.source = options.source;
        this.checkpointStore = options.checkpointStore
            ?? createInMemoryCanonicalPolicyCheckpointStore();
        this.trustAnchor = options.trustAnchor;
        this.allowFixture = options.allowFixture === true;
        this.minimumSequence =
            Number.isSafeInteger(options.minimumSequence)
            && options.minimumSequence > 0
                ? options.minimumSequence
                : 1;
        this.now = typeof options.now === "function"
            ? options.now
            : () => new Date();
        this.currentBundle = null;
        this.currentCheckpoint = null;
        this.latestBinding = null;
        this.lastError = null;
        this.syncPromise = null;
        this.syncGeneration = 0;
        this.epoch = 0;
    }

    async sync(input = {}) {
        if (this.syncPromise) {
            return this.syncPromise;
        }
        const operation = this.syncInternal(input, this.epoch);
        this.syncPromise = operation.finally(() => {
            this.syncPromise = null;
        });
        return this.syncPromise;
    }

    async syncInternal(input, epoch) {
        const reason = SYNC_REASONS.has(input.reason)
            ? input.reason
            : "owner_inspection";
        try {
            if (!this.source || typeof this.source.read !== "function") {
                fail(
                    "POLICY_SOURCE_UNAVAILABLE",
                    "Canonical policy source is unavailable.",
                );
            }
            if (!this.checkpointStore
                || typeof this.checkpointStore.load !== "function"
                || typeof this.checkpointStore.compareAndSet !== "function") {
                fail(
                    "POLICY_CHECKPOINT_STORE_UNAVAILABLE",
                    "Policy checkpoint store is unavailable.",
                );
            }
            const previousRaw = await this.checkpointStore.load();
            const previous = previousRaw === null
                ? null
                : validateCanonicalPolicySyncCheckpointV1(previousRaw);
            const bundleRaw = await this.source.read({
                origin: CANONICAL_ORIGIN,
                path: CANONICAL_PATH,
                accept:
                    "application/vnd.noderooms.connector-policy+json",
                maximum_bytes: MAX_BUNDLE_BYTES,
                redirects_allowed: false,
                timeout_ms: 4_000,
                read_only: true,
            });
            if (epoch !== this.epoch) {
                return null;
            }
            const evaluatedAt = normalizeNow(this.now());
            const bundle = validateCanonicalConnectorPolicyBundleV1(
                bundleRaw,
                {
                    trustAnchor: this.trustAnchor,
                    allowFixture: this.allowFixture,
                    now: evaluatedAt,
                },
            );
            let idempotent = false;
            if (previous === null) {
                if (bundle.sequence !== this.minimumSequence
                    || bundle.previous_bundle_fingerprint_sha256 !== null) {
                    fail(
                        "POLICY_UNTRUSTED_GENESIS",
                        "First accepted policy bundle does not match the pinned sequence floor.",
                    );
                }
            }
            else if (bundle.sequence < previous.sequence) {
                fail(
                    "POLICY_ROLLBACK_DETECTED",
                    "Canonical policy sequence moved backwards.",
                );
            }
            else if (bundle.sequence === previous.sequence) {
                if (bundle.bundle_fingerprint_sha256
                        !== previous.bundle_fingerprint_sha256
                    || bundle.bundle_id !== previous.bundle_id) {
                    fail(
                        "POLICY_EQUIVOCATION_DETECTED",
                        "Canonical policy sequence has conflicting content.",
                    );
                }
                if (bundle.registry.registry_version
                        !== previous.registry_version
                    || bundle.registry.policy_version
                        !== previous.policy_version
                    || bundle.registry_fingerprint_sha256
                        !== previous.registry_fingerprint_sha256) {
                    fail(
                        "POLICY_CHECKPOINT_BINDING_MISMATCH",
                        "Policy checkpoint metadata does not match the signed bundle.",
                    );
                }
                idempotent = true;
            }
            else {
                if (bundle.sequence !== previous.sequence + 1) {
                    fail(
                        "POLICY_SEQUENCE_GAP",
                        "Canonical policy sequence contains an unverified gap.",
                    );
                }
                if (bundle.previous_bundle_fingerprint_sha256
                        !== previous.bundle_fingerprint_sha256) {
                    fail(
                        "POLICY_CHAIN_INVALID",
                        "Canonical policy predecessor binding is invalid.",
                    );
                }
            }
            const checkpoint = createCanonicalPolicySyncCheckpointV1(
                bundle,
                evaluatedAt,
            );
            if (!idempotent) {
                const stored = await this.checkpointStore.compareAndSet(
                    previous?.checkpoint_fingerprint_sha256 ?? null,
                    checkpoint,
                );
                if (stored !== true) {
                    fail(
                        "POLICY_CHECKPOINT_CONFLICT",
                        "Policy checkpoint changed during sync.",
                    );
                }
            }
            if (epoch !== this.epoch) {
                return null;
            }
            this.currentBundle = bundle;
            this.currentCheckpoint = idempotent
                ? previous
                : checkpoint;
            this.latestBinding = null;
            this.lastError = null;
            this.syncGeneration += 1;
            return Object.freeze({
                contract_version:
                    "noderooms-canonical-policy-sync-result-v1",
                sync_reason: reason,
                sync_generation: this.syncGeneration,
                idempotent,
                bundle_id: bundle.bundle_id,
                sequence: bundle.sequence,
                bundle_fingerprint_sha256:
                    bundle.bundle_fingerprint_sha256,
                registry_version: bundle.registry.registry_version,
                policy_version: bundle.registry.policy_version,
                checkpoint_fingerprint_sha256:
                    this.currentCheckpoint
                        .checkpoint_fingerprint_sha256,
                activation_state: "policy_synced_contract_only",
                live_policy_sync_allowed: false,
                live_enforce_allowed: false,
                tool_authority_granted: false,
            });
        }
        catch (error) {
            if (epoch !== this.epoch) {
                return null;
            }
            this.currentBundle = null;
            this.latestBinding = null;
            this.lastError = safeSyncError(error);
            return null;
        }
    }

    bindInventory(inventory) {
        if (this.currentBundle === null || this.lastError !== null) {
            fail(
                "POLICY_NOT_SYNCED",
                "A healthy verified canonical policy is required.",
            );
        }
        this.latestBinding = buildPolicyInventoryBinding(
            this.currentBundle,
            inventory,
        );
        return this.latestBinding;
    }

    verifiedRegistry() {
        if (this.currentBundle === null || this.lastError !== null) {
            return null;
        }
        return deepFreeze(structuredClone(this.currentBundle.registry));
    }

    status() {
        const bundle = this.currentBundle;
        return Object.freeze({
            contract_version:
                "noderooms-canonical-policy-sync-status-v1",
            activation_state: bundle === null
                ? "not_synced"
                : "policy_synced_contract_only",
            live_policy_sync_allowed:
                CANONICAL_POLICY_SYNC_LIVE_FETCH_ALLOWED,
            live_enforce_allowed: false,
            sync_generation: this.syncGeneration,
            current_policy: bundle === null
                ? null
                : Object.freeze({
                    bundle_id: bundle.bundle_id,
                    sequence: bundle.sequence,
                    bundle_fingerprint_sha256:
                        bundle.bundle_fingerprint_sha256,
                    registry_version:
                        bundle.registry.registry_version,
                    policy_version:
                        bundle.registry.policy_version,
                    registry_fingerprint_sha256:
                        bundle.registry_fingerprint_sha256,
                    expires_at: bundle.expires_at,
                }),
            checkpoint: this.currentCheckpoint,
            latest_inventory_binding: this.latestBinding,
            phase4c_contract_prerequisite_ready:
                this.latestBinding
                    ?.phase4c_contract_prerequisite_ready === true,
            phase4c_external_write_authority_granted: false,
            last_error: this.lastError,
            safety: Object.freeze({
                grants_tool_authority:
                    CANONICAL_POLICY_SYNC_GRANTS_TOOL_AUTHORITY,
                invokes_connectors: false,
                performs_network_request: false,
                performs_external_write: false,
                automates_owner_decision: false,
                persists_raw_schema: false,
                persists_raw_parameters: false,
                persists_raw_results: false,
                persists_provider_credentials: false,
            }),
        });
    }

    clearRuntimeCache() {
        this.epoch += 1;
        this.currentBundle = null;
        this.currentCheckpoint = null;
        this.latestBinding = null;
        this.lastError = null;
        this.syncPromise = null;
        this.syncGeneration = 0;
    }
}
