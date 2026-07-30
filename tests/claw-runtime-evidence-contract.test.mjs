import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Value } from "typebox/value";

import { sha256Fingerprint } from "../src/passport-runtime-binding.js";

const readText = async (relativePath) => readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
);

const readJson = async (relativePath) => JSON.parse(await readText(relativePath));

const schemaText = await readText("contracts/claw-runtime-evidence-v0.1.schema.json");
const schema = JSON.parse(schemaText);
const validFixture = await readJson(
    "contracts/fixtures/claw-runtime-evidence.readonly-pass-v0.1.json",
);
const revokedFixture = await readJson(
    "contracts/fixtures/claw-runtime-evidence.revoked-v0.1.json",
);
const unknownOutcomeFixture = await readJson(
    "contracts/fixtures/claw-runtime-evidence.unknown-outcome-v0.1.json",
);
const packageJson = await readJson("package.json");
const manifest = await readJson("openclaw.plugin.json");
const pluginIndex = await readText("src/index.js");
const strategicSupplement = await readText(
    "docs/strategy/NODEROOMS_TRUSTBRIDGE_ALPHA2_COMPETITIVE_POSITION_20260730_HU.md",
);

const CONTRACT_VERSION = "claw-runtime-evidence.v0.1";
const SCHEMA_ID =
    "https://noderooms.com/contracts/claw-runtime-evidence-v0.1.schema.json";
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const EVIDENCE_ID_PATTERN = /^nrevd_[a-f0-9]{32}$/;
const CHECK_ID_PATTERN = /^[a-z][a-z0-9._:-]{2,127}$/;
const CHECK_VERSION_PATTERN = /^v[0-9]+\.[0-9]+(?:\.[0-9]+)?$/;
const ALLOWED_OUTCOMES = new Set(["pass", "fail", "inconclusive", "not_run"]);
const READ_ONLY_PROFILES = new Set([
    "artifact_runtime_assessment",
    "owner_bound_read_only_observation",
]);
const OWNER_BOUND_PROFILES = new Set([
    "owner_bound_read_only_observation",
    "owner_approved_external_action_outcome",
]);
const MAX_DOCUMENT_BYTES = schema["x-noderooms-contract"].max_document_bytes;
const MAX_NESTING_DEPTH = schema["x-noderooms-contract"].max_nesting_depth;
const SCHEMA_FINGERPRINT = `sha256:${createHash("sha256")
    .update(schemaText, "utf8")
    .digest("hex")}`;
const PRIVATE_KEY_PATTERN =
    /^(?:d|private[_-]?(?:key|jwk)|signing[_-]?private[_-]?key)$/i;
const SENSITIVE_FIELD_PATTERN =
    /(?:api[_-]?key|oauth[_-]?token|access[_-]?token|refresh[_-]?token|authorization|cookie|credential|run[_-]?secret|invite[_-]?token|raw[_-]?(?:prompt|conversation|message|email|tool|request|response|result|body)|owner[_-]?sender|session[_-]?key|local[_-]?(?:username|path)|home[_-]?path|environment[_-]?value|workboard[_-]?claim[_-]?token|public[_-]?key[_-]?jwk)/i;
const LOCAL_PATH_PATTERN =
    /^(?:[A-Za-z]:[\\/]|\/(?:home|root|Users|workspace)(?:\/|$))/;

class EvidenceContractError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "EvidenceContractError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new EvidenceContractError(code, message);
}

function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

function clone(value) {
    return structuredClone(value);
}

function assertShape(value, definition, label) {
    if (!isRecord(value)) {
        fail("EVIDENCE_TYPE_INVALID", `${label} must be an object.`);
    }
    const allowed = new Set(Object.keys(definition.properties ?? {}));
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail("EVIDENCE_UNKNOWN_FIELD", `${label}.${key} is not declared.`);
        }
    }
    for (const key of definition.required ?? []) {
        if (!Object.hasOwn(value, key)) {
            fail(
                "EVIDENCE_REQUIRED_FIELD_MISSING",
                `${label}.${key} is required.`,
            );
        }
    }
}

function assertSafeUrl(value, path) {
    let parsed;
    try {
        parsed = new URL(value);
    }
    catch {
        fail("EVIDENCE_URL_UNSAFE", `${path} is not a valid URL.`);
    }
    if (parsed.protocol !== "https:"
        || parsed.username
        || parsed.password
        || parsed.search
        || parsed.hash) {
        fail(
            "EVIDENCE_URL_UNSAFE",
            `${path} must be HTTPS and contain no userinfo, query, or fragment.`,
        );
    }
}

function assertPublicSafe(value, path = "$", depth = 0) {
    if (depth > MAX_NESTING_DEPTH) {
        fail("EVIDENCE_NESTING_TOO_DEEP", `${path} exceeds the nesting limit.`);
    }
    if (Array.isArray(value)) {
        value.forEach((entry, index) => {
            assertPublicSafe(entry, `${path}[${index}]`, depth + 1);
        });
        return;
    }
    if (!isRecord(value)) {
        if (typeof value === "string" && LOCAL_PATH_PATTERN.test(value)) {
            fail("EVIDENCE_SENSITIVE_FIELD", `${path} exposes a local path.`);
        }
        return;
    }
    for (const [key, entry] of Object.entries(value)) {
        const safePolicyBoolean = typeof entry === "boolean"
            && /(?:allowed|included|persisted|attempted|claimed|required|supported|forwarded|generated|automated|granted|used)$/i
                .test(key);
        if (PRIVATE_KEY_PATTERN.test(key)) {
            fail(
                "EVIDENCE_PRIVATE_KEY_EMBEDDED",
                `${path}.${key} embeds private key material.`,
            );
        }
        if (!safePolicyBoolean && SENSITIVE_FIELD_PATTERN.test(key)) {
            fail(
                "EVIDENCE_SENSITIVE_FIELD",
                `${path}.${key} is not public-safe.`,
            );
        }
        if (typeof entry === "string"
            && (key.endsWith("_uri")
                || key === "$schema"
                || key === "schema_id"
                || /^https?:\/\//.test(entry))) {
            assertSafeUrl(entry, `${path}.${key}`);
        }
        assertPublicSafe(entry, `${path}.${key}`, depth + 1);
    }
}

function assertAllHashes(value, path = "$") {
    if (Array.isArray(value)) {
        value.forEach((entry, index) => assertAllHashes(entry, `${path}[${index}]`));
        return;
    }
    if (!isRecord(value)) {
        return;
    }
    for (const [key, entry] of Object.entries(value)) {
        if ((key === "sha256" || key.endsWith("_sha256"))
            && !SHA256_PATTERN.test(entry)) {
            fail("EVIDENCE_HASH_INVALID", `${path}.${key} is not lowercase SHA-256.`);
        }
        assertAllHashes(entry, `${path}.${key}`);
    }
}

function parseTimestamp(value, path) {
    if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
        fail("EVIDENCE_TIMESTAMP_INVALID", `${path} is not a valid timestamp.`);
    }
    return Date.parse(value);
}

function evidenceProjection(value) {
    const {
        $schema: _schemaReference,
        evidence_fingerprint_sha256: _fingerprint,
        attestation: _attestation,
        ...projection
    } = value;
    return projection;
}

function evidenceFingerprint(value) {
    return sha256Fingerprint(evidenceProjection(value));
}

function refingerprint(value) {
    value.evidence_fingerprint_sha256 = evidenceFingerprint(value);
    return value;
}

function mutated(mutator, options = {}) {
    const value = clone(validFixture);
    mutator(value);
    return options.refingerprint === false ? value : refingerprint(value);
}

function validateEvidence(value) {
    const documentBytes = Buffer.byteLength(JSON.stringify(value), "utf8");
    if (documentBytes > MAX_DOCUMENT_BYTES) {
        fail(
            "EVIDENCE_DOCUMENT_TOO_LARGE",
            `Evidence document exceeds ${MAX_DOCUMENT_BYTES} bytes.`,
        );
    }

    assertPublicSafe(value);
    assertShape(value, schema, "evidence");

    if (value.$schema !== SCHEMA_ID) {
        fail("EVIDENCE_CONTRACT_VERSION_INVALID", "Schema reference is invalid.");
    }
    if (value.contract_version !== CONTRACT_VERSION) {
        fail("EVIDENCE_CONTRACT_VERSION_INVALID", "Contract version is invalid.");
    }
    if (typeof value.fixture !== "boolean") {
        fail("EVIDENCE_TYPE_INVALID", "fixture must be boolean.");
    }
    if (!EVIDENCE_ID_PATTERN.test(value.evidence_id)) {
        fail("EVIDENCE_ID_INVALID", "Evidence id is invalid.");
    }
    if (!schema.properties.evidence_profile.enum.includes(value.evidence_profile)) {
        fail("EVIDENCE_PROFILE_INVALID", "Evidence profile is invalid.");
    }
    if (value.authority_status !== "evidence_only_no_authority"
        || value.live_enforce_allowed !== false) {
        fail("EVIDENCE_CLAIM_INVALID", "Evidence cannot grant live authority.");
    }
    if (JSON.stringify(value).includes("*")) {
        fail("EVIDENCE_WILDCARD_REJECTED", "Wildcards are prohibited.");
    }

    assertAllHashes(value);

    assertShape(value.schema_binding, schema.$defs.schemaBinding, "schema_binding");
    if (value.schema_binding.schema_id !== SCHEMA_ID
        || value.schema_binding.fingerprint_profile !== "raw-utf8-lf-sha256-v1"
        || value.schema_binding.semantic_validation_profile
            !== "noderooms-claw-runtime-evidence-semantic-v0.1") {
        fail("EVIDENCE_CONTRACT_VERSION_INVALID", "Schema binding is invalid.");
    }
    if (value.schema_binding.schema_fingerprint_sha256 !== SCHEMA_FINGERPRINT) {
        fail(
            "EVIDENCE_SCHEMA_FINGERPRINT_MISMATCH",
            "Schema fingerprint does not match the exact schema bytes.",
        );
    }

    assertShape(
        value.artifact_binding,
        schema.$defs.artifactBinding,
        "artifact_binding",
    );
    if (!value.artifact_binding.archive && !value.artifact_binding.directory) {
        fail(
            "EVIDENCE_REQUIRED_FIELD_MISSING",
            "Artifact binding requires archive or directory evidence.",
        );
    }
    if (value.artifact_binding.archive) {
        assertShape(
            value.artifact_binding.archive,
            schema.$defs.archiveBinding,
            "artifact_binding.archive",
        );
        if (!Number.isSafeInteger(value.artifact_binding.archive.size_bytes)
            || value.artifact_binding.archive.size_bytes < 0) {
            fail("EVIDENCE_TYPE_INVALID", "Archive size must be bounded.");
        }
    }
    if (value.artifact_binding.directory) {
        assertShape(
            value.artifact_binding.directory,
            schema.$defs.directoryBinding,
            "artifact_binding.directory",
        );
        if (!Number.isSafeInteger(value.artifact_binding.directory.file_count)
            || value.artifact_binding.directory.file_count < 0) {
            fail("EVIDENCE_TYPE_INVALID", "Directory file count must be bounded.");
        }
    }

    assertShape(value.runtime_binding, schema.$defs.runtimeBinding, "runtime_binding");
    if (value.runtime_binding.plugin_package_name
        !== value.artifact_binding.package_name
        || value.runtime_binding.plugin_package_version
            !== value.artifact_binding.package_version) {
        fail(
            "EVIDENCE_ARTIFACT_RUNTIME_MISMATCH",
            "Runtime package identity differs from the artifact identity.",
        );
    }

    if (OWNER_BOUND_PROFILES.has(value.evidence_profile)
        && !value.authority_binding) {
        fail(
            "EVIDENCE_AUTHORITY_BINDING_REQUIRED",
            "Owner-bound profiles require authority fingerprints.",
        );
    }
    if (value.authority_binding) {
        assertShape(
            value.authority_binding,
            schema.$defs.authorityBinding,
            "authority_binding",
        );
        if (value.authority_binding.owner_decision_automated !== false
            || value.authority_binding.shared_run_secret_allowed !== false
            || value.authority_binding.shared_lease_allowed !== false) {
            fail("EVIDENCE_CLAIM_INVALID", "Authority safety flags are invalid.");
        }
    }
    if (value.evidence_profile === "owner_approved_external_action_outcome") {
        const required = [
            "capability_request_fingerprint_sha256",
            "owner_decision_fingerprint_sha256",
            "run_lease_fingerprint_sha256",
            "external_action_intent_fingerprint_sha256",
            "external_action_receipt_fingerprint_sha256",
        ];
        for (const key of required) {
            if (!Object.hasOwn(value.authority_binding, key)) {
                fail(
                    "EVIDENCE_AUTHORITY_BINDING_REQUIRED",
                    `authority_binding.${key} is required.`,
                );
            }
        }
        if (value.authority_binding.live_lease_used !== true
            || value.authority_binding.lease_state_at_observation !== "active") {
            fail(
                "EVIDENCE_AUTHORITY_BINDING_REQUIRED",
                "External-action evidence requires one active exact lease.",
            );
        }
    }

    assertShape(value.claims, schema.$defs.claims, "claims");
    const expectedClaims = {
        evidence_available: true,
        absolute_safety_claimed: false,
        exactly_once_effect_claimed: false,
        execution_authority_granted: false,
        reputation_score_generated: false,
        owner_decision_automated: false,
    };
    for (const [key, expected] of Object.entries(expectedClaims)) {
        if (value.claims[key] !== expected) {
            fail("EVIDENCE_CLAIM_INVALID", `claims.${key} is invalid.`);
        }
    }

    assertShape(value.assessment, schema.$defs.assessment, "assessment");
    if (!Array.isArray(value.assessment.checks)
        || value.assessment.checks.length < 1
        || value.assessment.checks.length > 256) {
        fail("EVIDENCE_TYPE_INVALID", "assessment.checks is not bounded.");
    }
    const seenChecks = new Set();
    for (const [index, check] of value.assessment.checks.entries()) {
        const label = `assessment.checks[${index}]`;
        assertShape(check, schema.$defs.check, label);
        if (!CHECK_ID_PATTERN.test(check.check_id)
            || !CHECK_VERSION_PATTERN.test(check.check_version)) {
            fail("EVIDENCE_ID_INVALID", `${label} id or version is invalid.`);
        }
        const identity = `${check.check_id}@${check.check_version}`;
        if (seenChecks.has(identity)) {
            fail("EVIDENCE_DUPLICATE_CHECK", `${identity} is duplicated.`);
        }
        seenChecks.add(identity);
        if (!ALLOWED_OUTCOMES.has(check.outcome)) {
            fail(
                "EVIDENCE_CHECK_OUTCOME_INVALID",
                `${label}.outcome is invalid.`,
            );
        }
        if (check.outcome === "not_run") {
            if (check.completed !== false
                || Object.hasOwn(check, "observed_at")
                || Object.hasOwn(check, "evidence_fingerprint_sha256")) {
                fail(
                    "EVIDENCE_CHECK_STATE_INVALID",
                    `${label} not_run state is inconsistent.`,
                );
            }
        }
        else {
            if (check.completed !== true
                || !Object.hasOwn(check, "observed_at")
                || !Object.hasOwn(check, "evidence_fingerprint_sha256")) {
                fail(
                    "EVIDENCE_CHECK_STATE_INVALID",
                    `${label} completed state is inconsistent.`,
                );
            }
            parseTimestamp(check.observed_at, `${label}.observed_at`);
        }
    }

    const requiredChecks = value.assessment.checks.filter((check) => check.required);
    const passed = requiredChecks.filter((check) => check.outcome === "pass").length;
    const failed = requiredChecks.filter((check) => check.outcome === "fail").length;
    const inconclusive = requiredChecks.filter(
        (check) => check.outcome === "inconclusive",
    ).length;
    const notRun = requiredChecks.filter((check) => check.outcome === "not_run").length;
    const completed = requiredChecks.length - notRun;
    if (notRun > 0 && value.assessment.outcome === "pass") {
        fail(
            "EVIDENCE_REQUIRED_CHECK_NOT_RUN",
            "A required not_run check cannot aggregate to pass.",
        );
    }
    const expectedAggregate = {
        required_check_count: requiredChecks.length,
        completed_required_check_count: completed,
        passed_required_check_count: passed,
        failed_required_check_count: failed,
        inconclusive_required_check_count: inconclusive,
        not_run_required_check_count: notRun,
    };
    for (const [key, expected] of Object.entries(expectedAggregate)) {
        if (value.assessment[key] !== expected) {
            fail("EVIDENCE_AGGREGATE_MISMATCH", `${key} is inconsistent.`);
        }
    }
    const expectedOutcome = failed > 0
        ? "fail"
        : inconclusive > 0 || notRun > 0
            ? "inconclusive"
            : "pass";
    if (value.assessment.outcome !== expectedOutcome
        || value.assessment.completed !== (notRun === 0)) {
        fail("EVIDENCE_AGGREGATE_MISMATCH", "Assessment aggregate is invalid.");
    }

    assertShape(
        value.zero_side_effects,
        schema.$defs.sideEffectCounters,
        "zero_side_effects",
    );
    for (const [key, count] of Object.entries(value.zero_side_effects)) {
        if (!Number.isSafeInteger(count) || count < 0) {
            fail("EVIDENCE_TYPE_INVALID", `zero_side_effects.${key} is invalid.`);
        }
    }
    if (READ_ONLY_PROFILES.has(value.evidence_profile)
        && Object.values(value.zero_side_effects).some((count) => count !== 0)) {
        fail(
            "EVIDENCE_SIDE_EFFECT_GATE_FAILED",
            "Read-only evidence must report zero side effects.",
        );
    }
    if (value.evidence_profile === "owner_approved_external_action_outcome"
        && value.zero_side_effects.PROVIDER_WRITES > 1) {
        fail(
            "EVIDENCE_SIDE_EFFECT_GATE_FAILED",
            "External-action evidence cannot report more than one provider write.",
        );
    }

    assertShape(value.lifecycle, schema.$defs.lifecycle, "lifecycle");
    const issuedAt = parseTimestamp(value.lifecycle.issued_at, "lifecycle.issued_at");
    const expiresAt = parseTimestamp(value.lifecycle.expires_at, "lifecycle.expires_at");
    const statusCheckedAt = parseTimestamp(
        value.lifecycle.status_checked_at,
        "lifecycle.status_checked_at",
    );
    if (expiresAt <= issuedAt || statusCheckedAt < issuedAt) {
        fail("EVIDENCE_TIME_ORDER_INVALID", "Lifecycle time order is invalid.");
    }
    if (value.lifecycle.active
        !== (value.lifecycle.current_status === "active")) {
        fail(
            "EVIDENCE_LIFECYCLE_CONFLICT",
            "Only current_status=active may set active=true.",
        );
    }
    if (value.lifecycle.current_status === "active"
        && statusCheckedAt >= expiresAt) {
        fail(
            "EVIDENCE_LIFECYCLE_CONFLICT",
            "Expired evidence cannot remain active.",
        );
    }
    if (value.lifecycle.current_status === "revoked") {
        const revokedAt = parseTimestamp(
            value.lifecycle.revoked_at,
            "lifecycle.revoked_at",
        );
        if (revokedAt < issuedAt || revokedAt > statusCheckedAt) {
            fail(
                "EVIDENCE_TIME_ORDER_INVALID",
                "Revocation time order is invalid.",
            );
        }
    }
    if (value.lifecycle.current_status === "superseded"
        && value.lifecycle.superseded_by_evidence_id === value.evidence_id) {
        fail(
            "EVIDENCE_SUPERSEDE_CYCLE",
            "Evidence cannot supersede itself.",
        );
    }

    if (value.attestation?.attestation_status === "not_run") {
        assertShape(
            value.attestation,
            schema.$defs.unsignedAttestation,
            "attestation",
        );
        if (value.fixture !== true
            || value.attestation.external_trust_anchor_required !== true) {
            fail(
                "EVIDENCE_ATTESTATION_INVALID",
                "Unsigned evidence is allowed only for contract fixtures.",
            );
        }
    }
    else if (value.attestation?.attestation_status === "signed") {
        assertShape(
            value.attestation,
            schema.$defs.signedAttestation,
            "attestation",
        );
        assertShape(
            value.attestation.external_trust_anchor,
            schema.$defs.externalTrustAnchorReference,
            "attestation.external_trust_anchor",
        );
        if (value.attestation.algorithm !== "Ed25519"
            || value.attestation.external_trust_anchor_required !== true
            || value.attestation.signed_evidence_fingerprint_sha256
                !== value.evidence_fingerprint_sha256) {
            fail("EVIDENCE_ATTESTATION_INVALID", "Signed attestation is invalid.");
        }
        parseTimestamp(value.attestation.signed_at, "attestation.signed_at");
    }
    else {
        fail("EVIDENCE_ATTESTATION_INVALID", "Attestation state is invalid.");
    }
    if (value.fixture === false
        && value.attestation.attestation_status !== "signed") {
        fail(
            "EVIDENCE_ATTESTATION_INVALID",
            "Non-fixture evidence requires a signed attestation.",
        );
    }

    if (value.evidence_fingerprint_sha256 !== evidenceFingerprint(value)) {
        fail(
            "EVIDENCE_FINGERPRINT_MISMATCH",
            "Evidence fingerprint differs from the canonical projection.",
        );
    }

    return {
        valid: true,
        authority_granted: false,
        live_enforce_allowed: false,
        evidence_available: true,
    };
}

function expectCode(value, code) {
    assert.throws(
        () => validateEvidence(value),
        (error) => error instanceof EvidenceContractError && error.code === code,
    );
}

function minimalFixture() {
    return mutated((value) => {
        value.evidence_id = "nrevd_44444444444444444444444444444444";
        value.evidence_profile = "artifact_runtime_assessment";
        delete value.authority_binding;
        value.assessment.checks = value.assessment.checks.slice(0, 2);
        value.assessment.required_check_count = 2;
        value.assessment.completed_required_check_count = 2;
        value.assessment.passed_required_check_count = 2;
    });
}

test("005A schema freezes evidence-only authority and separate artifact bindings", () => {
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.$id, SCHEMA_ID);
    assert.equal(schema.additionalProperties, false);
    assert.equal(schema.properties.contract_version.const, CONTRACT_VERSION);
    assert.equal(schema.properties.authority_status.const, "evidence_only_no_authority");
    assert.equal(schema.properties.live_enforce_allowed.const, false);
    assert.equal(schema.$defs.claims.properties.absolute_safety_claimed.const, false);
    assert.equal(schema.$defs.claims.properties.exactly_once_effect_claimed.const, false);
    assert.equal(schema.$defs.claims.properties.execution_authority_granted.const, false);
    assert.deepEqual(schema.$defs.artifactBinding.anyOf, [
        { required: ["archive"] },
        { required: ["directory"] },
    ]);
    assert.equal(schema.$defs.archiveBinding.additionalProperties, false);
    assert.equal(schema.$defs.directoryBinding.additionalProperties, false);
    assert.equal(schema["x-noderooms-contract"].external_trust_anchor_required, true);
    assert.doesNotMatch(schemaText, /\r/);
    assert.doesNotMatch(
        JSON.stringify(schema.$defs.signedAttestation.properties),
        /public_key_jwk|private_key|private_jwk/,
    );
});

test("valid minimal and full public-safe fixtures pass semantic validation", () => {
    const minimal = minimalFixture();
    assert.equal(Value.Check(schema, minimal), true);
    assert.equal(Value.Check(schema, validFixture), true);
    assert.deepEqual(validateEvidence(minimal), {
        valid: true,
        authority_granted: false,
        live_enforce_allowed: false,
        evidence_available: true,
    });
    assert.deepEqual(validateEvidence(validFixture), {
        valid: true,
        authority_granted: false,
        live_enforce_allowed: false,
        evidence_available: true,
    });
    assert.equal(validFixture.schema_binding.schema_fingerprint_sha256, SCHEMA_FINGERPRINT);
    assert.equal(validFixture.evidence_fingerprint_sha256, evidenceFingerprint(validFixture));
});

test("stored negative fixtures reject revoked-active conflict and unknown outcome", () => {
    assert.equal(Value.Check(schema, revokedFixture), false);
    assert.equal(Value.Check(schema, unknownOutcomeFixture), false);
    expectCode(revokedFixture, "EVIDENCE_LIFECYCLE_CONFLICT");
    expectCode(unknownOutcomeFixture, "EVIDENCE_CHECK_OUTCOME_INVALID");
});

test("schema drift and unknown fields fail closed", () => {
    expectCode(mutated((value) => {
        value.unexpected = false;
    }), "EVIDENCE_UNKNOWN_FIELD");
    expectCode(mutated((value) => {
        delete value.artifact_binding;
    }), "EVIDENCE_REQUIRED_FIELD_MISSING");
    expectCode(mutated((value) => {
        value.contract_version = "claw-runtime-evidence.v0.2";
    }), "EVIDENCE_CONTRACT_VERSION_INVALID");
    expectCode(mutated((value) => {
        value.schema_binding.schema_fingerprint_sha256 =
            `sha256:${"0".repeat(64)}`;
    }), "EVIDENCE_SCHEMA_FINGERPRINT_MISMATCH");
});

test("malformed ids, hashes, uppercase hashes, and wildcards are rejected", () => {
    expectCode(mutated((value) => {
        value.evidence_id = "evidence-invalid";
    }), "EVIDENCE_ID_INVALID");
    expectCode(mutated((value) => {
        value.artifact_binding.archive.sha256 = "sha256:1234";
    }), "EVIDENCE_HASH_INVALID");
    expectCode(mutated((value) => {
        value.artifact_binding.archive.sha256 = `sha256:${"A".repeat(64)}`;
    }), "EVIDENCE_HASH_INVALID");
    expectCode(mutated((value) => {
        value.assessment.checks[0].check_id = "artifact.*";
    }), "EVIDENCE_WILDCARD_REJECTED");
});

test("timestamps, lifecycle state, and supersede chains fail closed", () => {
    expectCode(mutated((value) => {
        value.lifecycle.issued_at = "not-a-time";
    }), "EVIDENCE_TIMESTAMP_INVALID");
    expectCode(mutated((value) => {
        value.lifecycle.expires_at = "2026-07-29T08:15:00Z";
    }), "EVIDENCE_TIME_ORDER_INVALID");
    expectCode(mutated((value) => {
        value.lifecycle.current_status = "superseded";
        value.lifecycle.active = false;
        value.lifecycle.superseded_by_evidence_id = value.evidence_id;
    }), "EVIDENCE_SUPERSEDE_CYCLE");
});

test("check identity, state, and strict aggregation fail closed", () => {
    expectCode(mutated((value) => {
        value.assessment.checks.push(clone(value.assessment.checks[0]));
    }), "EVIDENCE_DUPLICATE_CHECK");
    expectCode(mutated((value) => {
        const check = value.assessment.checks[0];
        check.outcome = "not_run";
        check.completed = false;
        delete check.observed_at;
        delete check.evidence_fingerprint_sha256;
    }), "EVIDENCE_REQUIRED_CHECK_NOT_RUN");
    expectCode(mutated((value) => {
        value.assessment.passed_required_check_count = 2;
    }), "EVIDENCE_AGGREGATE_MISMATCH");
});

test("private keys, sensitive nested fields, unsafe URLs, and local paths are rejected", () => {
    expectCode(mutated((value) => {
        value.attestation.private_jwk = {
            d: "fixture-private-key-material",
        };
    }), "EVIDENCE_PRIVATE_KEY_EMBEDDED");
    expectCode(mutated((value) => {
        value.authority_binding.oauth_token = "fixture-secret";
    }), "EVIDENCE_SENSITIVE_FIELD");
    expectCode(mutated((value) => {
        value.artifact_binding.origin_uri =
            "https://example.invalid/registry?token=fixture-secret";
    }), "EVIDENCE_URL_UNSAFE");
    expectCode(mutated((value) => {
        value.runtime_binding.local_source = "/workspace/private/source";
    }), "EVIDENCE_SENSITIVE_FIELD");
});

test("exact artifact/runtime, Owner-bound authority, claims, and side effects remain narrow", () => {
    expectCode(mutated((value) => {
        value.runtime_binding.plugin_package_version = "0.0.1-fixture";
    }), "EVIDENCE_ARTIFACT_RUNTIME_MISMATCH");
    expectCode(mutated((value) => {
        delete value.authority_binding;
    }), "EVIDENCE_AUTHORITY_BINDING_REQUIRED");
    expectCode(mutated((value) => {
        value.claims.execution_authority_granted = true;
    }), "EVIDENCE_CLAIM_INVALID");
    expectCode(mutated((value) => {
        value.zero_side_effects.PROVIDER_WRITES = 1;
    }), "EVIDENCE_SIDE_EFFECT_GATE_FAILED");
});

test("non-fixture evidence requires an external-anchor signed attestation", () => {
    expectCode(mutated((value) => {
        value.fixture = false;
    }), "EVIDENCE_ATTESTATION_INVALID");
});

test("Alpha2 strategy freezes the integrated evidence-chain and claim boundary", () => {
    const requiredChainTerms = [
        "Verified Owner",
        "persistent Agent Passport",
        "exact artifact fingerprint",
        "Agent/Gateway/runtime binding",
        "Owner-approved exact scoped permit",
        "actual provider outcome",
        "signed privacy-preserving receipt",
        "idempotency and replay protection",
        "portable cross-Gateway evidence",
    ];
    const requiredProofStatuses = [
        "implemented and locally tested",
        "contract-level",
        "isolated provider proof",
        "observe-only",
        "external validation pending",
        "cross-Gateway proof pending",
        "production enforcement disabled",
    ];
    const prohibitedClaims = [
        "„világelső”",
        "„production-safe”",
        "„exactly once”",
        "„tamper-proof”",
        "„ClawHub által hitelesített”",
    ];

    for (const term of requiredChainTerms) {
        assert.match(strategicSupplement, new RegExp(term.replaceAll("/", "\\/")));
    }
    for (const status of requiredProofStatuses) {
        assert.match(strategicSupplement, new RegExp(status));
    }
    for (const claim of prohibitedClaims) {
        assert.equal(strategicSupplement.includes(claim), true);
    }
    assert.match(
        strategicSupplement,
        /runtime_authority_granted: false/,
    );
    assert.match(
        strategicSupplement,
        /production_enforcement_enabled: false/,
    );
    assert.match(
        strategicSupplement,
        /a stabil `1\.3\.0` release-forrást és package identityt nem módosítjuk/,
    );
});

test("fingerprint, size, and nesting limits fail closed", () => {
    expectCode(mutated((value) => {
        value.evidence_fingerprint_sha256 = `sha256:${"0".repeat(64)}`;
    }, { refingerprint: false }), "EVIDENCE_FINGERPRINT_MISMATCH");
    expectCode(mutated((value) => {
        value.unexpected = "x".repeat(MAX_DOCUMENT_BYTES);
    }, { refingerprint: false }), "EVIDENCE_DOCUMENT_TOO_LARGE");
    expectCode(mutated((value) => {
        let cursor = {};
        value.unexpected = cursor;
        for (let index = 0; index <= MAX_NESTING_DEPTH; index += 1) {
            cursor.next = {};
            cursor = cursor.next;
        }
    }, { refingerprint: false }), "EVIDENCE_NESTING_TOO_DEEP");
});

test("005A remains outside the published 1.3.0 package and live entry point", () => {
    const files = new Set(packageJson.files);
    const candidatePaths = [
        "contracts/claw-runtime-evidence-v0.1.schema.json",
        "contracts/fixtures/claw-runtime-evidence.readonly-pass-v0.1.json",
        "contracts/fixtures/claw-runtime-evidence.revoked-v0.1.json",
        "contracts/fixtures/claw-runtime-evidence.unknown-outcome-v0.1.json",
        "contracts/fixtures/README.md",
        "docs/adr/005A-claw-runtime-evidence-contract.md",
        "docs/strategy/NODEROOMS_TRUSTBRIDGE_ALPHA2_COMPETITIVE_POSITION_20260730_HU.md",
        "docs/SOURCE_PROVENANCE.md",
        "tests/claw-runtime-evidence-contract.test.mjs",
    ];
    assert.equal(packageJson.version, "1.3.0");
    assert.equal(manifest.version, "1.3.0");
    assert.equal(manifest.contracts.tools.length, 14);
    assert.equal(
        manifest.configSchema.properties.trustLayer.properties.mode.default,
        "off",
    );
    assert.equal(
        manifest.configSchema.properties.workRuntime.properties.mode.default,
        "off",
    );
    for (const candidatePath of candidatePaths) {
        assert.equal(
            [...files].some((entry) => candidatePath === entry
                || candidatePath.startsWith(`${entry}/`)),
            false,
            `${candidatePath} must remain outside the npm package`,
        );
    }
    assert.doesNotMatch(pluginIndex, /claw-runtime-evidence/i);
});
