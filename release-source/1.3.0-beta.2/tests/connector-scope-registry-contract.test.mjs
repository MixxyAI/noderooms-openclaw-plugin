import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import {
    validateExternalActionIntentV2,
    validateExternalActionReceiptV2,
} from "../src/external-action-intent-receipt.js";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const schema = await readJson("contracts/connector-scope-registry-v1.schema.json");
const registry = await readJson("contracts/reference/github-draft-pr.v1.json");
const lease = await readJson("contracts/fixtures/github-draft-pr.run-lease-v2.json");
const request = await readJson(
    "contracts/fixtures/github-draft-pr.capability-request-v2.json",
);
const decision = await readJson(
    "contracts/fixtures/github-draft-pr.owner-decision-v2.json",
);
const intent = await readJson("contracts/fixtures/github-draft-pr.external-action-intent-v2.json");
const receipt = await readJson("contracts/fixtures/github-draft-pr.external-action-receipt-v2.json");
const runtimeBinding = await readJson(
    "contracts/fixtures/openclaw-agent-passport.runtime-binding-v1.json",
);

const SCOPE_PATTERN = /^connector\.[a-z][a-z0-9_]{1,31}\.[a-z][a-z0-9_]{1,47}\.[a-z][a-z0-9_]{1,47}$/;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const REGISTRY_VERSION_PATTERN = /^nrcr_[a-z0-9][a-z0-9._-]{2,63}$/;
const POLICY_VERSION_PATTERN = /^nrp_[a-z0-9][a-z0-9._-]{2,63}$/;

function canonicalJson(value) {
    if (Array.isArray(value)) {
        return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
    }
    if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}

function fingerprint(value) {
    return `sha256:${createHash("sha256").update(canonicalJson(value), "utf8").digest("hex")}`;
}

function clone(value) {
    return structuredClone(value);
}

function assertExactKeys(value, expected, label) {
    assert.ok(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
    assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${label} fields drifted`);
}

function assertNoSensitiveMaterial(value, path = "$") {
    if (Array.isArray(value)) {
        value.forEach((entry, index) => assertNoSensitiveMaterial(entry, `${path}[${index}]`));
        return;
    }
    if (!value || typeof value !== "object") {
        return;
    }
    for (const [key, entry] of Object.entries(value)) {
        const safePolicyBoolean = typeof entry === "boolean"
            && /(?:allowed|included|automatable|automated|persisted|attempted|claimed|required|supported|forwarded)$/i
                .test(key);
        if (!safePolicyBoolean) {
            assert.doesNotMatch(
                key,
                /(?:secret|token|authorization|raw_prompt|raw_body|raw_request|raw_response|credential_value)/i,
                `sensitive field at ${path}.${key}`,
            );
        }
        assertNoSensitiveMaterial(entry, `${path}.${key}`);
    }
}

function assertRegistryContract(value) {
    assertExactKeys(value, [
        "$schema",
        "contract_version",
        "registry_version",
        "policy_version",
        "activation_state",
        "live_enforce_allowed",
        "source_provenance",
        "profiles",
    ], "registry");
    assert.equal(value.contract_version, "noderooms-connector-scope-registry-v1");
    assert.match(value.registry_version, REGISTRY_VERSION_PATTERN);
    assert.match(value.policy_version, POLICY_VERSION_PATTERN);
    assert.equal(value.activation_state, "contract_only");
    assert.equal(value.live_enforce_allowed, false);
    assertExactKeys(value.source_provenance, ["repository", "commit", "tree"], "source provenance");
    assert.equal(value.source_provenance.repository, "MixxyAI/noderooms-openclaw-plugin");
    assert.match(value.source_provenance.commit, /^[a-f0-9]{40}$/);
    assert.match(value.source_provenance.tree, /^[a-f0-9]{40}$/);
    assert.ok(Array.isArray(value.profiles) && value.profiles.length > 0);

    const profileIds = new Set();
    const scopes = new Set();
    for (const profile of value.profiles) {
        assertExactKeys(profile, [
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
        ], "profile");
        assert.match(profile.profile_id, /^nrscp_[a-z0-9][a-z0-9_]{2,95}$/);
        assert.match(profile.scope, SCOPE_PATTERN);
        assert.doesNotMatch(profile.scope, /[*{}[\]]/);
        assert.ok(!profileIds.has(profile.profile_id), "duplicate profile id");
        assert.ok(!scopes.has(profile.scope), "duplicate scope");
        profileIds.add(profile.profile_id);
        scopes.add(profile.scope);
        assert.equal(profile.status, "reference_only");
        assert.match(profile.provider, /^[a-z][a-z0-9_]{1,31}$/);
        assert.match(profile.connector_id, /^[a-z][a-z0-9._:-]{2,127}$/);
        assert.match(profile.connector_version, /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/);
        assert.match(profile.tool_name, /^[A-Za-z0-9._:-]{1,128}$/);
        assert.match(profile.tool_schema_fingerprint, SHA256_PATTERN);
        assert.equal(profile.tool_schema_fingerprint, fingerprint(profile.tool_input_schema));
        assert.equal(profile.tool_input_schema.type, "object");
        assert.equal(profile.tool_input_schema.additionalProperties, false);
        assert.equal(profile.resource_selector.strategy, "exact");
        assert.equal(profile.resource_selector.wildcards_allowed, false);
        assert.ok(profile.resource_selector.required_claims.length > 0);
        assert.equal(new Set(profile.resource_selector.required_claims).size, profile.resource_selector.required_claims.length);
        if (profile.risk === "high" || profile.risk === "critical") {
            assert.equal(profile.approval_policy, "allow_once");
        }
        assert.notEqual(profile.approval_policy, "allow_always");
    }
    assertNoSensitiveMaterial(value);
}

function assertLeaseContract(value, profile, now = Date.parse("2026-07-24T16:10:00Z")) {
    assert.equal(value.contract_version, "noderooms-run-lease-v2");
    assert.equal(value.fixture, true);
    assert.equal(value.registry_version, registry.registry_version);
    assert.equal(value.policy_version, registry.policy_version);
    assert.equal(value.profile_id, profile.profile_id);
    assert.equal(value.scope, profile.scope);
    assert.deepEqual(value.agent_binding, runtimeBinding.agent_binding);
    assert.equal(value.runtime_binding.binding_id, runtimeBinding.binding_id);
    for (const field of ["platform", "gateway_id", "runtime_instance_id", "openclaw_agent_id"]) {
        assert.equal(
            value.runtime_binding[field],
            runtimeBinding.runtime_binding[field],
            `lease runtime ${field} mismatch`,
        );
    }
    assert.equal(
        value.runtime_binding.runtime_key_thumbprint,
        runtimeBinding.runtime_key.thumbprint_sha256,
    );
    assert.equal(value.connector_binding.provider, profile.provider);
    assert.equal(value.connector_binding.connector_id, profile.connector_id);
    assert.equal(value.connector_binding.connector_version, profile.connector_version);
    assert.equal(value.connector_binding.tool_name, profile.tool_name);
    assert.equal(value.connector_binding.tool_schema_fingerprint, profile.tool_schema_fingerprint);
    assert.equal(value.action, profile.action);
    assert.equal(value.resource.resource_type, profile.resource_type);
    for (const claim of profile.resource_selector.required_claims) {
        assert.equal(typeof value.resource.selector[claim], "string", `missing exact resource claim ${claim}`);
        assert.ok(value.resource.selector[claim].length > 0, `empty exact resource claim ${claim}`);
        assert.doesNotMatch(value.resource.selector[claim], /[*{}[\]]/);
    }
    assert.equal(value.approval.policy, profile.approval_policy);
    assert.equal(value.approval.decision, "approved_once");
    assert.equal(value.approval.approved_by, "verified_human_owner");
    assert.equal(value.approval.consumed, false);
    assert.equal(value.limits.max_actions, 1);
    assert.equal(value.limits.actions_remaining, 1);
    assert.ok(Date.parse(value.issued_at) <= now);
    assert.ok(Date.parse(value.expires_at) > now);
    assert.equal(value.revocation.revoked, false);
    assertNoSensitiveMaterial(value);
}

function assertIntentContract(value, leaseValue, profile) {
    validateExternalActionIntentV2({
        intent: value,
        lease: leaseValue,
        request,
        decision,
    }, {
        registry,
        runtimeBinding,
        allowFixture: true,
        allowContractOnly: true,
        now: Date.parse("2026-07-24T16:10:00Z"),
    });
    assert.equal(value.contract_version, "noderooms-external-action-intent-v2");
    assert.equal(value.fixture, true);
    assert.equal(value.lease_binding.lease_id, leaseValue.lease_id);
    for (const field of ["registry_version", "policy_version", "profile_id", "scope", "action"]) {
        assert.equal(value[field], leaseValue[field], `intent ${field} mismatch`);
    }
    assert.deepEqual(value.agent_binding, leaseValue.agent_binding);
    assert.deepEqual(value.runtime_binding, leaseValue.runtime_binding);
    assert.deepEqual(value.connector_binding, leaseValue.connector_binding);
    assert.deepEqual(value.resource, leaseValue.resource);
    assert.equal(value.payload_projection.repository_full_name, value.resource.selector.repository_full_name);
    assert.equal(value.payload_projection.base_ref, value.resource.selector.base_ref);
    assert.equal(value.payload_projection.draft, true);
    assert.match(value.payload_projection.title_sha256, SHA256_PATTERN);
    assert.match(value.payload_projection.body_sha256, SHA256_PATTERN);
    assert.equal(value.payload_fingerprint_sha256, fingerprint(value.payload_projection));
    assert.equal(value.approval_consumption.policy, profile.approval_policy);
    assert.equal(value.approval_consumption.decision_id, decision.decision_id);
    assert.equal(value.approval_consumption.consumed, false);
    assert.equal(value.dispatch_reservation.state, "reserved");
    assert.equal(value.dispatch_reservation.attempt_count, 0);
    assert.equal(value.dispatch_reservation.max_attempts, 1);
    assert.equal(value.dispatch_reservation.automatic_write_retry, false);
    assert.equal(value.dispatch_reservation.uncertain_outcome_state, "not_dispatched");
    assert.equal(value.dispatch_reservation.reconcile_mode, "read_only");
    assert.ok(Date.parse(value.expires_at) > Date.parse(value.created_at));
    assertNoSensitiveMaterial(value);
}

function assertReceiptContract(value, intentValue, leaseValue, profile) {
    validateExternalActionReceiptV2({
        receipt: value,
        intent: intentValue,
        lease: leaseValue,
        request,
        decision,
    }, {
        registry,
        runtimeBinding,
        allowFixture: true,
        allowContractOnly: true,
        trustedReceiptKeyThumbprint:
            receipt.attestation.key_thumbprint_sha256,
        trustedReceiptPublicKeyJwk:
            receipt.attestation.public_key_jwk,
    });
    assert.equal(value.contract_version, "noderooms-external-action-receipt-v2");
    assert.equal(value.fixture, true);
    assert.equal(value.intent_binding.intent_id, intentValue.intent_id);
    assert.equal(value.lease_binding.lease_id, leaseValue.lease_id);
    for (const field of ["registry_version", "policy_version", "profile_id", "scope", "action"]) {
        assert.equal(value[field], intentValue[field], `receipt ${field} mismatch`);
    }
    assert.deepEqual(value.agent_binding, intentValue.agent_binding);
    assert.deepEqual(value.runtime_binding, intentValue.runtime_binding);
    assert.deepEqual(value.connector_binding, intentValue.connector_binding);
    assert.deepEqual(value.resource, intentValue.resource);
    assert.equal(value.payload_fingerprint_sha256, intentValue.payload_fingerprint_sha256);
    assert.equal(value.outcome.status, "committed");
    assert.equal(value.outcome.provider_object.state, "draft");
    assert.equal(value.dispatch.attempt_count, 1);
    assert.equal(value.dispatch.at_most_once_dispatch_enforced, true);
    assert.equal(value.dispatch.exactly_once_effect_claimed, false);
    assert.equal(value.dispatch.automatic_write_retry_attempted, false);
    assert.equal(value.reconciliation.mode, "read_only");
    assert.equal(value.approval_consumption.policy, profile.approval_policy);
    assert.equal(value.approval_consumption.consumed, true);
    assertNoSensitiveMaterial(value);
}

test("registry JSON Schema declares every canonical authorization dimension", () => {
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.additionalProperties, false);
    const required = schema.$defs.profile.required;
    for (const field of [
        "provider",
        "connector_id",
        "connector_version",
        "tool_name",
        "tool_schema_fingerprint",
        "action",
        "resource_type",
        "resource_selector",
        "risk",
        "side_effect_class",
        "replay_semantics",
        "approval_policy",
        "receipt_profile",
    ]) {
        assert.ok(required.includes(field), `schema is missing ${field}`);
    }
    assert.equal(schema.$defs.profile.additionalProperties, false);
});

test("GitHub Draft PR profile is internally consistent and cannot activate live enforcement", () => {
    assertRegistryContract(registry);
    const [profile] = registry.profiles;
    assert.equal(profile.scope, "connector.github.pull_request.draft");
    assert.equal(profile.status, "reference_only");
    assert.equal(registry.live_enforce_allowed, false);
});

test("registry validation fails closed on wildcard, duplicate, approval, and schema drift", () => {
    const wildcard = clone(registry);
    wildcard.profiles[0].scope = "connector.github.pull_request.*";
    assert.throws(() => assertRegistryContract(wildcard));

    const duplicate = clone(registry);
    duplicate.profiles.push(clone(duplicate.profiles[0]));
    duplicate.profiles[1].profile_id = "nrscp_github_pull_request_draft_v2";
    assert.throws(() => assertRegistryContract(duplicate), /duplicate scope/);

    const unsafeApproval = clone(registry);
    unsafeApproval.profiles[0].approval_policy = "none";
    assert.throws(() => assertRegistryContract(unsafeApproval));

    const schemaDrift = clone(registry);
    schemaDrift.profiles[0].tool_input_schema.properties.title.maxLength = 257;
    assert.throws(() => assertRegistryContract(schemaDrift));
});

test("run lease v2 fixture binds one verified Owner, Agent, runtime, tool, action, and resource", () => {
    assertLeaseContract(lease, registry.profiles[0]);
});

test("run lease binding fails closed on drift, mismatch, revocation, expiry, and exhaustion", () => {
    const profile = registry.profiles[0];
    const cases = [
        (value) => { value.registry_version = "nrcr_drift.001"; },
        (value) => { value.policy_version = "nrp_drift.001"; },
        (value) => { value.connector_binding.provider = "gitlab"; },
        (value) => { value.connector_binding.connector_version = "0.0.0-reference.2"; },
        (value) => { value.connector_binding.tool_name = "github_other_tool"; },
        (value) => { value.connector_binding.tool_schema_fingerprint = `sha256:${"d".repeat(64)}`; },
        (value) => { value.action = "merge"; },
        (value) => { value.resource.selector.repository_full_name = "*"; },
        (value) => { value.runtime_binding.openclaw_agent_id = "agent-other"; },
        (value) => { value.revocation.revoked = true; },
        (value) => { value.limits.actions_remaining = 0; },
    ];
    for (const mutate of cases) {
        const value = clone(lease);
        mutate(value);
        assert.throws(() => assertLeaseContract(value, profile));
    }
    assert.throws(() => assertLeaseContract(
        lease,
        profile,
        Date.parse("2026-07-24T16:18:30Z"),
    ));
});

test("external action intent v2 uses a canonical projection and one reserved dispatch", () => {
    assertIntentContract(intent, lease, registry.profiles[0]);
    assert.equal(Object.hasOwn(intent.payload_projection, "title"), false);
    assert.equal(Object.hasOwn(intent.payload_projection, "body"), false);
});

test("external action intent fails closed on binding or payload drift", () => {
    const profile = registry.profiles[0];
    for (const mutate of [
        (value) => { value.agent_binding.agent_id = "agent-other"; },
        (value) => { value.runtime_binding.run_id = "run-other"; },
        (value) => { value.connector_binding.tool_schema_fingerprint = `sha256:${"e".repeat(64)}`; },
        (value) => { value.resource.selector.base_ref = "release"; },
        (value) => { value.payload_projection.base_ref = "release"; },
        (value) => { value.payload_projection.head_ref = "other-head"; },
        (value) => { value.dispatch_reservation.max_attempts = 2; },
        (value) => { value.dispatch_reservation.automatic_write_retry = true; },
    ]) {
        const value = clone(intent);
        mutate(value);
        assert.throws(() => assertIntentContract(value, lease, profile));
    }
});

test("external action receipt v2 proves at-most-once dispatch without overclaiming provider effects", () => {
    assertReceiptContract(receipt, intent, lease, registry.profiles[0]);
});

test("receipt validation rejects retry, exactly-once overclaim, and binding mismatch", () => {
    const profile = registry.profiles[0];
    for (const mutate of [
        (value) => { value.dispatch.attempt_count = 2; },
        (value) => { value.dispatch.exactly_once_effect_claimed = true; },
        (value) => { value.dispatch.automatic_write_retry_attempted = true; },
        (value) => { value.payload_fingerprint_sha256 = `sha256:${"f".repeat(64)}`; },
        (value) => { value.runtime_binding.session_id = "session-other"; },
        (value) => { value.action = "merge"; },
    ]) {
        const value = clone(receipt);
        mutate(value);
        assert.throws(() => assertReceiptContract(value, intent, lease, profile));
    }
});

test("contract CI remains read-only and Beta.1 is pinned to validation-only", async () => {
    const ci = await readFile(new URL("../.github/workflows/plugin-ci.yml", import.meta.url), "utf8");
    assert.match(ci, /permissions:\s*\n\s+contents:\s+read/);
    assert.doesNotMatch(ci, /contents:\s+write/);
    assert.doesNotMatch(ci, /packages:\s+write/);

    const publishWorkflow = await readFile(
        new URL("../.github/workflows/package-publish.yml", import.meta.url),
    );
    assert.equal(
        createHash("sha256").update(publishWorkflow).digest("hex"),
        "676e3b91c53322854de6c1b6b44a588d4bde767e4b51a246bc0ea16d5d39b2fe",
    );
    const publishWorkflowText = publishWorkflow.toString("utf8");
    assert.match(
        publishWorkflowText,
        /name:\s*NodeRooms Beta1 immutable validation \(publish disabled\)/,
    );
    assert.doesNotMatch(publishWorkflowText, /^\s{2}publish:\s*$/m);
    assert.doesNotMatch(publishWorkflowText, /dry_run:\s*false/);

    const manifest = await readJson("openclaw.plugin.json");
    assert.deepEqual(
        manifest.configSchema.properties.trustLayer.properties.mode.enum,
        ["off", "observe"],
    );
});
