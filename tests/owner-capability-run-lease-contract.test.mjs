import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
    capabilityRequestFingerprint,
    evaluateRunLeaseV2,
    leaseAuthorityFingerprint,
    ownerDecisionFingerprint,
    validateCapabilityRequest,
    validateLeaseIssuanceSet,
    validateOwnerDecision,
    validateRunLeaseV2,
} from "../src/owner-capability-run-lease.js";
import { sha256Fingerprint } from "../src/passport-runtime-binding.js";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const schema = await readJson(
    "contracts/owner-reviewed-capability-run-lease-v2.schema.json",
);
const registry = await readJson("contracts/reference/github-draft-pr.v1.json");
const runtimeBinding = await readJson(
    "contracts/fixtures/openclaw-agent-passport.runtime-binding-v1.json",
);
const request = await readJson(
    "contracts/fixtures/github-draft-pr.capability-request-v2.json",
);
const decision = await readJson(
    "contracts/fixtures/github-draft-pr.owner-decision-v2.json",
);
const lease = await readJson("contracts/fixtures/github-draft-pr.run-lease-v2.json");

const NOW = Date.parse("2026-07-24T16:10:00Z");
const OPTIONS = Object.freeze({
    registry,
    runtimeBinding,
    allowFixture: true,
    allowContractOnly: true,
    now: NOW,
});

function clone(value) {
    return structuredClone(value);
}

function refreshRequest(value) {
    value.request_fingerprint_sha256 = capabilityRequestFingerprint(value);
    return value;
}

function refreshDecision(value) {
    value.decision_fingerprint_sha256 = ownerDecisionFingerprint(value);
    return value;
}

function refreshLease(value) {
    value.lease_authority_fingerprint_sha256 = leaseAuthorityFingerprint(value);
    return value;
}

function validateExactChain(values = {}) {
    const nextRequest = values.request ?? request;
    const nextDecision = values.decision ?? decision;
    const nextLease = values.lease ?? lease;
    validateCapabilityRequest(nextRequest, OPTIONS);
    validateOwnerDecision({
        request: nextRequest,
        decision: nextDecision,
    }, OPTIONS);
    validateRunLeaseV2({
        request: nextRequest,
        decision: nextDecision,
        lease: nextLease,
    }, OPTIONS);
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
            && /(?:allowed|included|automatable|automated)$/i.test(key);
        if (!safePolicyBoolean) {
            assert.doesNotMatch(
                key,
                /(?:secret|token|authorization|cookie|credential|private_key|raw_prompt|raw_request|raw_response|raw_result)/i,
                `sensitive field at ${path}.${key}`,
            );
        }
        assertNoSensitiveMaterial(entry, `${path}.${key}`);
    }
}

test("002C schema defines strict request, human Owner decision, and lease records", () => {
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.oneOf.length, 3);
    for (const key of ["capabilityRequest", "ownerDecision", "runLease"]) {
        assert.equal(schema.$defs[key].additionalProperties, false);
    }
    assert.equal(
        schema.$defs.ownerDecision.properties.reviewer
            .properties.decision_automated.const,
        false,
    );
    assert.equal(
        schema.$defs.runLease.properties.live_enforce_allowed.const,
        false,
    );
    assert.equal(
        schema.$defs.runLease.properties.constraints
            .properties.shared_run_secret_allowed.const,
        false,
    );
    assert.equal(
        schema.$defs.runLease.properties.constraints
            .properties.owner_decision_automatable.const,
        false,
    );
});

test("capability request is fingerprinted and bound to exact registry, runtime, and resource", () => {
    assert.equal(
        request.request_fingerprint_sha256,
        capabilityRequestFingerprint(request),
    );
    assert.equal(
        request.registry_binding.tool_schema_fingerprint,
        registry.profiles[0].tool_schema_fingerprint,
    );
    assert.equal(
        request.resource.selector_fingerprint_sha256,
        sha256Fingerprint(request.resource.selector),
    );
    assert.deepEqual(request.agent_binding, runtimeBinding.agent_binding);
    validateCapabilityRequest(request, OPTIONS);
});

test("live validation rejects every 002C fixture and contract-only authority by default", () => {
    assert.throws(
        () => validateCapabilityRequest(request, { registry, runtimeBinding, now: NOW }),
        (error) => error.code === "FIXTURE_REJECTED",
    );
    assert.throws(
        () => validateCapabilityRequest(clone({ ...request, fixture: false }), {
            registry,
            runtimeBinding,
            now: NOW,
        }),
        (error) => error.code === "CONTRACT_ONLY_REQUEST",
    );
});

test("capability request fails closed on identity, tool, resource, and limit drift", () => {
    const cases = [
        (value) => { value.agent_binding.passport_id = "NRP-000043-AGENT"; },
        (value) => { value.runtime_binding.openclaw_agent_id = "agent-other"; },
        (value) => {
            value.registry_binding.tool_schema_fingerprint = `sha256:${"d".repeat(64)}`;
        },
        (value) => { value.registry_binding.scope = "connector.github.pull_request.merge"; },
        (value) => { value.resource.selector.repository_full_name = "*"; },
        (value) => { value.resource.selector.base_ref = "release"; },
        (value) => { value.resource.selector.issue_number = 42; },
        (value) => { delete value.resource.selector.base_ref; },
        (value) => { value.requested_limits.ttl_seconds = 901; },
        (value) => { value.requested_limits.max_actions = 2; },
        (value) => {
            value.requested_limits.resource_limit.selector_fingerprint_sha256 =
                `sha256:${"e".repeat(64)}`;
        },
    ];
    for (const mutate of cases) {
        const value = clone(request);
        mutate(value);
        refreshRequest(value);
        assert.throws(() => validateCapabilityRequest(value, OPTIONS));
    }

    const fingerprintDrift = clone(request);
    fingerprintDrift.runtime_binding.run_id = "run-other";
    assert.throws(
        () => validateCapabilityRequest(fingerprintDrift, OPTIONS),
        (error) => error.code === "REQUEST_FINGERPRINT_MISMATCH",
    );
});

test("Owner decision is exact, human, non-automated, and no broader than the request", () => {
    assert.equal(
        decision.decision_fingerprint_sha256,
        ownerDecisionFingerprint(decision),
    );
    assert.equal(decision.reviewer.kind, "verified_human_owner");
    assert.equal(decision.reviewer.decision_automated, false);
    assert.equal(decision.granted_limits.max_actions, 1);
    assert.equal(decision.granted_limits.ttl_seconds, 900);
    validateOwnerDecision({ request, decision }, OPTIONS);
});

test("Owner decision rejects automation, impersonation, expansion, and high-risk persistence", () => {
    const cases = [
        (value) => { value.reviewer.kind = "agent"; },
        (value) => { value.reviewer.decision_automated = true; },
        (value) => {
            value.reviewer.owner_binding_id = "NRPB-DDDDDDDDDDDDDDDDDDDDDD";
        },
        (value) => { value.reviewer.channel = "slack"; },
        (value) => {
            value.reviewer.owner_sender_binding_sha256 = `sha256:${"f".repeat(64)}`;
        },
        (value) => { value.granted_limits.ttl_seconds = 901; },
        (value) => { value.granted_limits.max_actions = 2; },
        (value) => {
            value.granted_limits.cost_limit = {
                currency: "USD",
                max_minor_units: 100,
            };
        },
        (value) => {
            value.granted_limits.goal_limit.objective_fingerprint_sha256 =
                `sha256:${"0".repeat(64)}`;
        },
        (value) => {
            value.granted_limits.resource_limit.max_distinct_resources = 2;
        },
        (value) => { value.decision = "approved_bounded"; },
        (value) => { value.request_fingerprint_sha256 = `sha256:${"1".repeat(64)}`; },
        (value) => {
            value.registry_binding_fingerprint_sha256 = `sha256:${"2".repeat(64)}`;
        },
    ];
    for (const mutate of cases) {
        const value = clone(decision);
        mutate(value);
        refreshDecision(value);
        assert.throws(() => validateOwnerDecision({ request, decision: value }, OPTIONS));
    }
});

test("a denial is valid review evidence but can never issue a run lease", () => {
    const denied = clone(decision);
    denied.decision = "denied";
    denied.granted_limits = null;
    denied.reason_code = "owner_denied_scope";
    refreshDecision(denied);
    validateOwnerDecision({ request, decision: denied }, OPTIONS);

    const deniedLease = clone(lease);
    deniedLease.owner_decision_binding.decision_fingerprint_sha256 =
        denied.decision_fingerprint_sha256;
    deniedLease.approval.decision = denied.decision;
    deniedLease.approval.decision_fingerprint_sha256 =
        denied.decision_fingerprint_sha256;
    refreshLease(deniedLease);
    assert.throws(
        () => validateRunLeaseV2({
            request,
            decision: denied,
            lease: deniedLease,
        }, OPTIONS),
        (error) => error.code === "OWNER_DENIED",
    );
});

test("run lease v2 carries the exact reviewed authority and remains non-live", () => {
    validateExactChain();
    assert.equal(
        lease.lease_authority_fingerprint_sha256,
        leaseAuthorityFingerprint(lease),
    );
    assert.equal(lease.request_binding.request_id, request.request_id);
    assert.equal(lease.owner_decision_binding.decision_id, decision.decision_id);
    assert.equal(lease.approval.decision_automated, false);
    assert.equal(lease.issuance.decision_consumed_atomically, true);
    assert.equal(lease.constraints.shared_lease_allowed, false);
    assert.equal(lease.constraints.shared_run_secret_allowed, false);
    const result = evaluateRunLeaseV2({
        request,
        decision,
        lease,
    }, OPTIONS);
    assert.equal(result.decision, "contract_match_not_authorized");
    assert.equal(result.reason_code, "LIVE_ENFORCE_PROHIBITED");
});

test("lease validation rejects every cross-layer authority drift", () => {
    const cases = [
        (value) => { value.request_binding.request_id = "nrcapreq_99999999999999999999999999999999"; },
        (value) => { value.owner_decision_binding.decision_id = "nrcapdec_99999999999999999999999999999999"; },
        (value) => { value.registry_version = "nrcr_drift.001"; },
        (value) => { value.policy_version = "nrp_drift.001"; },
        (value) => { value.connector_binding.provider = "gitlab"; },
        (value) => { value.connector_binding.connector_version = "0.0.0-reference.2"; },
        (value) => { value.connector_binding.tool_name = "github_merge_pull_request"; },
        (value) => {
            value.connector_binding.tool_schema_fingerprint = `sha256:${"3".repeat(64)}`;
        },
        (value) => { value.action = "merge"; },
        (value) => { value.resource.selector.base_ref = "release"; },
        (value) => { value.runtime_binding.session_id = "session-other"; },
        (value) => { value.runtime_binding.run_id = "run-other"; },
        (value) => { value.runtime_binding.channel = "slack"; },
        (value) => {
            value.runtime_binding.owner_sender_binding_sha256 = `sha256:${"4".repeat(64)}`;
        },
        (value) => { value.agent_binding.owner_binding_id = "NRPB-DDDDDDDDDDDDDDDDDDDDDD"; },
    ];
    for (const mutate of cases) {
        const value = clone(lease);
        mutate(value);
        if (value.resource.selector.base_ref !== lease.resource.selector.base_ref) {
            value.resource.selector_fingerprint_sha256 =
                sha256Fingerprint(value.resource.selector);
            value.limits.resource_limit.selector_fingerprint_sha256 =
                value.resource.selector_fingerprint_sha256;
        }
        refreshLease(value);
        assert.throws(() => validateRunLeaseV2({
            request,
            decision,
            lease: value,
        }, OPTIONS));
    }
});

test("revocation, expiry, exhaustion, and counter drift fail closed", () => {
    const revoked = clone(lease);
    revoked.revocation = {
        state: "revoked",
        revoked: true,
        revoked_at: "2026-07-24T16:09:00Z",
        reason_code: "owner_revoked",
        sequence: 1,
    };
    assert.throws(
        () => validateRunLeaseV2({ request, decision, lease: revoked }, OPTIONS),
        (error) => error.code === "LEASE_REVOKED",
    );

    assert.throws(
        () => validateRunLeaseV2({ request, decision, lease }, {
            ...OPTIONS,
            now: Date.parse(lease.expires_at),
        }),
        (error) => error.code === "DECISION_EXPIRED"
            || error.code === "LEASE_EXPIRED",
    );

    const exhausted = clone(lease);
    exhausted.limits.actions_consumed = 1;
    exhausted.limits.actions_remaining = 0;
    assert.throws(
        () => validateRunLeaseV2({ request, decision, lease: exhausted }, OPTIONS),
        (error) => error.code === "LEASE_EXHAUSTED",
    );

    const counterDrift = clone(lease);
    counterDrift.limits.actions_consumed = 1;
    counterDrift.limits.actions_remaining = 1;
    assert.throws(
        () => validateRunLeaseV2({ request, decision, lease: counterDrift }, OPTIONS),
        (error) => error.code === "LEASE_COUNTER_MISMATCH",
    );

    for (const field of [
        "wildcard_authorization_allowed",
        "shared_lease_allowed",
        "shared_run_secret_allowed",
        "provider_credentials_included",
        "owner_decision_automatable",
    ]) {
        const unsafe = clone(lease);
        unsafe.constraints[field] = true;
        refreshLease(unsafe);
        assert.throws(() => validateRunLeaseV2({
            request,
            decision,
            lease: unsafe,
        }, OPTIONS));
    }
});

test("lease authority fingerprint is stable across mutable consumption and revocation state", () => {
    const mutable = clone(lease);
    mutable.approval.consumed = true;
    mutable.limits.actions_consumed = 1;
    mutable.limits.actions_remaining = 0;
    mutable.revocation = {
        state: "revoked",
        revoked: true,
        revoked_at: "2026-07-24T16:09:00Z",
        reason_code: "owner_revoked",
        sequence: 1,
    };
    assert.equal(
        leaseAuthorityFingerprint(mutable),
        lease.lease_authority_fingerprint_sha256,
    );
});

test("one request or Owner decision cannot mint more than one lease", () => {
    const record = {
        lease,
        request,
        decision,
        registry,
        runtimeBinding,
    };
    const summary = validateLeaseIssuanceSet([record], {
        allowFixture: true,
        allowContractOnly: true,
        now: NOW,
    });
    assert.equal(summary.lease_count, 1);
    assert.equal(summary.owner_decision_automatable, false);
    assert.equal(summary.shared_lease_allowed, false);

    assert.throws(
        () => validateLeaseIssuanceSet([record, clone(record)], {
            allowFixture: true,
            allowContractOnly: true,
            now: NOW,
        }),
        (error) => [
            "DUPLICATE_LEASE_ID",
            "REQUEST_REPLAY",
            "DECISION_REPLAY",
            "DUPLICATE_LEASE_AUTHORITY",
        ].includes(error.code),
    );
});

test("002C stores no provider credential, run secret, raw prompt, or raw result", () => {
    for (const value of [request, decision, lease]) {
        assertNoSensitiveMaterial(value);
    }
});

test("002C validator is packaged but disconnected from live hooks", async () => {
    const index = await readFile(new URL("../src/index.js", import.meta.url), "utf8");
    const manifest = await readJson("openclaw.plugin.json");
    assert.doesNotMatch(index, /owner-capability-run-lease/);
    assert.deepEqual(
        manifest.configSchema.properties.trustLayer.properties.mode.enum,
        ["off", "observe"],
    );
    assert.equal(lease.live_enforce_allowed, false);
});
