import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Value } from "typebox/value";

import {
    externalActionIntentFingerprint,
    externalActionReceiptFingerprint,
} from "../src/external-action-intent-receipt.js";
import {
    capabilityRequestFingerprint,
    leaseAuthorityFingerprint,
    ownerDecisionFingerprint,
} from "../src/owner-capability-run-lease.js";
import {
    sha256Fingerprint,
} from "../src/passport-runtime-binding.js";
import {
    ACTION_EVIDENCE_ADAPTER_LIVE_AUTHORITY_ALLOWED,
    actionEvidenceFingerprint,
    buildOwnerApprovedActionEvidenceV01,
    TrustBridgeActionEvidenceError,
    validateOwnerApprovedActionEvidenceV01,
} from "../tools/trustbridge/action-evidence-adapter.mjs";
import {
    fingerprintResult,
    fingerprintRuntimeObservation,
} from "../tools/trustbridge/artifact-runtime-fingerprint.mjs";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const [
    evidenceSchema,
    artifactRuntimeFixture,
    registry,
    runtimeBinding,
    request,
    decision,
    lease,
    intent,
    receipt,
] = await Promise.all([
    "contracts/claw-runtime-evidence-v0.1.schema.json",
    "contracts/fixtures/artifact-runtime-fingerprint-v1/expected-result.json",
    "contracts/reference/github-draft-pr.v1.json",
    "contracts/fixtures/openclaw-agent-passport.runtime-binding-v1.json",
    "contracts/fixtures/github-draft-pr.capability-request-v2.json",
    "contracts/fixtures/github-draft-pr.owner-decision-v2.json",
    "contracts/fixtures/github-draft-pr.run-lease-v2.json",
    "contracts/fixtures/github-draft-pr.external-action-intent-v2.json",
    "contracts/fixtures/github-draft-pr.external-action-receipt-v2.json",
].map(readJson));

const source = await readFile(
    new URL("../tools/trustbridge/action-evidence-adapter.mjs", import.meta.url),
    "utf8",
);
const pluginIndex = await readFile(
    new URL("../src/index.js", import.meta.url),
    "utf8",
);
const stableTree = await readFile(
    new URL("../release-source/1.3.0/package.json", import.meta.url),
    "utf8",
);
const NOW = Date.parse("2026-07-24T16:10:00Z");

function clone(value) {
    return structuredClone(value);
}

function alignedArtifactRuntime() {
    const value = clone(artifactRuntimeFixture);
    value.runtime_observation_manifest.bindings.gateway_fingerprint_sha256 =
        sha256Fingerprint({
            gateway_id: lease.runtime_binding.gateway_id,
        });
    value.runtime_observation_manifest.bindings
        .openclaw_agent_fingerprint_sha256 = sha256Fingerprint({
            openclaw_agent_id: lease.runtime_binding.openclaw_agent_id,
        });
    value.runtime_observation_manifest.bindings
        .runtime_key_thumbprint_sha256 =
            lease.runtime_binding.runtime_key_thumbprint;
    const nextRuntime = fingerprintRuntimeObservation({
        openclaw: value.runtime_observation_manifest.openclaw,
        node: value.runtime_observation_manifest.node,
        bindings: value.runtime_observation_manifest.bindings,
        environment: value.runtime_observation_manifest.environment,
    }, value.artifact_binding);
    value.runtime_observation_manifest =
        nextRuntime.runtime_observation_manifest;
    value.runtime_binding = nextRuntime.runtime_binding;
    value.result_fingerprint_sha256 = fingerprintResult(value);
    return value;
}

function lifecycle() {
    return {
        issued_at: "2026-07-24T16:05:00Z",
        expires_at: "2026-07-25T16:05:00Z",
        status_checked_at: "2026-07-24T16:10:00Z",
        current_status: "active",
        active: true,
        status_model: "external_signed_status_record",
        status_record_id: "nrevstatus_55555555555555555555555555555555",
        status_record_uri:
            "https://example.invalid/evidence/status/nrevstatus_55555555555555555555555555555555",
        status_record_fingerprint_sha256:
            `sha256:${"5".repeat(64)}`,
    };
}

function input(overrides = {}) {
    return {
        fixture: true,
        evidence_id: "nrevd_55555555555555555555555555555555",
        artifact_runtime_result: alignedArtifactRuntime(),
        capability_request: clone(request),
        owner_decision: clone(decision),
        run_lease: clone(lease),
        intent: clone(intent),
        receipt: clone(receipt),
        lifecycle: lifecycle(),
        ...overrides,
    };
}

function options() {
    return {
        registry,
        runtimeBinding,
        trustedReceiptKeyThumbprint:
            receipt.attestation.key_thumbprint_sha256,
        trustedReceiptPublicKeyJwk:
            receipt.attestation.public_key_jwk,
        expectedReceiptIssuer: "noderooms",
        now: NOW,
    };
}

function expectCode(code, operation) {
    assert.throws(
        operation,
        (error) =>
            error instanceof TrustBridgeActionEvidenceError
            && error.code === code,
    );
}

test("005C closes exact 005B, authority, intent, and receipt references", () => {
    const evidence = buildOwnerApprovedActionEvidenceV01(input(), options());
    assert.equal(Value.Check(evidenceSchema, evidence), true);
    assert.equal(
        validateOwnerApprovedActionEvidenceV01(evidence),
        evidence,
    );
    assert.equal(
        evidence.authority_binding.capability_request_fingerprint_sha256,
        capabilityRequestFingerprint(request),
    );
    assert.equal(
        evidence.authority_binding.owner_decision_fingerprint_sha256,
        ownerDecisionFingerprint(decision),
    );
    assert.equal(
        evidence.authority_binding.run_lease_fingerprint_sha256,
        leaseAuthorityFingerprint(lease),
    );
    assert.equal(
        evidence.authority_binding.external_action_intent_fingerprint_sha256,
        externalActionIntentFingerprint(intent),
    );
    assert.equal(
        evidence.authority_binding.external_action_receipt_fingerprint_sha256,
        externalActionReceiptFingerprint(receipt),
    );
    assert.equal(
        evidence.evidence_fingerprint_sha256,
        actionEvidenceFingerprint(evidence),
    );
});

test("005C remains fixture-only, evidence-only, and zero-side-effect", () => {
    const evidence = buildOwnerApprovedActionEvidenceV01(input(), options());
    assert.equal(ACTION_EVIDENCE_ADAPTER_LIVE_AUTHORITY_ALLOWED, false);
    assert.equal(evidence.fixture, true);
    assert.equal(evidence.authority_status, "evidence_only_no_authority");
    assert.equal(evidence.live_enforce_allowed, false);
    assert.equal(evidence.claims.execution_authority_granted, false);
    assert.equal(evidence.claims.exactly_once_effect_claimed, false);
    assert.equal(evidence.claims.reputation_score_generated, false);
    assert.deepEqual(Object.values(evidence.zero_side_effects), Array(12).fill(0));
    expectCode(
        "005C_EXTERNAL_ATTESTATION_REQUIRED",
        () => buildOwnerApprovedActionEvidenceV01(
            input({ fixture: false }),
            options(),
        ),
    );
});

test("005C rejects 005B result and runtime cross-binding drift", () => {
    const fingerprintDrift = input();
    fingerprintDrift.artifact_runtime_result.result_fingerprint_sha256 =
        `sha256:${"0".repeat(64)}`;
    expectCode(
        "005C_ARTIFACT_RUNTIME_FINGERPRINT_MISMATCH",
        () => buildOwnerApprovedActionEvidenceV01(
            fingerprintDrift,
            options(),
        ),
    );

    const runtimeDrift = input();
    runtimeDrift.artifact_runtime_result.runtime_observation_manifest
        .bindings.gateway_fingerprint_sha256 = `sha256:${"9".repeat(64)}`;
    const nextRuntime = fingerprintRuntimeObservation({
        openclaw:
            runtimeDrift.artifact_runtime_result
                .runtime_observation_manifest.openclaw,
        node:
            runtimeDrift.artifact_runtime_result
                .runtime_observation_manifest.node,
        bindings:
            runtimeDrift.artifact_runtime_result
                .runtime_observation_manifest.bindings,
        environment:
            runtimeDrift.artifact_runtime_result
                .runtime_observation_manifest.environment,
    }, runtimeDrift.artifact_runtime_result.artifact_binding);
    runtimeDrift.artifact_runtime_result.runtime_observation_manifest =
        nextRuntime.runtime_observation_manifest;
    runtimeDrift.artifact_runtime_result.runtime_binding =
        nextRuntime.runtime_binding;
    runtimeDrift.artifact_runtime_result.result_fingerprint_sha256 =
        fingerprintResult(runtimeDrift.artifact_runtime_result);
    expectCode(
        "005C_RUNTIME_CROSS_BINDING_MISMATCH",
        () => buildOwnerApprovedActionEvidenceV01(runtimeDrift, options()),
    );
});

test("005C fails closed on Owner, intent, receipt, and evidence drift", () => {
    const automatedOwner = input();
    automatedOwner.owner_decision.reviewer.decision_automated = true;
    assert.throws(
        () => buildOwnerApprovedActionEvidenceV01(automatedOwner, options()),
        (error) => error.code === "INVALID_BOOLEAN",
    );

    const replayDrift = input();
    replayDrift.intent.dispatch_reservation.max_attempts = 2;
    assert.throws(
        () => buildOwnerApprovedActionEvidenceV01(replayDrift, options()),
        (error) => error.code === "INVALID_INTEGER",
    );

    const unsignedReceipt = input();
    unsignedReceipt.receipt.attestation.signature_base64url =
        "A".repeat(86);
    assert.throws(
        () => buildOwnerApprovedActionEvidenceV01(unsignedReceipt, options()),
        (error) => error.code === "RECEIPT_SIGNATURE_INVALID",
    );

    const evidence = structuredClone(
        buildOwnerApprovedActionEvidenceV01(input(), options()),
    );
    evidence.authority_binding.shared_lease_allowed = true;
    expectCode(
        "005C_EVIDENCE_BOUNDARY_INVALID",
        () => validateOwnerApprovedActionEvidenceV01(evidence),
    );
});

test("005C adapter is repository-only and disconnected from live runtime", () => {
    assert.doesNotMatch(pluginIndex, /action-evidence-adapter/i);
    assert.doesNotMatch(
        source,
        /(?:node:https|node:http|node:net|node:child_process|node:fs|fetch\s*\()/,
    );
    assert.doesNotMatch(
        source,
        /(?:gateway\s+(?:start|restart)|clawhub\s+publish|npm\s+publish)/i,
    );
    assert.equal(JSON.parse(stableTree).version, "1.3.0");
});
