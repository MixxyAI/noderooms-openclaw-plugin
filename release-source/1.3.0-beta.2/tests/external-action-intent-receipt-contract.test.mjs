import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
    dispatchReservationFingerprint,
    evaluateExternalActionReceiptV2,
    externalActionIntentFingerprint,
    externalActionReceiptFingerprint,
    outcomeFingerprint,
    receiptAttributionFingerprint,
    validateExternalActionIntentV2,
    validateExternalActionReceiptV2,
    validateIntentReservationSet,
    validateReceiptChain,
} from "../src/external-action-intent-receipt.js";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const [
    schema,
    registry,
    runtimeBinding,
    request,
    decision,
    lease,
    intent,
    committedReceipt,
    unknownReceipt,
    reconciledReceipt,
] = await Promise.all([
    "contracts/canonical-external-action-intent-receipt-v2.schema.json",
    "contracts/reference/github-draft-pr.v1.json",
    "contracts/fixtures/openclaw-agent-passport.runtime-binding-v1.json",
    "contracts/fixtures/github-draft-pr.capability-request-v2.json",
    "contracts/fixtures/github-draft-pr.owner-decision-v2.json",
    "contracts/fixtures/github-draft-pr.run-lease-v2.json",
    "contracts/fixtures/github-draft-pr.external-action-intent-v2.json",
    "contracts/fixtures/github-draft-pr.external-action-receipt-v2.json",
    "contracts/fixtures/github-draft-pr.external-action-unknown-receipt-v2.json",
    "contracts/fixtures/github-draft-pr.external-action-reconciled-receipt-v2.json",
].map(readJson));

const NOW = Date.parse("2026-07-24T16:10:00Z");
const TRUSTED_RECEIPT_KEY = committedReceipt.attestation.key_thumbprint_sha256;
const OPTIONS = Object.freeze({
    registry,
    runtimeBinding,
    allowFixture: true,
    allowContractOnly: true,
    trustedReceiptKeyThumbprint: TRUSTED_RECEIPT_KEY,
    trustedReceiptPublicKeyJwk: committedReceipt.attestation.public_key_jwk,
    now: NOW,
});

function clone(value) {
    return structuredClone(value);
}

function refreshIntent(value) {
    value.dispatch_reservation.reservation_fingerprint_sha256 =
        dispatchReservationFingerprint(value);
    value.intent_fingerprint_sha256 = externalActionIntentFingerprint(value);
    return value;
}

function intentInput(nextIntent = intent, nextLease = lease) {
    return {
        intent: nextIntent,
        lease: nextLease,
        request,
        decision,
    };
}

function receiptInput(
    receipt,
    previousReceipt,
    nextIntent = intent,
    nextLease = lease,
) {
    return {
        receipt,
        previousReceipt,
        intent: nextIntent,
        lease: nextLease,
        request,
        decision,
    };
}

function recordFor(receipt) {
    return {
        receipt,
        intent,
        lease,
        request,
        decision,
        registry,
        runtimeBinding,
    };
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
            && /(?:allowed|included|persisted|attempted|claimed|required|supported|forwarded)$/i
                .test(key);
        if (!safePolicyBoolean) {
            assert.doesNotMatch(
                key,
                /(?:secret|token|authorization|cookie|credential|private_key|raw_prompt|raw_request|raw_response|raw_result|raw_body)/i,
                `sensitive field at ${path}.${key}`,
            );
        }
        assertNoSensitiveMaterial(entry, `${path}.${key}`);
    }
}

test("002D schema is strict for canonical intent and signed receipt records", () => {
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.oneOf.length, 2);
    assert.equal(schema.$defs.intent.additionalProperties, false);
    assert.equal(schema.$defs.receipt.additionalProperties, false);
    assert.equal(schema.$defs.intent.properties.live_enforce_allowed.const, false);
    assert.equal(
        schema.$defs.receipt.properties.receipt_sequence.maximum,
        2,
    );
    assert.equal(
        schema.$defs.attestation.properties.algorithm.const,
        "Ed25519",
    );
});

test("canonical intent binds one live lease snapshot and one dispatch reservation", () => {
    validateExternalActionIntentV2(intentInput(), OPTIONS);
    assert.equal(
        intent.dispatch_reservation.reservation_fingerprint_sha256,
        dispatchReservationFingerprint(intent),
    );
    assert.equal(
        intent.intent_fingerprint_sha256,
        externalActionIntentFingerprint(intent),
    );
    assert.equal(intent.dispatch_reservation.attempt_count, 0);
    assert.equal(intent.dispatch_reservation.max_attempts, 1);
    assert.equal(intent.approval_consumption.consumed, false);
    assert.equal(intent.constraints.at_most_once_dispatch_required, true);
});

test("contract-only intent cannot authorize a live write", () => {
    assert.throws(
        () => validateExternalActionIntentV2(intentInput(), {
            registry,
            runtimeBinding,
            now: NOW,
        }),
        (error) => error.code === "FIXTURE_REJECTED",
    );
    const nonFixture = clone(intent);
    nonFixture.fixture = false;
    assert.throws(
        () => validateExternalActionIntentV2(intentInput(nonFixture), {
            registry,
            runtimeBinding,
            now: NOW,
        }),
        (error) => error.code === "LIVE_ENFORCE_PROHIBITED",
    );
});

test("intent fails closed on lease, runtime, resource, approval, or payload drift", () => {
    const cases = [
        (value) => { value.lease_binding.lease_id = `nrlv2_${"9".repeat(32)}`; },
        (value) => { value.runtime_binding.run_id = "run-other"; },
        (value) => { value.connector_binding.tool_name = "github_merge_pull_request"; },
        (value) => { value.resource.selector.base_ref = "release"; },
        (value) => { value.payload_projection.base_ref = "release"; },
        (value) => { value.approval_consumption.decision_id = `nrcapdec_${"9".repeat(32)}`; },
        (value) => { value.dispatch_reservation.max_attempts = 2; },
        (value) => { value.dispatch_reservation.automatic_write_retry = true; },
        (value) => { value.constraints.exactly_once_effect_claimed = true; },
    ];
    for (const mutate of cases) {
        const value = clone(intent);
        mutate(value);
        refreshIntent(value);
        assert.throws(() => validateExternalActionIntentV2(intentInput(value), OPTIONS));
    }
});

test("payload content remains projected as hashes and fingerprinted canonically", () => {
    assert.equal(Object.hasOwn(intent.payload_projection, "title"), false);
    assert.equal(Object.hasOwn(intent.payload_projection, "body"), false);
    assert.match(intent.payload_projection.title_sha256, /^sha256:[a-f0-9]{64}$/);
    assert.match(intent.payload_projection.body_sha256, /^sha256:[a-f0-9]{64}$/);
    const drift = clone(intent);
    drift.payload_projection.head_ref = "noderooms/other-change";
    refreshIntent(drift);
    assert.throws(
        () => validateExternalActionIntentV2(intentInput(drift), OPTIONS),
        (error) => error.code === "PAYLOAD_FINGERPRINT_MISMATCH",
    );
});

test("provider idempotency keys are forwarded only when the connector profile supports them", () => {
    const value = clone(intent);
    value.dispatch_reservation.provider_idempotency = {
        supported: true,
        key_binding_fingerprint_sha256: `sha256:${"8".repeat(64)}`,
        forward_on_dispatch: true,
    };
    refreshIntent(value);
    assert.throws(
        () => validateExternalActionIntentV2(intentInput(value), OPTIONS),
        (error) => error.code === "IDEMPOTENCY_PROFILE_MISMATCH",
    );
});

test("revoked, expired, or exhausted lease blocks reservation validation", () => {
    const revoked = clone(lease);
    revoked.revocation = {
        state: "revoked",
        revoked: true,
        revoked_at: "2026-07-24T16:09:00Z",
        reason_code: "owner_revoked",
        sequence: 1,
    };
    assert.throws(
        () => validateExternalActionIntentV2(intentInput(intent, revoked), OPTIONS),
        (error) => error.code === "LEASE_REVOKED",
    );

    const exhausted = clone(lease);
    exhausted.limits.actions_consumed = 1;
    exhausted.limits.actions_remaining = 0;
    assert.throws(
        () => validateExternalActionIntentV2(intentInput(intent, exhausted), OPTIONS),
        (error) => error.code === "LEASE_EXHAUSTED",
    );

    assert.throws(
        () => validateExternalActionIntentV2(intentInput(), {
            ...OPTIONS,
            now: Date.parse(intent.expires_at),
        }),
        (error) => error.code === "INTENT_EXPIRED"
            || error.code === "INTENT_LIFETIME_INVALID"
            || error.code === "LEASE_EXPIRED",
    );
});

test("one lease cannot reserve a second external write intent", () => {
    const record = {
        intent,
        lease,
        request,
        decision,
        registry,
        runtimeBinding,
    };
    const result = validateIntentReservationSet([record], {
        allowFixture: true,
        allowContractOnly: true,
        now: NOW,
    });
    assert.equal(result.intent_count, 1);
    assert.equal(result.at_most_once_dispatch_required, true);
    assert.throws(
        () => validateIntentReservationSet([record, clone(record)], {
            allowFixture: true,
            allowContractOnly: true,
            now: NOW,
        }),
        (error) => [
            "DUPLICATE_INTENT_ID",
            "DUPLICATE_INTENT_FINGERPRINT",
            "LEASE_ACTION_REPLAY",
            "DUPLICATE_RESERVATION_ID",
            "DUPLICATE_RESERVATION_FINGERPRINT",
        ].includes(error.code),
    );
});

test("committed receipt is fingerprinted, signed, and never overclaims exactly-once effect", () => {
    validateExternalActionReceiptV2(receiptInput(committedReceipt), OPTIONS);
    assert.equal(
        committedReceipt.outcome_fingerprint_sha256,
        outcomeFingerprint(committedReceipt),
    );
    assert.equal(
        committedReceipt.audit_projection.attribution_fingerprint_sha256,
        receiptAttributionFingerprint(committedReceipt),
    );
    assert.equal(
        committedReceipt.receipt_fingerprint_sha256,
        externalActionReceiptFingerprint(committedReceipt),
    );
    assert.equal(committedReceipt.dispatch.attempt_count, 1);
    assert.equal(committedReceipt.dispatch.at_most_once_dispatch_enforced, true);
    assert.equal(committedReceipt.dispatch.exactly_once_effect_claimed, false);
    assert.equal(committedReceipt.approval_consumption.consumed, true);
});

test("receipt rejects a different trust anchor or tampered Ed25519 signature", () => {
    assert.throws(
        () => validateExternalActionReceiptV2(receiptInput(committedReceipt), {
            ...OPTIONS,
            trustedReceiptKeyThumbprint: `sha256:${"f".repeat(64)}`,
        }),
        (error) => error.code === "RECEIPT_TRUST_ANCHOR_MISMATCH",
    );
    const tampered = clone(committedReceipt);
    tampered.attestation.signature_base64url =
        `${tampered.attestation.signature_base64url[0] === "A" ? "B" : "A"}`
        + tampered.attestation.signature_base64url.slice(1);
    assert.throws(
        () => validateExternalActionReceiptV2(receiptInput(tampered), OPTIONS),
        (error) => error.code === "RECEIPT_SIGNATURE_INVALID",
    );
});

test("receipt rejects binding, retry, counter, audit, and reputation drift", () => {
    const cases = [
        (value) => { value.intent_binding.intent_id = `nreai_${"9".repeat(32)}`; },
        (value) => { value.lease_binding.lease_id = `nrlv2_${"9".repeat(32)}`; },
        (value) => { value.runtime_binding.session_id = "session-other"; },
        (value) => { value.payload_fingerprint_sha256 = `sha256:${"9".repeat(64)}`; },
        (value) => { value.dispatch.attempt_count = 2; },
        (value) => { value.dispatch.automatic_write_retry_attempted = true; },
        (value) => { value.dispatch.exactly_once_effect_claimed = true; },
        (value) => { value.approval_consumption.lease_actions_after = 2; },
        (value) => { value.audit_projection.raw_content_included = true; },
        (value) => { value.reputation_projection.score_delta_applied = true; },
        (value) => {
            value.outcome.provider_object.url =
                "https://example.com/example-org/example-repo/pull/123";
        },
        (value) => {
            value.outcome.provider_object.url =
                "https://github.com/other-org/other-repo/pull/123";
        },
    ];
    for (const mutate of cases) {
        const value = clone(committedReceipt);
        mutate(value);
        assert.throws(() => validateExternalActionReceiptV2(receiptInput(value), OPTIONS));
    }
});

test("receipt content tamper cannot be hidden by recomputing unsigned fingerprints", () => {
    const value = clone(committedReceipt);
    value.outcome.provider_object.id = "124";
    value.outcome.provider_object.url =
        "https://github.com/example-org/example-repo/pull/124";
    value.outcome_fingerprint_sha256 = outcomeFingerprint(value);
    value.audit_projection.evidence_fingerprint_sha256 =
        value.outcome_fingerprint_sha256;
    value.receipt_fingerprint_sha256 =
        externalActionReceiptFingerprint(value);
    value.attestation.signed_receipt_fingerprint_sha256 =
        value.receipt_fingerprint_sha256;
    assert.throws(
        () => validateExternalActionReceiptV2(receiptInput(value), OPTIONS),
        (error) => error.code === "RECEIPT_SIGNATURE_INVALID",
    );
});

test("lost response produces an unknown receipt and blocks write replay", () => {
    validateExternalActionReceiptV2(receiptInput(unknownReceipt), OPTIONS);
    assert.equal(unknownReceipt.outcome.status, "unknown");
    assert.equal(unknownReceipt.dispatch.attempt_count, 1);
    assert.equal(unknownReceipt.dispatch.automatic_write_retry_attempted, false);
    assert.equal(unknownReceipt.reconciliation.mode, "read_only");
    assert.equal(unknownReceipt.reconciliation.attempted, false);
});

test("read-only reconciliation resolves unknown outcome with no second write", () => {
    validateExternalActionReceiptV2(
        receiptInput(reconciledReceipt, unknownReceipt),
        OPTIONS,
    );
    const summary = validateReceiptChain([
        recordFor(unknownReceipt),
        recordFor(reconciledReceipt),
    ], {
        allowFixture: true,
        allowContractOnly: true,
        trustedReceiptKeyThumbprint: TRUSTED_RECEIPT_KEY,
        trustedReceiptPublicKeyJwk: committedReceipt.attestation.public_key_jwk,
    });
    assert.equal(summary.receipt_count, 2);
    assert.equal(summary.dispatch_attempt_count, 1);
    assert.equal(summary.automatic_write_retry_attempted, false);
    assert.equal(summary.reconciliation_mode, "read_only");
    assert.equal(summary.terminal_status, "committed");
    assert.equal(summary.exactly_once_effect_claimed, false);
});

test("reconciliation rejects write attempts, wrong history, or a non-unknown predecessor", () => {
    const writeAttempt = clone(reconciledReceipt);
    writeAttempt.reconciliation.provider_write_attempted = true;
    assert.throws(
        () => validateExternalActionReceiptV2(
            receiptInput(writeAttempt, unknownReceipt),
            OPTIONS,
        ),
        (error) => error.code === "INVALID_BOOLEAN",
    );

    const wrongBinding = clone(reconciledReceipt);
    wrongBinding.previous_receipt_binding.receipt_id =
        `nrear_${"9".repeat(32)}`;
    assert.throws(
        () => validateExternalActionReceiptV2(
            receiptInput(wrongBinding, unknownReceipt),
            OPTIONS,
        ),
        (error) => error.code === "PREVIOUS_RECEIPT_MISMATCH",
    );

    assert.throws(
        () => validateExternalActionReceiptV2(
            receiptInput(reconciledReceipt, committedReceipt),
            OPTIONS,
        ),
        (error) => error.code === "RECONCILIATION_HISTORY_INVALID",
    );
});

test("contract match returns evidence, never live authorization or reputation mutation", () => {
    const result = evaluateExternalActionReceiptV2(
        receiptInput(committedReceipt),
        OPTIONS,
    );
    assert.equal(result.decision, "contract_match_not_authorized");
    assert.equal(result.reason_code, "LIVE_ENFORCE_PROHIBITED");
    assert.equal(
        committedReceipt.reputation_projection.eligible_for_reputation,
        false,
    );
    assert.equal(
        committedReceipt.reputation_projection.score_delta_applied,
        false,
    );
});

test("002D stores no provider credential, raw payload, response, prompt, or result", () => {
    for (const value of [
        intent,
        committedReceipt,
        unknownReceipt,
        reconciledReceipt,
    ]) {
        assertNoSensitiveMaterial(value);
    }
});

test("002D validator is packaged but disconnected from live OpenClaw hooks", async () => {
    const index = await readFile(new URL("../src/index.js", import.meta.url), "utf8");
    const manifest = await readJson("openclaw.plugin.json");
    assert.doesNotMatch(index, /external-action-intent-receipt/);
    assert.deepEqual(
        manifest.configSchema.properties.trustLayer.properties.mode.enum,
        ["off", "observe"],
    );
    assert.equal(intent.live_enforce_allowed, false);
    assert.equal(committedReceipt.live_enforce_allowed, false);
});
