import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { sha256Fingerprint } from "../src/passport-runtime-binding.js";
import {
    evaluateWorkMissionV1,
    publicWorkReceiptProjectionFingerprint,
    taskFlowRunFingerprint,
    validateMissionSet,
    validateTaskFlowRunV1,
    validateWorkItemV1,
    validateWorkboardCardV1,
    validateWorkStepReceiptV1,
    workItemFingerprint,
    workboardCardFingerprint,
    workStepReceiptFingerprint,
} from "../src/workdesk-workboard-task-flow.js";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const [
    schema,
    workItemFixture,
    researchReceiptFixture,
    draftReceiptFixture,
    flowFixture,
    cardFixture,
    externalReceiptFixture,
    externalLeaseFixture,
] = await Promise.all([
    "contracts/workdesk-workboard-task-flow-v1.schema.json",
    "contracts/fixtures/github-draft-pr.work-item-v1.json",
    "contracts/fixtures/github-draft-pr.research-work-receipt-v1.json",
    "contracts/fixtures/github-draft-pr.draft-work-receipt-v1.json",
    "contracts/fixtures/github-draft-pr.task-flow-binding-v1.json",
    "contracts/fixtures/github-draft-pr.workboard-binding-v1.json",
    "contracts/fixtures/github-draft-pr.external-action-receipt-v2.json",
    "contracts/fixtures/github-draft-pr.run-lease-v2.json",
].map(readJson));

const NOW = Date.parse("2026-07-24T17:20:00Z");
const OPTIONS = Object.freeze({
    allowFixture: true,
    allowContractOnly: true,
    now: NOW,
});

function clone(value) {
    return structuredClone(value);
}

function fixtureBundle() {
    return {
        workItem: clone(workItemFixture),
        receipts: [
            clone(researchReceiptFixture),
            clone(draftReceiptFixture),
        ],
        flow: clone(flowFixture),
        card: clone(cardFixture),
    };
}

function refreshReceipt(receipt) {
    receipt.public_projection.projection_fingerprint_sha256 =
        publicWorkReceiptProjectionFingerprint(receipt);
    receipt.receipt_fingerprint_sha256 = workStepReceiptFingerprint(receipt);
    return receipt;
}

function refreshFlowReceiptBindings(flow, receipts) {
    const receiptMap = new Map(receipts.map((receipt) => [receipt.step_binding.step_id, receipt]));
    for (const node of flow.nodes) {
        const receipt = receiptMap.get(node.step_id);
        if (receipt && node.receipt_binding) {
            node.receipt_binding.receipt_id = receipt.receipt_id;
            node.receipt_binding.receipt_fingerprint_sha256 =
                receipt.receipt_fingerprint_sha256;
        }
    }
}

function refreshCard(bundle) {
    bundle.card.work_item_binding.work_item_fingerprint_sha256 =
        bundle.workItem.work_item_fingerprint_sha256;
    bundle.card.task_flow_binding.flow_revision = bundle.flow.revision;
    bundle.card.task_flow_binding.flow_fingerprint_sha256 =
        bundle.flow.flow_fingerprint_sha256;
    bundle.card.task_flow_binding.current_step_id = bundle.flow.current_step_id;
    bundle.card.card_fingerprint_sha256 = workboardCardFingerprint(bundle.card);
    return bundle;
}

function completedBundle() {
    const bundle = fixtureBundle();
    bundle.workItem.workflow.status = "completed";
    bundle.workItem.workflow.current_step_id = "create_draft_pr";
    bundle.workItem.updated_at = "2026-07-24T17:24:00Z";
    bundle.workItem.work_item_fingerprint_sha256 =
        workItemFingerprint(bundle.workItem);

    for (const receipt of bundle.receipts) {
        receipt.work_item_binding.work_item_fingerprint_sha256 =
            bundle.workItem.work_item_fingerprint_sha256;
        refreshReceipt(receipt);
    }

    const writeReceipt = clone(draftReceiptFixture);
    writeReceipt.$comment =
        "Programmatic Phase 3A completion fixture with an exact 002D receipt binding.";
    writeReceipt.receipt_id = "nrworkrcpt_33333333333333333333333333333333";
    writeReceipt.work_item_binding.work_item_fingerprint_sha256 =
        bundle.workItem.work_item_fingerprint_sha256;
    writeReceipt.step_binding = {
        step_id: "create_draft_pr",
        execution_class: "write",
        attempt: 1,
        lease: {
            lease_id: externalLeaseFixture.lease_id,
            lease_authority_fingerprint_sha256:
                externalLeaseFixture.lease_authority_fingerprint_sha256,
            contract_version: externalLeaseFixture.contract_version,
        },
    };
    writeReceipt.outcome = {
        status: "completed",
        reason_code: null,
        started_at: "2026-07-24T17:22:00Z",
        completed_at: "2026-07-24T17:23:00Z",
    };
    writeReceipt.artifacts = [
        {
            artifact_id: "nrartifact_33333333333333333333333333333333",
            kind: "draft_pr_reference",
            content_sha256:
                "sha256:7777777777777777777777777777777777777777777777777777777777777777",
            visibility: "public_safe_projection",
            raw_content_included: false,
        },
    ];
    writeReceipt.external_action_receipt_binding = {
        receipt_id: externalReceiptFixture.receipt_id,
        receipt_fingerprint_sha256:
            externalReceiptFixture.receipt_fingerprint_sha256,
    };
    writeReceipt.public_projection = {
        contract_version: "noderooms-public-work-receipt-v1",
        work_item_id: bundle.workItem.work_item_id,
        mission_id: bundle.workItem.mission_id,
        step_id: "create_draft_pr",
        noderooms_agent_id: bundle.workItem.agent_binding.noderooms_agent_id,
        outcome_status: "completed",
        completed_at: "2026-07-24T17:23:00Z",
        artifact_count: 1,
        external_write_performed: true,
        raw_content_included: false,
        provider_credentials_included: false,
        safe_for_public: true,
        projection_fingerprint_sha256:
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    };
    writeReceipt.recorded_at = "2026-07-24T17:23:05Z";
    refreshReceipt(writeReceipt);
    bundle.receipts.push(writeReceipt);

    bundle.flow.work_item_binding.work_item_fingerprint_sha256 =
        bundle.workItem.work_item_fingerprint_sha256;
    bundle.flow.status = "succeeded";
    bundle.flow.revision = 7;
    bundle.flow.current_step_id = "create_draft_pr";
    bundle.flow.wait = null;
    bundle.flow.nodes[2].status = "approved";
    bundle.flow.nodes[3] = {
        step_id: "create_draft_pr",
        kind: "task",
        status: "completed",
        depends_on: ["owner_review"],
        task_binding: {
            task_id: "task-create-draft-pr-example-01",
            run_id: "run-create-draft-pr-example-01",
            status: "succeeded",
        },
        lease_binding: clone(writeReceipt.step_binding.lease),
        receipt_binding: {
            receipt_id: writeReceipt.receipt_id,
            receipt_fingerprint_sha256: writeReceipt.receipt_fingerprint_sha256,
        },
        artifact_refs: [
            writeReceipt.artifacts[0].artifact_id,
        ],
        external_action_receipt_binding:
            clone(writeReceipt.external_action_receipt_binding),
        started_at: writeReceipt.outcome.started_at,
        completed_at: writeReceipt.outcome.completed_at,
    };
    refreshFlowReceiptBindings(bundle.flow, bundle.receipts);
    bundle.flow.checkpoint.last_persisted_revision = bundle.flow.revision;
    bundle.flow.updated_at = "2026-07-24T17:24:00Z";
    bundle.flow.flow_fingerprint_sha256 = taskFlowRunFingerprint(bundle.flow);

    bundle.card.openclaw_card.status = "done";
    bundle.card.proof_refs.work_receipt_ids.push(writeReceipt.receipt_id);
    bundle.card.proof_refs.artifact_ids.push(writeReceipt.artifacts[0].artifact_id);
    bundle.card.proof_refs.external_action_receipt_ids.push(
        externalReceiptFixture.receipt_id,
    );
    bundle.card.handoff = {
        state: "completed",
        from_step_id: "create_draft_pr",
        to_step_id: null,
        claim_released: true,
        owner_review_required: false,
    };
    bundle.card.updated_at = "2026-07-24T17:24:00Z";
    return refreshCard(bundle);
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
            && /(?:allowed|included|persisted|performed|required|inherited|automated|redacted|safe)$/i
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

test("003A schema is strict for work item, work receipt, Task Flow, and Workboard records", () => {
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.oneOf.length, 4);
    for (const name of [
        "workItem",
        "workStepReceipt",
        "taskFlowBinding",
        "workboardBinding",
    ]) {
        assert.equal(schema.$defs[name].additionalProperties, false);
    }
    assert.equal(
        schema.$defs.workItem.properties.live_dispatch_allowed.const,
        false,
    );
    assert.deepEqual(
        schema.$defs.taskFlowBinding.properties.status.enum,
        [
            "queued",
            "running",
            "waiting",
            "blocked",
            "succeeded",
            "failed",
            "cancelled",
            "lost",
        ],
    );
    assert.deepEqual(
        schema.$defs.workboardBinding.properties.openclaw_card.properties.status.enum,
        [
            "triage",
            "backlog",
            "todo",
            "scheduled",
            "ready",
            "running",
            "review",
            "blocked",
            "done",
        ],
    );
});

test("canonical Phase 3A mission validates and remains non-live", () => {
    const bundle = fixtureBundle();
    validateWorkItemV1(bundle.workItem, OPTIONS);
    for (const receipt of bundle.receipts) {
        validateWorkStepReceiptV1(receipt, bundle.workItem, OPTIONS);
    }
    validateTaskFlowRunV1(bundle, OPTIONS);
    validateWorkboardCardV1(bundle, OPTIONS);
    const result = evaluateWorkMissionV1(bundle, OPTIONS);
    assert.equal(result.decision, "contract_match_not_dispatched");
    assert.equal(result.reason_code, "LIVE_DISPATCH_PROHIBITED");
    assert.equal(result.work_receipt_count, 2);
    assert.equal(result.live_dispatch_allowed, false);
});

test("MISSION_CARD_IDEMPOTENCY=PASS", () => {
    const bundle = fixtureBundle();
    const result = validateMissionSet([bundle], OPTIONS);
    assert.equal(result.mission_count, 1);
    assert.equal(result.work_item_count, 1);
    assert.equal(result.workboard_card_count, 1);
    assert.equal(result.task_flow_count, 1);
    assert.equal(result.one_to_one_mapping, true);
    assert.throws(
        () => validateMissionSet([bundle, clone(bundle)], OPTIONS),
        (error) => [
            "DUPLICATE_MISSION_ID",
            "DUPLICATE_WORK_ITEM_ID",
            "DUPLICATE_WORKBOARD_CARD_ID",
            "DUPLICATE_TASK_FLOW_ID",
            "DUPLICATE_CARD_IDEMPOTENCY_KEY",
        ].includes(error.code),
    );
});

test("CLAIM_WITHOUT_LEASE=BLOCKED", () => {
    const bundle = fixtureBundle();
    bundle.card.claim.state = "active";
    bundle.card.claim.claimed_by_runtime_binding_id =
        bundle.workItem.runtime_binding.binding_id;
    bundle.card.claim.heartbeat_at = "2026-07-24T17:19:30Z";
    bundle.card.claim.expires_at = "2026-07-24T17:24:30Z";
    assert.throws(
        () => validateWorkboardCardV1(bundle, OPTIONS),
        (error) => error.code === "CLAIM_WITHOUT_LEASE",
    );

    const flowBundle = fixtureBundle();
    flowBundle.flow.nodes[3].status = "running";
    flowBundle.flow.nodes[3].task_binding = {
        task_id: "task-without-lease",
        run_id: "run-without-lease",
        status: "running",
    };
    flowBundle.flow.nodes[3].started_at = "2026-07-24T17:20:00Z";
    assert.throws(
        () => validateTaskFlowRunV1(flowBundle, OPTIONS),
        (error) => error.code === "CLAIM_WITHOUT_LEASE",
    );
});

test("RESTART_FLOW_RECOVERY=PASS", () => {
    const bundle = fixtureBundle();
    validateTaskFlowRunV1(bundle, OPTIONS);
    assert.equal(bundle.flow.checkpoint.restart_count, 1);
    assert.equal(bundle.flow.checkpoint.recovery_state, "reconciled");
    assert.equal(bundle.flow.checkpoint.reconciliation_mode, "read_only");
    assert.equal(bundle.flow.checkpoint.resume_without_reconcile_allowed, false);

    for (const mutate of [
        (flow) => { flow.checkpoint.last_persisted_revision = 4; },
        (flow) => { flow.checkpoint.recovery_state = "pending"; },
        (flow) => { flow.checkpoint.reconciliation_mode = "write"; },
        (flow) => { flow.checkpoint.resume_without_reconcile_allowed = true; },
    ]) {
        const next = fixtureBundle();
        mutate(next.flow);
        assert.throws(
            () => validateTaskFlowRunV1(next, OPTIONS),
            (error) => error.code === "RESTART_RECOVERY_INVALID",
        );
    }
});

test("ARTIFACT_LINKING=PASS", () => {
    const bundle = fixtureBundle();
    validateWorkboardCardV1(bundle, OPTIONS);
    assert.deepEqual(
        bundle.card.proof_refs.artifact_ids,
        bundle.receipts.flatMap(
            (receipt) => receipt.artifacts.map((artifact) => artifact.artifact_id),
        ),
    );

    const missing = fixtureBundle();
    missing.card.proof_refs.artifact_ids.pop();
    assert.throws(
        () => validateWorkboardCardV1(missing, OPTIONS),
        (error) => error.code === "WORKBOARD_PROOF_MISMATCH",
    );

    const drift = fixtureBundle();
    drift.flow.nodes[1].artifact_refs = [
        "nrartifact_99999999999999999999999999999999",
    ];
    assert.throws(
        () => validateTaskFlowRunV1(drift, OPTIONS),
        (error) => error.code === "FLOW_RECEIPT_BINDING_MISMATCH",
    );
});

test("OWNER_REVIEW_WAIT_STATE=PASS", () => {
    const bundle = fixtureBundle();
    validateWorkboardCardV1(bundle, OPTIONS);
    assert.equal(bundle.workItem.workflow.status, "waiting_owner_review");
    assert.equal(bundle.flow.status, "waiting");
    assert.equal(bundle.flow.nodes[2].status, "waiting");
    assert.equal(bundle.flow.nodes[3].status, "queued");
    assert.equal(bundle.flow.nodes[3].lease_binding, null);
    assert.equal(bundle.card.openclaw_card.status, "review");
    assert.equal(bundle.card.claim.state, "released");

    const prematureWrite = fixtureBundle();
    prematureWrite.flow.nodes[3].lease_binding = {
        lease_id: externalLeaseFixture.lease_id,
        lease_authority_fingerprint_sha256:
            externalLeaseFixture.lease_authority_fingerprint_sha256,
        contract_version: externalLeaseFixture.contract_version,
    };
    assert.throws(
        () => validateTaskFlowRunV1(prematureWrite, OPTIONS),
        (error) => error.code === "QUEUED_STEP_AUTHORITY_INVALID",
    );
});

test("PUBLIC_SAFE_WORK_RECEIPT=PASS", () => {
    const bundle = fixtureBundle();
    for (const receipt of bundle.receipts) {
        validateWorkStepReceiptV1(receipt, bundle.workItem, OPTIONS);
        assert.equal(receipt.public_projection.safe_for_public, true);
        assert.equal(receipt.public_projection.raw_content_included, false);
        assert.equal(receipt.public_projection.provider_credentials_included, false);
        assert.equal(
            receipt.public_projection.projection_fingerprint_sha256,
            publicWorkReceiptProjectionFingerprint(receipt),
        );
    }

    const unsafe = clone(bundle.receipts[0]);
    unsafe.public_projection.raw_content_included = true;
    assert.throws(
        () => validateWorkStepReceiptV1(unsafe, bundle.workItem, OPTIONS),
        (error) => error.code === "INVALID_BOOLEAN",
    );
});

test("each executable task has a distinct lease and receipt with no privilege inheritance", () => {
    const bundle = fixtureBundle();
    assert.notEqual(
        bundle.flow.nodes[0].lease_binding.lease_id,
        bundle.flow.nodes[1].lease_binding.lease_id,
    );
    assert.equal(
        bundle.flow.constraints.subagent_privilege_inheritance_allowed,
        false,
    );

    const reused = fixtureBundle();
    reused.receipts[1].step_binding.lease =
        clone(reused.receipts[0].step_binding.lease);
    refreshReceipt(reused.receipts[1]);
    reused.flow.nodes[1].lease_binding =
        clone(reused.receipts[1].step_binding.lease);
    refreshFlowReceiptBindings(reused.flow, reused.receipts);
    reused.flow.flow_fingerprint_sha256 = taskFlowRunFingerprint(reused.flow);
    assert.throws(
        () => validateTaskFlowRunV1(reused, OPTIONS),
        (error) => error.code === "STEP_LEASE_REUSE",
    );
});

test("completed write step binds one exact 002D receipt after Owner review", () => {
    const bundle = completedBundle();
    validateWorkboardCardV1(bundle, OPTIONS);
    const writeReceipt = bundle.receipts[2];
    assert.equal(
        writeReceipt.external_action_receipt_binding.receipt_id,
        externalReceiptFixture.receipt_id,
    );
    assert.equal(
        writeReceipt.external_action_receipt_binding.receipt_fingerprint_sha256,
        externalReceiptFixture.receipt_fingerprint_sha256,
    );
    assert.equal(writeReceipt.public_projection.external_write_performed, true);
    assert.equal(writeReceipt.constraints.noderooms_public_write_performed, false);
    assert.equal(bundle.card.openclaw_card.status, "done");
    assert.equal(bundle.flow.status, "succeeded");
});

test("Owner automation, wildcard authority, shared leases, and public write fail closed", () => {
    const cases = [
        (workItem) => { workItem.owner_policy.automatic_owner_decision_allowed = true; },
        (workItem) => { workItem.constraints.owner_decision_automated = true; },
        (workItem) => { workItem.constraints.shared_lease_allowed = true; },
        (workItem) => { workItem.constraints.wildcard_scope_allowed = true; },
        (workItem) => { workItem.constraints.public_write_allowed = true; },
        (workItem) => {
            workItem.connector_allowlist[0].resource.selector.base_ref = "release/*";
        },
    ];
    for (const mutate of cases) {
        const workItem = clone(workItemFixture);
        mutate(workItem);
        assert.throws(() => validateWorkItemV1(workItem, OPTIONS));
    }
});

test("Workboard remains a local execution mirror and cannot grant authority", () => {
    const bundle = fixtureBundle();
    assert.equal(bundle.card.constraints.canonical_source, "noderooms_workdesk");
    assert.equal(bundle.card.constraints.card_can_grant_authority, false);
    assert.equal(bundle.card.constraints.local_edits_are_proposals, true);
    assert.equal(bundle.card.claim.token_redacted, true);
    assert.equal(bundle.card.claim.token_persisted, false);

    const authorityDrift = fixtureBundle();
    authorityDrift.card.constraints.card_can_grant_authority = true;
    assert.throws(
        () => validateWorkboardCardV1(authorityDrift, OPTIONS),
        (error) => error.code === "INVALID_BOOLEAN",
    );
});

test("pause, cancel, and revision conflict policies stop new work", () => {
    const bundle = fixtureBundle();
    assert.equal(bundle.flow.cancellation.no_new_tasks_when_requested, true);
    assert.equal(bundle.flow.cancellation.cancel_is_sticky, true);
    assert.equal(bundle.flow.constraints.expected_revision_required, true);
    assert.equal(
        bundle.flow.checkpoint.stale_write_strategy,
        "reject_revision_conflict_reread",
    );

    const weakened = fixtureBundle();
    weakened.flow.cancellation.no_new_tasks_when_requested = false;
    assert.throws(
        () => validateTaskFlowRunV1(weakened, OPTIONS),
        (error) => error.code === "INVALID_BOOLEAN",
    );
});

test("contract-only records never authorize live dispatch", () => {
    const bundle = fixtureBundle();
    assert.throws(
        () => validateWorkboardCardV1(bundle),
        (error) => error.code === "FIXTURE_REJECTED",
    );

    const nonFixture = fixtureBundle();
    nonFixture.workItem.fixture = false;
    nonFixture.workItem.work_item_fingerprint_sha256 =
        workItemFingerprint(nonFixture.workItem);
    assert.throws(
        () => validateWorkItemV1(nonFixture.workItem, {
            allowFixture: false,
            allowContractOnly: false,
            now: NOW,
        }),
        (error) => error.code === "LIVE_DISPATCH_PROHIBITED",
    );
});

test("003A stores no claim token, session key, provider credential, prompt, or raw result", () => {
    const bundle = fixtureBundle();
    for (const value of [
        bundle.workItem,
        ...bundle.receipts,
        bundle.flow,
        bundle.card,
    ]) {
        assertNoSensitiveMaterial(value);
    }
});

test("003A module is packaged but disconnected from live OpenClaw hooks", async () => {
    const index = await readFile(new URL("../src/index.js", import.meta.url), "utf8");
    const manifest = await readJson("openclaw.plugin.json");
    assert.doesNotMatch(index, /workdesk-workboard-task-flow/);
    assert.deepEqual(
        manifest.configSchema.properties.trustLayer.properties.mode.enum,
        ["off", "observe"],
    );
    assert.equal(workItemFixture.live_dispatch_allowed, false);
    assert.equal(flowFixture.live_dispatch_allowed, false);
    assert.equal(cardFixture.live_dispatch_allowed, false);
});

test("mission bundle rejects binding, revision, proof, and fingerprint drift", () => {
    const cases = [
        (bundle) => { bundle.flow.work_item_binding.mission_id =
            "nrmission_99999999999999999999999999999999"; },
        (bundle) => { bundle.card.task_flow_binding.flow_revision = 4; },
        (bundle) => { bundle.card.openclaw_card.agent_id = "agent-other"; },
        (bundle) => { bundle.receipts[0].step_binding.step_id = "draft"; },
        (bundle) => { bundle.flow.nodes[0].receipt_binding.receipt_fingerprint_sha256 =
            "sha256:9999999999999999999999999999999999999999999999999999999999999999"; },
        (bundle) => { bundle.card.card_fingerprint_sha256 =
            "sha256:9999999999999999999999999999999999999999999999999999999999999999"; },
    ];
    for (const mutate of cases) {
        const bundle = fixtureBundle();
        mutate(bundle);
        const result = evaluateWorkMissionV1(bundle, OPTIONS);
        assert.equal(result.decision, "block_invalid_work_mission");
        assert.equal(result.live_dispatch_allowed, false);
    }
});

test("canonical fingerprints cover every authority and state projection", () => {
    const bundle = fixtureBundle();
    assert.equal(
        bundle.workItem.work_item_fingerprint_sha256,
        workItemFingerprint(bundle.workItem),
    );
    for (const receipt of bundle.receipts) {
        assert.equal(
            receipt.receipt_fingerprint_sha256,
            workStepReceiptFingerprint(receipt),
        );
    }
    assert.equal(
        bundle.flow.flow_fingerprint_sha256,
        taskFlowRunFingerprint(bundle.flow),
    );
    assert.equal(
        bundle.card.card_fingerprint_sha256,
        workboardCardFingerprint(bundle.card),
    );
    assert.equal(
        bundle.card.work_item_binding.create_idempotency_key_sha256,
        sha256Fingerprint({
            mission_id: bundle.workItem.mission_id,
            work_item_id: bundle.workItem.work_item_id,
            mapping_revision: bundle.card.mapping_revision,
        }),
    );
});
