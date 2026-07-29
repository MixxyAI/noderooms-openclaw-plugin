import test from "node:test";
import assert from "node:assert/strict";

import {
    buildPhase3ClosureProof,
} from "../scripts/phase3-closure-proof.mjs";

let proofPromise;
function proof() {
    proofPromise ??= buildPhase3ClosureProof();
    return proofPromise;
}

test("Phase 3 Closure preserves one canonical Workdesk mission binding", async () => {
    const result = await proof();
    assert.equal(result.contract_version, "noderooms-phase3-closure-proof-v1");
    assert.equal(result.canonical_binding.canonical_source, "noderooms_workdesk");
    assert.equal(result.safety.one_to_one_mapping, true);
});

test("OWNER_INITIATED_MULTI_STEP_FLOW=PASS", async () => {
    const result = await proof();
    assert.equal(result.owner_initiation.verified_human_owner_required, true);
    assert.equal(result.owner_initiation.automatic_owner_decision_allowed, false);
    assert.equal(result.owner_initiation.owner_review_waiting, true);
    assert.deepEqual(result.multi_step_flow.completed_step_ids, [
        "research",
        "draft",
    ]);
    assert.equal(result.multi_step_flow.current_step_id, "owner_review");
    assert.equal(result.multi_step_flow.flow_status, "waiting");
});

test("PER_STEP_LEASE_RECEIPT=PASS", async () => {
    const result = await proof();
    assert.equal(result.per_step_authority.completed_lease_ids.length, 2);
    assert.equal(result.per_step_authority.completed_receipt_ids.length, 2);
    assert.equal(result.per_step_authority.distinct_lease_count, 2);
    assert.equal(result.per_step_authority.distinct_receipt_count, 2);
    assert.equal(result.per_step_authority.shared_lease_allowed, false);
    assert.equal(
        result.per_step_authority.subagent_privilege_inheritance_allowed,
        false,
    );
});

test("OWNER_WAIT_HANDOFF_CLAIM_RELEASE=PASS", async () => {
    const result = await proof();
    assert.equal(result.owner_initiation.claim_released, true);
    assert.equal(result.per_step_authority.waiting_write_step_id, "create_draft_pr");
    assert.equal(result.per_step_authority.waiting_write_step_status, "queued");
    assert.equal(result.per_step_authority.waiting_write_lease_present, false);
    assert.equal(result.per_step_authority.waiting_write_receipt_present, false);
});

test("NODEROOMS_WORKDESK_HISTORY=PASS", async () => {
    const result = await proof();
    assert.deepEqual(
        result.workdesk_history.work_receipt_ids,
        result.per_step_authority.completed_receipt_ids,
    );
    assert.deepEqual(
        result.workdesk_history.artifact_ids,
        result.workdesk_history.receipt_artifact_ids,
    );
    assert.equal(result.workdesk_history.public_safe_receipt_count, 2);
    assert.equal(result.workdesk_history.raw_work_content_persisted, false);
    assert.equal(result.workdesk_history.provider_credentials_included, false);
});

test("PHASE3_ZERO_EXTERNAL_WRITE=PASS", async () => {
    const result = await proof();
    assert.deepEqual(result.safety, {
        one_to_one_mapping: true,
        live_dispatch_allowed: false,
        workboard_can_grant_authority: false,
        public_write_allowed: false,
        automatic_external_write_retry_allowed: false,
        task_run_started: false,
        task_flow_resume_attempted: false,
        workboard_claim_attempted: false,
        workboard_dispatch_attempted: false,
        connector_call_attempted: false,
        external_network_attempted: false,
        external_write_attempted: false,
        production_modified: false,
    });
    assert.equal(result.closure.phase3_acceptance, "pass");
    assert.equal(result.closure.phase4_authority_granted, false);
    console.log("NR_OC_PHASE3_CLOSURE=PASS");
});
