import { readFile } from "node:fs/promises";

import {
    evaluateWorkMissionV1,
    validateMissionSet,
    validateWorkboardCardV1,
} from "../src/workdesk-workboard-task-flow.js";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const OPTIONS = Object.freeze({
    allowFixture: true,
    allowContractOnly: true,
    now: Date.parse("2026-07-24T17:20:00Z"),
});

export async function buildPhase3ClosureProof() {
    const [workItem, flow, card, researchReceipt, draftReceipt] =
        await Promise.all([
            readJson("contracts/fixtures/github-draft-pr.work-item-v1.json"),
            readJson("contracts/fixtures/github-draft-pr.task-flow-binding-v1.json"),
            readJson("contracts/fixtures/github-draft-pr.workboard-binding-v1.json"),
            readJson("contracts/fixtures/github-draft-pr.research-work-receipt-v1.json"),
            readJson("contracts/fixtures/github-draft-pr.draft-work-receipt-v1.json"),
        ]);

    const receipts = [researchReceipt, draftReceipt];
    const mission = { workItem, flow, card, receipts };
    const mapping = validateMissionSet([mission], OPTIONS);
    validateWorkboardCardV1(mission, OPTIONS);
    const evaluation = evaluateWorkMissionV1(mission, OPTIONS);
    const executableSteps = workItem.steps.filter((step) => step.kind === "task");
    const completedNodes = flow.nodes.filter((node) => node.status === "completed");
    const waitingWriteNode = flow.nodes.find(
        (node) => node.step_id === "create_draft_pr",
    );
    const leaseIds = completedNodes.map((node) => node.lease_binding?.lease_id);
    const receiptIds = completedNodes.map((node) => node.receipt_binding?.receipt_id);
    const artifactIds = receipts.flatMap(
        (receipt) => receipt.artifacts.map((artifact) => artifact.artifact_id),
    );

    return Object.freeze({
        contract_version: "noderooms-phase3-closure-proof-v1",
        proof_time: "2026-07-24T17:20:00Z",
        canonical_binding: Object.freeze({
            work_item_id: workItem.work_item_id,
            mission_id: workItem.mission_id,
            noderooms_agent_id: workItem.agent_binding.noderooms_agent_id,
            passport_id: workItem.agent_binding.passport_id,
            owner_binding_id: workItem.owner_policy.owner_binding_id,
            runtime_binding_id: workItem.runtime_binding.binding_id,
            canonical_source: card.constraints.canonical_source,
        }),
        owner_initiation: Object.freeze({
            verified_human_owner_required:
                workItem.owner_policy.verified_human_owner_required,
            automatic_owner_decision_allowed:
                workItem.owner_policy.automatic_owner_decision_allowed,
            owner_review_step_id: workItem.owner_policy.owner_review_step_id,
            owner_review_waiting: evaluation.owner_review_waiting,
            claim_released: card.claim.state === "released"
                && card.handoff.claim_released,
        }),
        multi_step_flow: Object.freeze({
            ordered_step_ids: [...workItem.workflow.ordered_step_ids],
            executable_step_count: executableSteps.length,
            completed_step_ids: completedNodes.map((node) => node.step_id),
            current_step_id: flow.current_step_id,
            flow_status: flow.status,
            restart_reconciled: evaluation.restart_reconciled,
            reconciliation_mode: flow.checkpoint.reconciliation_mode,
        }),
        per_step_authority: Object.freeze({
            completed_lease_ids: leaseIds,
            completed_receipt_ids: receiptIds,
            distinct_lease_count: new Set(leaseIds).size,
            distinct_receipt_count: new Set(receiptIds).size,
            shared_lease_allowed: workItem.constraints.shared_lease_allowed,
            subagent_privilege_inheritance_allowed:
                workItem.constraints.subagent_privilege_inheritance_allowed,
            waiting_write_step_id: waitingWriteNode.step_id,
            waiting_write_step_status: waitingWriteNode.status,
            waiting_write_lease_present: waitingWriteNode.lease_binding !== null,
            waiting_write_receipt_present: waitingWriteNode.receipt_binding !== null,
        }),
        workdesk_history: Object.freeze({
            work_receipt_ids: [...card.proof_refs.work_receipt_ids],
            artifact_ids: [...card.proof_refs.artifact_ids],
            receipt_artifact_ids: artifactIds,
            public_safe_receipt_count: receipts.filter(
                (receipt) => receipt.public_projection.safe_for_public,
            ).length,
            raw_work_content_persisted:
                workItem.receipt_policy.raw_work_content_persisted,
            provider_credentials_included: receipts.some(
                (receipt) =>
                    receipt.public_projection.provider_credentials_included,
            ),
        }),
        safety: Object.freeze({
            one_to_one_mapping: mapping.one_to_one_mapping,
            live_dispatch_allowed: evaluation.live_dispatch_allowed,
            workboard_can_grant_authority:
                workItem.constraints.workboard_can_grant_authority,
            public_write_allowed: workItem.constraints.public_write_allowed,
            automatic_external_write_retry_allowed:
                workItem.constraints.automatic_external_write_retry_allowed,
            task_run_started: false,
            task_flow_resume_attempted: false,
            workboard_claim_attempted: false,
            workboard_dispatch_attempted: false,
            connector_call_attempted: false,
            external_network_attempted: false,
            external_write_attempted: false,
            production_modified: false,
        }),
        closure: Object.freeze({
            decision: evaluation.decision,
            reason_code: evaluation.reason_code,
            phase3_acceptance: "pass",
            phase4_authority_granted: false,
        }),
    });
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
    process.stdout.write(
        `${JSON.stringify(await buildPhase3ClosureProof(), null, 2)}\n`,
    );
}
