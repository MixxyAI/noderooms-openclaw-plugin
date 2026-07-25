import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    runIsolatedShadowRuntimeE2E,
} from "../scripts/isolated-shadow-runtime-e2e.mjs";

const pluginRoot = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
);

let proofPromise;
function proof() {
    proofPromise ??= runIsolatedShadowRuntimeE2E({ pluginRoot });
    return proofPromise;
}

test("003C pins and loads the exact supported OpenClaw host", async () => {
    const result = await proof();
    assert.equal(result.ok, true);
    assert.equal(
        result.contract_version,
        "noderooms-phase3c-isolated-shadow-runtime-e2e-v1",
    );
    assert.equal(result.host.openclaw_version, "2026.7.1-2");
    assert.equal(result.host.plugin_version, "1.3.0-beta.2-dev.1");
    assert.equal(result.host.exact_host_version_pinned, true);
});

test("003C uses exact isolated state, config, and workspace paths", async () => {
    const { isolation } = await proof();
    assert.equal(isolation.exact_state_env_used, true);
    assert.equal(isolation.exact_config_env_used, true);
    assert.equal(isolation.isolated_workspace_configured, true);
    assert.equal(isolation.default_config_unchanged, true);
});

test("003C exercises the real OpenClaw plugin loader", async () => {
    const { loader } = await proof();
    assert.equal(loader.noderooms_status, "loaded");
    assert.equal(loader.workboard_status, "loaded");
    assert.equal(loader.linked_source_install, true);
    assert.equal(loader.noderooms_tool_count, 14);
    assert.equal(loader.noderooms_hook_count, 6);
});

test("003C creates exactly one waiting managed Task Flow", async () => {
    const flow = (await proof()).primary.final_task_flow;
    assert.equal(flow.count, 1);
    assert.equal(flow.sync_mode, "managed");
    assert.equal(flow.status, "waiting");
    assert.equal(flow.child_task_count, 0);
});

test("003C creates exactly one unclaimed review card", async () => {
    const card = (await proof()).primary.final_workboard;
    assert.equal(card.count, 1);
    assert.equal(card.status, "review");
    assert.equal(card.claim_created, false);
    assert.equal(card.dispatch_attempted, false);
});

test("003C reloads persisted state in a fresh process", async () => {
    const restart = (await proof()).primary.restart_verify;
    assert.equal(restart.restart_reloaded_persisted_state, true);
    assert.equal(restart.task_flow_count, 1);
    assert.equal(restart.workboard_card_count, 1);
    assert.equal(restart.child_task_count, 0);
});

test("003C reuses the binding without duplicate flow or card creation", async () => {
    const restart = (await proof()).primary.restart_verify;
    assert.equal(restart.duplicate_binding_reused, true);
    assert.equal(restart.duplicate_flow_created, false);
    assert.equal(restart.duplicate_card_created, false);
});

test("003C blocks byte-drifted Workboard create parameters", async () => {
    assert.equal(
        (await proof()).primary.restart_verify.drifted_create_blocked,
        true,
    );
});

test("003C reconcile is read-only and leaves private state unchanged", async () => {
    const restart = (await proof()).primary.restart_verify;
    assert.equal(restart.reconciliation_mode, "read_only");
    assert.equal(restart.private_state_hash_unchanged, true);
});

test("003C rejects a stale Task Flow cancellation revision", async () => {
    const cancellation = (await proof()).cancellation.proof;
    assert.equal(cancellation.owner_command_required, true);
    assert.equal(cancellation.stale_revision_rejected, true);
    assert.ok(cancellation.revision_after > cancellation.revision_before);
});

test("003C Owner cancel remains taskless and leaves the card in review", async () => {
    const cancellation = (await proof()).cancellation;
    assert.equal(cancellation.cancel_requested, true);
    assert.equal(cancellation.proof.no_new_tasks_allowed, true);
    assert.equal(cancellation.proof.child_task_count, 0);
    assert.equal(cancellation.proof.workboard_status_unchanged, true);
    assert.equal(cancellation.workboard_status, "review");
});

test("003C starts no Task Run and never resumes a Task Flow", async () => {
    const safety = (await proof()).safety;
    assert.equal(safety.task_run_started, false);
    assert.equal(safety.task_flow_resume_attempted, false);
});

test("003C never claims or dispatches Workboard work", async () => {
    const safety = (await proof()).safety;
    assert.equal(safety.workboard_claim_attempted, false);
    assert.equal(safety.workboard_dispatch_attempted, false);
});

test("003C performs no connector call, network request, or external write", async () => {
    const safety = (await proof()).safety;
    assert.equal(safety.connector_call_attempted, false);
    assert.equal(safety.external_network_attempted, false);
    assert.equal(safety.external_write_attempted, false);
    assert.equal(safety.automatic_retry_attempted, false);
});

test("003C evidence contains no raw work content, credentials, or claim token", async () => {
    const safety = (await proof()).safety;
    assert.equal(safety.raw_work_content_in_evidence, false);
    assert.equal(safety.provider_credentials_in_evidence, false);
    assert.equal(safety.claim_token_in_evidence, false);
});

test("003C starts no Gateway and makes no production change", async () => {
    const result = await proof();
    assert.equal(result.isolation.gateway_started, false);
    assert.equal(result.isolation.gateway_restart_attempted, false);
    assert.equal(result.safety.production_modified, false);
});

test("003C removes all isolated runtime state after proof", async () => {
    const rollback = (await proof()).rollback;
    assert.equal(rollback.isolated_state_removal_attempted, true);
    assert.equal(rollback.temp_root_removed, true);
    console.log("NR_OC_WORK_003C_RUNTIME_E2E=PASS");
});
