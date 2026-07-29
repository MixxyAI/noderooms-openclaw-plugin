import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
    LIVE_WORK_RUNTIME_ARMED_ALLOWED,
    normalizeSafeWorkRuntimeConfig,
    runtimeContextFingerprints,
    SafeWorkRuntimeBindingController,
    workboardCreateParamsFingerprint,
} from "../src/safe-work-runtime-binding.js";
import {
    workItemFingerprint,
} from "../src/workdesk-workboard-task-flow.js";

const workItemFixture = JSON.parse(await readFile(
    new URL(
        "../contracts/fixtures/github-draft-pr.work-item-v1.json",
        import.meta.url,
    ),
    "utf8",
));

const NOW = Date.parse("2026-07-24T17:30:00Z");
const TOOL_CONTEXT = Object.freeze({
    senderIsOwner: true,
    agentId: "agent-example-openclaw",
    sessionKey: "session-example-owner-01",
    messageChannel: "telegram",
    requesterSenderId: "owner-example-01",
    deliveryContext: { channel: "telegram" },
});
const COMMAND_CONTEXT = Object.freeze({
    senderIsOwner: true,
    isAuthorizedSender: true,
    agentId: TOOL_CONTEXT.agentId,
    sessionKey: TOOL_CONTEXT.sessionKey,
    channel: TOOL_CONTEXT.messageChannel,
    senderId: TOOL_CONTEXT.requesterSenderId,
});

function clone(value) {
    return structuredClone(value);
}

function runtimeWorkItem(ctx = TOOL_CONTEXT) {
    const item = clone(workItemFixture);
    const fingerprints = runtimeContextFingerprints({
        agentId: ctx.agentId,
        sessionKey: ctx.sessionKey,
        channel: ctx.messageChannel,
        requesterSenderId: ctx.requesterSenderId,
    });
    item.fixture = false;
    item.$comment =
        "Test-only canonical non-fixture work item for the shadow runtime gate.";
    item.runtime_binding.openclaw_agent_id = ctx.agentId;
    item.runtime_binding.session_key_fingerprint_sha256 =
        fingerprints.sessionFingerprintSha256;
    item.runtime_binding.requester_origin_fingerprint_sha256 =
        fingerprints.requesterOriginFingerprintSha256;
    item.work_item_fingerprint_sha256 = workItemFingerprint(item);
    return item;
}

function createTaskRuntime() {
    const flows = new Map();
    const counters = {
        createManaged: 0,
        requestCancel: 0,
        runTask: 0,
        resume: 0,
    };

    function boundRuntime() {
        return {
            createManaged(params) {
                counters.createManaged += 1;
                const flow = {
                    flowId: `flow-noderooms-shadow-${counters.createManaged}`,
                    syncMode: "managed",
                    ownerKey: "owner-session-example",
                    controllerId: params.controllerId,
                    revision: 1,
                    status: params.status,
                    notifyPolicy: params.notifyPolicy,
                    goal: params.goal,
                    currentStep: params.currentStep,
                    stateJson: clone(params.stateJson),
                    waitJson: clone(params.waitJson),
                    createdAt: NOW,
                    updatedAt: NOW,
                };
                flows.set(flow.flowId, flow);
                return clone(flow);
            },
            get(flowId) {
                const flow = flows.get(flowId);
                return flow ? clone(flow) : undefined;
            },
            requestCancel(params) {
                counters.requestCancel += 1;
                const current = flows.get(params.flowId);
                if (!current || current.revision !== params.expectedRevision) {
                    return {
                        applied: false,
                        code: "revision_conflict",
                        current: current ? clone(current) : undefined,
                    };
                }
                const flow = {
                    ...current,
                    revision: current.revision + 1,
                    cancelRequestedAt: params.cancelRequestedAt,
                    updatedAt: params.cancelRequestedAt,
                };
                flows.set(flow.flowId, flow);
                return { applied: true, flow: clone(flow) };
            },
            runTask() {
                counters.runTask += 1;
                throw new Error("runTask must never be reached in 003B");
            },
            resume() {
                counters.resume += 1;
                throw new Error("resume must never be reached in 003B");
            },
        };
    }

    return {
        runtime: {
            fromToolContext() {
                return boundRuntime();
            },
            bindSession() {
                return boundRuntime();
            },
        },
        counters,
        flows,
    };
}

async function createHarness(mode = "shadow") {
    const directory = await mkdtemp(
        path.join(os.tmpdir(), "noderooms-work-runtime-"),
    );
    const stateFilePath = path.join(
        directory,
        "safe-work-runtime-bindings-v1.json",
    );
    const task = createTaskRuntime();
    const config = normalizeSafeWorkRuntimeConfig({
        workRuntime: {
            mode,
            boardId: "noderooms-workdesk",
            maxEntries: 16,
        },
    });
    const controller = new SafeWorkRuntimeBindingController({
        config,
        stateFilePath,
        taskRuntime: task.runtime,
        now: () => NOW,
    });
    return {
        directory,
        stateFilePath,
        task,
        config,
        controller,
        async cleanup() {
            await rm(directory, { recursive: true, force: true });
        },
    };
}

function workboardCard(params, id = "card-noderooms-shadow-01") {
    return {
        id,
        title: params.title,
        status: params.status,
        priority: params.priority,
        labels: clone(params.labels),
        agentId: params.agentId,
        metadata: {
            automation: {
                tenant: params.tenant,
                boardId: params.boardId,
                idempotencyKey: params.idempotencyKey,
            },
        },
    };
}

test("003B config exposes only off and shadow; armed activation is hard-blocked", () => {
    assert.equal(LIVE_WORK_RUNTIME_ARMED_ALLOWED, false);
    const off = normalizeSafeWorkRuntimeConfig({
        workRuntime: {
            mode: "armed",
            boardId: "NODEROOMS-WORKDESK",
            maxEntries: 9999,
        },
    });
    assert.equal(off.mode, "off");
    assert.equal(off.boardId, "noderooms-workdesk");
    assert.equal(off.maxEntries, 512);
    assert.equal(off.armedActivationAllowed, false);
    assert.equal(off.armedActivationBlocked, true);
    assert.equal(off.automaticDispatchAllowed, false);
    assert.equal(off.automaticExternalWriteAllowed, false);
    assert.equal(off.automaticRetryAllowed, false);
});

test("runtime fingerprints are deterministic and contain no raw context", () => {
    const first = runtimeContextFingerprints({
        agentId: TOOL_CONTEXT.agentId,
        sessionKey: TOOL_CONTEXT.sessionKey,
        channel: TOOL_CONTEXT.messageChannel,
        requesterSenderId: TOOL_CONTEXT.requesterSenderId,
    });
    const second = runtimeContextFingerprints({
        agentId: TOOL_CONTEXT.agentId,
        sessionKey: TOOL_CONTEXT.sessionKey,
        channel: TOOL_CONTEXT.messageChannel,
        requesterSenderId: TOOL_CONTEXT.requesterSenderId,
    });
    assert.deepEqual(first, second);
    assert.match(first.sessionFingerprintSha256, /^sha256:[a-f0-9]{64}$/);
    assert.match(
        first.requesterOriginFingerprintSha256,
        /^sha256:[a-f0-9]{64}$/,
    );
    assert.doesNotMatch(JSON.stringify(first), /session-example|owner-example/);
});

test("shadow mode requires exact authenticated Owner and runtime binding", async () => {
    const harness = await createHarness();
    try {
        const item = runtimeWorkItem();
        await assert.rejects(
            harness.controller.prepare(
                { ...TOOL_CONTEXT, senderIsOwner: false },
                JSON.stringify(item),
            ),
            (error) => error.code === "WORK_RUNTIME_OWNER_REQUIRED",
        );

        item.runtime_binding.openclaw_agent_id = "another-agent";
        item.work_item_fingerprint_sha256 = workItemFingerprint(item);
        await assert.rejects(
            harness.controller.prepare(
                TOOL_CONTEXT,
                JSON.stringify(item),
            ),
            (error) => error.code === "WORK_RUNTIME_CONTEXT_MISMATCH",
        );
        assert.equal(harness.task.counters.createManaged, 0);
    }
    finally {
        await harness.cleanup();
    }
});

test("contract fixtures and expired work items cannot enter runtime shadow", async () => {
    const harness = await createHarness();
    try {
        await assert.rejects(
            harness.controller.prepare(
                TOOL_CONTEXT,
                JSON.stringify(workItemFixture),
            ),
            (error) => error.code === "WORK_RUNTIME_WORK_ITEM_REJECTED",
        );
        const expired = runtimeWorkItem();
        expired.deadline_at = "2026-07-24T17:29:59Z";
        expired.work_item_fingerprint_sha256 = workItemFingerprint(expired);
        await assert.rejects(
            harness.controller.prepare(
                TOOL_CONTEXT,
                JSON.stringify(expired),
            ),
            (error) => error.code === "WORK_RUNTIME_WORK_ITEM_REJECTED",
        );
        assert.equal(harness.task.counters.createManaged, 0);
    }
    finally {
        await harness.cleanup();
    }
});

test("default-off mode performs no Task Flow or Workboard mutation", async () => {
    const harness = await createHarness("off");
    try {
        assert.equal(harness.controller.preflight().ok, false);
        await assert.rejects(
            harness.controller.prepare(
                TOOL_CONTEXT,
                JSON.stringify(runtimeWorkItem()),
            ),
            (error) => error.code === "WORK_RUNTIME_SHADOW_DISABLED",
        );
        const blocked = await harness.controller.beforeToolCall({
            toolName: "workboard_create",
            toolCallId: "tool-off-01",
            params: {
                title: "Blocked",
                tenant: "noderooms",
                idempotencyKey: "noderooms-work:blocked",
            },
        }, {
            agentId: TOOL_CONTEXT.agentId,
            sessionKey: TOOL_CONTEXT.sessionKey,
        });
        assert.equal(blocked.block, true);
        assert.equal(harness.task.counters.createManaged, 0);
    }
    finally {
        await harness.cleanup();
    }
});

test("prepare creates one waiting managed flow and no task, resume, connector, or dispatch", async () => {
    const harness = await createHarness();
    try {
        const result = await harness.controller.prepare(
            TOOL_CONTEXT,
            JSON.stringify(runtimeWorkItem()),
        );
        assert.equal(result.ok, true);
        assert.equal(result.activation_state, "shadow");
        assert.equal(result.state, "prepared");
        assert.equal(result.live_dispatch_allowed, false);
        assert.equal(result.task_flow.status, "waiting");
        assert.equal(result.task_flow.child_task_started, false);
        assert.equal(result.workboard.status, null);
        assert.equal(result.safety.task_run_started, false);
        assert.equal(result.safety.connector_called, false);
        assert.equal(result.safety.external_write_attempted, false);
        assert.equal(harness.task.counters.createManaged, 1);
        assert.equal(harness.task.counters.runTask, 0);
        assert.equal(harness.task.counters.resume, 0);
        assert.equal(result.workboard_create_params.status, "review");
        assert.equal(result.workboard_create_params.tenant, "noderooms");
        assert.deepEqual(result.workboard_create_params.labels, [
            "noderooms",
            "owner-review",
            "shadow-runtime",
        ]);
        assert.equal(
            workboardCreateParamsFingerprint(
                result.workboard_create_params,
            ),
            result.workboard.create_params_fingerprint_sha256,
        );

        const duplicate = await harness.controller.prepare(
            TOOL_CONTEXT,
            JSON.stringify(runtimeWorkItem()),
        );
        assert.equal(duplicate.duplicate_binding_reused, true);
        assert.equal(duplicate.binding_id, result.binding_id);
        assert.equal(harness.task.counters.createManaged, 1);
    }
    finally {
        await harness.cleanup();
    }
});

test("Workboard hook blocks parameter drift before any card create", async () => {
    const harness = await createHarness();
    try {
        const prepared = await harness.controller.prepare(
            TOOL_CONTEXT,
            JSON.stringify(runtimeWorkItem()),
        );
        const drifted = {
            ...prepared.workboard_create_params,
            status: "todo",
        };
        const decision = await harness.controller.beforeToolCall({
            toolName: "workboard_create",
            toolCallId: "tool-drift-01",
            params: drifted,
        }, {
            agentId: TOOL_CONTEXT.agentId,
            sessionKey: TOOL_CONTEXT.sessionKey,
        });
        assert.equal(decision.block, true);

        const status = await harness.controller.list(COMMAND_CONTEXT);
        assert.equal(status.bindings[0].state, "prepared");
        assert.equal(status.bindings[0].workboard.create_attempted, false);
    }
    finally {
        await harness.cleanup();
    }
});

test("one exact Workboard review card binds at most once and persists no raw context", async () => {
    const harness = await createHarness();
    try {
        const prepared = await harness.controller.prepare(
            TOOL_CONTEXT,
            JSON.stringify(runtimeWorkItem()),
        );
        const params = prepared.workboard_create_params;
        const before = await harness.controller.beforeToolCall({
            toolName: "workboard_create",
            toolCallId: "tool-bind-01",
            params,
        }, {
            agentId: TOOL_CONTEXT.agentId,
            sessionKey: TOOL_CONTEXT.sessionKey,
        });
        assert.deepEqual(before, { params });

        await harness.controller.afterToolCall({
            toolName: "workboard_create",
            toolCallId: "tool-bind-01",
            params,
            result: {
                details: {
                    card: workboardCard(params),
                },
            },
        });
        const listed = await harness.controller.list(COMMAND_CONTEXT);
        assert.equal(listed.bindings[0].state, "bound");
        assert.equal(
            listed.bindings[0].workboard.card_id,
            "card-noderooms-shadow-01",
        );
        assert.equal(listed.bindings[0].workboard.status, "review");
        assert.equal(listed.bindings[0].workboard.claim_created, false);
        assert.equal(listed.bindings[0].workboard.dispatch_attempted, false);

        const replay = await harness.controller.beforeToolCall({
            toolName: "workboard_create",
            toolCallId: "tool-bind-02",
            params,
        }, {
            agentId: TOOL_CONTEXT.agentId,
            sessionKey: TOOL_CONTEXT.sessionKey,
        });
        assert.equal(replay.block, true);

        const persisted = await readFile(harness.stateFilePath, "utf8");
        assert.doesNotMatch(persisted, /session-example-owner-01/);
        assert.doesNotMatch(persisted, /owner-example-01/);
        assert.doesNotMatch(
            persisted,
            /authorization|cookie|private_key|raw_prompt|raw_response/i,
        );
    }
    finally {
        await harness.cleanup();
    }
});

test("unknown Workboard result blocks all automatic create retries", async () => {
    const harness = await createHarness();
    try {
        const prepared = await harness.controller.prepare(
            TOOL_CONTEXT,
            JSON.stringify(runtimeWorkItem()),
        );
        const params = prepared.workboard_create_params;
        await harness.controller.beforeToolCall({
            toolName: "workboard_create",
            toolCallId: "tool-unknown-01",
            params,
        }, {
            agentId: TOOL_CONTEXT.agentId,
            sessionKey: TOOL_CONTEXT.sessionKey,
        });
        await harness.controller.afterToolCall({
            toolName: "workboard_create",
            toolCallId: "tool-unknown-01",
            params,
            error: "provider result unavailable",
        });

        const listed = await harness.controller.list(COMMAND_CONTEXT);
        assert.equal(listed.bindings[0].state, "reconcile_required");
        assert.equal(
            listed.bindings[0].safety.automatic_retry_allowed,
            false,
        );
        const retry = await harness.controller.beforeToolCall({
            toolName: "workboard_create",
            toolCallId: "tool-unknown-02",
            params,
        }, {
            agentId: TOOL_CONTEXT.agentId,
            sessionKey: TOOL_CONTEXT.sessionKey,
        });
        assert.equal(retry.block, true);
    }
    finally {
        await harness.cleanup();
    }
});

test("Gateway restart converts an interrupted card create to read-only reconciliation", async () => {
    const harness = await createHarness();
    try {
        const prepared = await harness.controller.prepare(
            TOOL_CONTEXT,
            JSON.stringify(runtimeWorkItem()),
        );
        await harness.controller.beforeToolCall({
            toolName: "workboard_create",
            toolCallId: "tool-restart-01",
            params: prepared.workboard_create_params,
        }, {
            agentId: TOOL_CONTEXT.agentId,
            sessionKey: TOOL_CONTEXT.sessionKey,
        });
        harness.controller.clearRuntimeCache();

        const beforeState = await readFile(harness.stateFilePath, "utf8");
        const reconciled = await harness.controller.reconcile(
            prepared.binding_id,
            COMMAND_CONTEXT,
        );
        const afterState = await readFile(harness.stateFilePath, "utf8");
        assert.equal(reconciled.reconciliation_mode, "read_only");
        assert.equal(reconciled.local_state_mutated, false);
        assert.equal(reconciled.automatic_retry_attempted, false);
        assert.equal(reconciled.binding.state, "reconcile_required");
        assert.match(reconciled.workboard_followup, /Do not repeat/);
        assert.equal(afterState, beforeState);
        assert.equal(harness.task.counters.createManaged, 1);
        assert.equal(harness.task.counters.requestCancel, 0);
    }
    finally {
        await harness.cleanup();
    }
});

test("Owner-only cancel is revision-gated, sticky, and stops later card creation", async () => {
    const harness = await createHarness();
    try {
        const prepared = await harness.controller.prepare(
            TOOL_CONTEXT,
            JSON.stringify(runtimeWorkItem()),
        );
        await assert.rejects(
            harness.controller.cancel(prepared.binding_id, {
                ...COMMAND_CONTEXT,
                senderIsOwner: false,
            }),
            (error) => error.code === "WORK_RUNTIME_OWNER_REQUIRED",
        );

        const cancelled = await harness.controller.cancel(
            prepared.binding_id,
            COMMAND_CONTEXT,
        );
        assert.equal(cancelled.ok, true);
        assert.equal(cancelled.owner_command_required, true);
        assert.equal(cancelled.cancel_requested, true);
        assert.equal(cancelled.no_new_tasks_allowed, true);
        assert.equal(cancelled.binding.state, "cancelled");
        assert.equal(harness.task.counters.requestCancel, 1);

        const blocked = await harness.controller.beforeToolCall({
            toolName: "workboard_create",
            toolCallId: "tool-after-cancel-01",
            params: prepared.workboard_create_params,
        }, {
            agentId: TOOL_CONTEXT.agentId,
            sessionKey: TOOL_CONTEXT.sessionKey,
        });
        assert.equal(blocked.block, true);
        assert.equal(harness.task.counters.runTask, 0);
        assert.equal(harness.task.counters.resume, 0);
    }
    finally {
        await harness.cleanup();
    }
});

test("unrelated Workboard cards remain outside the NodeRooms hook", async () => {
    const harness = await createHarness();
    try {
        const decision = await harness.controller.beforeToolCall({
            toolName: "workboard_create",
            toolCallId: "tool-unrelated-01",
            params: {
                title: "Independent local card",
                status: "todo",
                boardId: "default",
            },
        }, {
            agentId: TOOL_CONTEXT.agentId,
            sessionKey: TOOL_CONTEXT.sessionKey,
        });
        assert.equal(decision, undefined);
    }
    finally {
        await harness.cleanup();
    }
});
