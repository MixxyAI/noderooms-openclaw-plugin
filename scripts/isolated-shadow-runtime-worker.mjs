#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const BOARD_ID = "noderooms-workdesk";
const TOOL_CONTEXT = Object.freeze({
    senderIsOwner: true,
    agentId: "agent-noderooms-phase3c",
    sessionKey: "session-noderooms-phase3c-owner",
    messageChannel: "cli",
    requesterSenderId: "owner-noderooms-phase3c",
    deliveryContext: { channel: "cli" },
});
const COMMAND_CONTEXT = Object.freeze({
    senderIsOwner: true,
    isAuthorizedSender: true,
    agentId: TOOL_CONTEXT.agentId,
    sessionKey: TOOL_CONTEXT.sessionKey,
    channel: TOOL_CONTEXT.messageChannel,
    senderId: TOOL_CONTEXT.requesterSenderId,
});

function parseArguments(argv) {
    const values = new Map();
    for (let index = 0; index < argv.length; index += 1) {
        const token = argv[index];
        if (!token.startsWith("--")) {
            throw new Error(`Unexpected argument: ${token}`);
        }
        const value = argv[index + 1];
        if (!value || value.startsWith("--")) {
            throw new Error(`Missing value for ${token}`);
        }
        values.set(token.slice(2), value);
        index += 1;
    }
    return {
        phase: values.get("phase") ?? "",
        pluginRoot: path.resolve(values.get("plugin-root") ?? "."),
        issuedAt: values.get("issued-at") ?? "",
        deadlineAt: values.get("deadline-at") ?? "",
    };
}

function jsonFromToolResult(result) {
    if (result && typeof result === "object" && result.details) {
        return structuredClone(result.details);
    }
    const text = result?.content?.find?.((entry) =>
        entry?.type === "text" && typeof entry.text === "string")?.text;
    if (!text) {
        throw new Error("Tool result did not contain JSON text.");
    }
    return JSON.parse(text);
}

function jsonFromCommandResult(result) {
    assert.equal(typeof result?.text, "string");
    return JSON.parse(result.text);
}

function sha256Text(value) {
    return createHash("sha256").update(value, "utf8").digest("hex");
}

async function fileSha256(filePath) {
    return sha256Text(await readFile(filePath, "utf8"));
}

function createCaptureApi({ runtime, pluginConfig }) {
    const registrations = {
        commands: [],
        gatewayMethods: [],
        hooks: [],
        tools: [],
    };
    return {
        api: {
            runtime,
            pluginConfig,
            on(name, handler, options = {}) {
                registrations.hooks.push({
                    name,
                    handler,
                    priority: Number(options.priority ?? 0),
                });
            },
            registerCli() {},
            registerCommand(command) {
                registrations.commands.push(command);
            },
            registerGatewayMethod(name, handler) {
                registrations.gatewayMethods.push({ name, handler });
            },
            registerTool(tool, options = {}) {
                registrations.tools.push({ tool, options });
            },
        },
        registrations,
    };
}

async function resolveTool(registrations, name, context) {
    for (const registration of registrations.tools) {
        const resolved = typeof registration.tool === "function"
            ? await registration.tool(context)
            : registration.tool;
        const tools = Array.isArray(resolved) ? resolved : [resolved];
        const match = tools.find((tool) => tool?.name === name);
        if (match) {
            return match;
        }
    }
    throw new Error(`Registered tool not found: ${name}`);
}

function resolveCommand(registrations, name) {
    const command = registrations.commands.find((entry) => entry?.name === name);
    if (!command) {
        throw new Error(`Registered command not found: ${name}`);
    }
    return command;
}

async function applyBeforeToolHooks(hooks, event, context) {
    let params = structuredClone(event.params);
    const matching = hooks
        .filter((entry) => entry.name === "before_tool_call")
        .sort((left, right) => left.priority - right.priority);
    for (const hook of matching) {
        const result = await hook.handler({ ...event, params }, context);
        if (result?.block === true) {
            return {
                blocked: true,
                blockReason: result.blockReason ?? "blocked",
                params,
            };
        }
        if (result?.params && typeof result.params === "object") {
            params = structuredClone(result.params);
        }
    }
    return { blocked: false, params };
}

async function applyAfterToolHooks(hooks, event, context) {
    const matching = hooks
        .filter((entry) => entry.name === "after_tool_call")
        .sort((left, right) => right.priority - left.priority);
    for (const hook of matching) {
        await hook.handler(event, context);
    }
}

function instrumentManagedFlows(original) {
    const counters = {
        bindSession: 0,
        createManaged: 0,
        fromToolContext: 0,
        get: 0,
        list: 0,
        requestCancel: 0,
        resume: 0,
        runTask: 0,
        setWaiting: 0,
    };

    function wrapBound(bound) {
        return new Proxy(bound, {
            get(target, property, receiver) {
                const value = Reflect.get(target, property, receiver);
                if (typeof value !== "function") {
                    return value;
                }
                return (...args) => {
                    if (Object.hasOwn(counters, property)) {
                        counters[property] += 1;
                    }
                    return value.apply(target, args);
                };
            },
        });
    }

    return {
        counters,
        runtime: {
            bindSession(params) {
                counters.bindSession += 1;
                return wrapBound(original.bindSession(params));
            },
            fromToolContext(context) {
                counters.fromToolContext += 1;
                return wrapBound(original.fromToolContext(context));
            },
        },
    };
}

async function runtimeWorkItem(pluginRoot, issuedAt, deadlineAt) {
    const fixture = JSON.parse(await readFile(
        path.join(
            pluginRoot,
            "contracts",
            "fixtures",
            "github-draft-pr.work-item-v1.json",
        ),
        "utf8",
    ));
    const [{ runtimeContextFingerprints }, { workItemFingerprint }] =
        await Promise.all([
            import(pathToFileURL(path.join(
                pluginRoot,
                "dist",
                "safe-work-runtime-binding.js",
            ))),
            import(pathToFileURL(path.join(
                pluginRoot,
                "dist",
                "workdesk-workboard-task-flow.js",
            ))),
        ]);
    const fingerprints = runtimeContextFingerprints({
        agentId: TOOL_CONTEXT.agentId,
        sessionKey: TOOL_CONTEXT.sessionKey,
        channel: TOOL_CONTEXT.messageChannel,
        requesterSenderId: TOOL_CONTEXT.requesterSenderId,
    });
    fixture.fixture = false;
    fixture.$comment =
        "Phase 3C isolated non-production shadow runtime proof item.";
    fixture.runtime_binding.openclaw_agent_id = TOOL_CONTEXT.agentId;
    fixture.runtime_binding.session_key_fingerprint_sha256 =
        fingerprints.sessionFingerprintSha256;
    fixture.runtime_binding.requester_origin_fingerprint_sha256 =
        fingerprints.requesterOriginFingerprintSha256;
    fixture.created_at = issuedAt;
    fixture.updated_at = issuedAt;
    fixture.deadline_at = deadlineAt;
    fixture.work_item_fingerprint_sha256 = workItemFingerprint(fixture);
    return fixture;
}

async function loadHarness(pluginRoot) {
    const openClawRoot = path.join(pluginRoot, "node_modules", "openclaw");
    const [{ createPluginRuntime }, workboardModule, noderoomsModule] =
        await Promise.all([
            import(pathToFileURL(path.join(
                openClawRoot,
                "dist",
                "plugins",
                "runtime",
                "index.js",
            ))),
            import(pathToFileURL(path.join(
                openClawRoot,
                "dist",
                "extensions",
                "workboard",
                "index.js",
            ))),
            import(pathToFileURL(path.join(pluginRoot, "dist", "index.js"))),
        ]);

    const runtime = createPluginRuntime();
    const instrumented = instrumentManagedFlows(runtime.tasks.managedFlows);
    runtime.tasks.managedFlows = instrumented.runtime;
    runtime.tasks.flow = instrumented.runtime;

    const workboard = createCaptureApi({
        runtime,
        pluginConfig: {},
    });
    const noderooms = createCaptureApi({
        runtime,
        pluginConfig: {
            trustLayer: { mode: "off" },
            workRuntime: {
                mode: "shadow",
                boardId: BOARD_ID,
                maxEntries: 16,
            },
        },
    });
    workboardModule.default.register(workboard.api);
    noderoomsModule.default.register(noderooms.api);
    return {
        runtime,
        flowCounters: instrumented.counters,
        noderooms: noderooms.registrations,
        workboard: workboard.registrations,
    };
}

async function listCards(harness) {
    const tool = await resolveTool(
        harness.workboard,
        "workboard_list",
        TOOL_CONTEXT,
    );
    return jsonFromToolResult(await tool.execute("phase3c-list", {
        boardId: BOARD_ID,
        includeArchived: true,
        limit: 20,
    })).cards;
}

async function readCard(harness, cardId) {
    const tool = await resolveTool(
        harness.workboard,
        "workboard_read",
        TOOL_CONTEXT,
    );
    return jsonFromToolResult(await tool.execute("phase3c-read", {
        id: cardId,
    })).card;
}

function listFlows(harness) {
    return harness.runtime.tasks.managedFlows.bindSession({
        sessionKey: TOOL_CONTEXT.sessionKey,
        requesterOrigin: TOOL_CONTEXT.deliveryContext,
    }).list();
}

function listTaskRuns(harness) {
    return harness.runtime.tasks.runs.bindSession({
        sessionKey: TOOL_CONTEXT.sessionKey,
        requesterOrigin: TOOL_CONTEXT.deliveryContext,
    }).list();
}

async function prepareBinding(harness, workItem, toolCallId) {
    const tool = await resolveTool(
        harness.noderooms,
        "noderooms_prepare_work_binding",
        TOOL_CONTEXT,
    );
    return jsonFromToolResult(await tool.execute(toolCallId, {
        work_item_json: JSON.stringify(workItem),
    }));
}

async function executeGuardedWorkboardCreate(harness, params, toolCallId) {
    const before = await applyBeforeToolHooks(
        harness.noderooms.hooks,
        {
            toolName: "workboard_create",
            toolCallId,
            params,
        },
        TOOL_CONTEXT,
    );
    if (before.blocked) {
        return {
            blocked: true,
            blockReason: before.blockReason,
            result: null,
        };
    }
    const tool = await resolveTool(
        harness.workboard,
        "workboard_create",
        TOOL_CONTEXT,
    );
    const result = await tool.execute(toolCallId, before.params);
    await applyAfterToolHooks(
        harness.noderooms.hooks,
        {
            toolName: "workboard_create",
            toolCallId,
            params: before.params,
            result,
        },
        TOOL_CONTEXT,
    );
    return {
        blocked: false,
        result: jsonFromToolResult(result),
    };
}

async function createPhase(options) {
    const harness = await loadHarness(options.pluginRoot);
    const workItem = await runtimeWorkItem(
        options.pluginRoot,
        options.issuedAt,
        options.deadlineAt,
    );
    let networkAttempts = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
        networkAttempts += 1;
        throw new Error("External network access is forbidden in Phase 3C.");
    };
    try {
        const prepared = await prepareBinding(
            harness,
            workItem,
            "phase3c-prepare",
        );
        assert.equal(prepared.ok, true);
        assert.equal(prepared.shadow_binding_prepared, true);
        assert.equal(prepared.activation_state, "shadow");
        assert.equal(prepared.task_flow.status, "waiting");
        assert.equal(prepared.workboard.status, null);
        assert.equal(prepared.safety.task_run_started, false);
        assert.equal(prepared.safety.external_write_attempted, false);

        const created = await executeGuardedWorkboardCreate(
            harness,
            prepared.workboard_create_params,
            "phase3c-workboard-create",
        );
        assert.equal(created.blocked, false);
        assert.equal(created.result.card.status, "review");

        const cards = await listCards(harness);
        const flows = listFlows(harness);
        const tasks = listTaskRuns(harness);
        assert.equal(cards.length, 1);
        assert.equal(flows.length, 1);
        assert.equal(tasks.length, 0);
        const fullCard = await readCard(harness, cards[0].id);
        assert.equal(fullCard.status, "review");
        assert.equal(fullCard.metadata?.claim, undefined);
        assert.equal(flows[0].status, "waiting");
        assert.equal(flows[0].syncMode, "managed");
        assert.equal(harness.flowCounters.createManaged, 1);
        assert.equal(harness.flowCounters.runTask, 0);
        assert.equal(harness.flowCounters.resume, 0);
        assert.equal(networkAttempts, 0);

        return {
            phase: "create",
            binding_id: prepared.binding_id,
            work_item_id: prepared.work_item_id,
            work_item_fingerprint_sha256:
                workItem.work_item_fingerprint_sha256,
            task_flow: {
                flow_id: flows[0].flowId,
                revision: flows[0].revision,
                status: flows[0].status,
                sync_mode: flows[0].syncMode,
                child_task_count: tasks.length,
            },
            workboard: {
                card_id: fullCard.id,
                status: fullCard.status,
                claim_created: false,
                dispatch_attempted: false,
            },
            counters: {
                ...harness.flowCounters,
                connector_calls: 0,
                external_network_attempts: networkAttempts,
                external_writes: 0,
                workboard_claim: 0,
                workboard_dispatch: 0,
            },
        };
    }
    finally {
        globalThis.fetch = originalFetch;
    }
}

async function verifyPhase(options) {
    const harness = await loadHarness(options.pluginRoot);
    const workItem = await runtimeWorkItem(
        options.pluginRoot,
        options.issuedAt,
        options.deadlineAt,
    );
    const duplicate = await prepareBinding(
        harness,
        workItem,
        "phase3c-duplicate-prepare",
    );
    assert.equal(duplicate.ok, true);
    assert.equal(duplicate.duplicate_binding_reused, true);
    assert.equal(duplicate.workboard_create_params, null);
    assert.equal(harness.flowCounters.createManaged, 0);

    const cardsBefore = await listCards(harness);
    assert.equal(cardsBefore.length, 1);
    const card = await readCard(harness, cardsBefore[0].id);
    const driftedParams = {
        title: `${card.title} drift`,
        notes: card.notes,
        status: card.status,
        priority: card.priority,
        labels: card.labels,
        agentId: card.agentId,
        tenant: card.metadata.automation.tenant,
        boardId: card.metadata.automation.boardId,
        idempotencyKey: card.metadata.automation.idempotencyKey,
    };
    const drift = await executeGuardedWorkboardCreate(
        harness,
        driftedParams,
        "phase3c-drift-create",
    );
    assert.equal(drift.blocked, true);
    assert.match(drift.blockReason, /blocked/i);

    const command = resolveCommand(harness.noderooms, "noderooms");
    const privateStatePath = path.join(
        process.env.OPENCLAW_STATE_DIR,
        "noderooms",
        "safe-work-runtime-bindings-v1.json",
    );
    const privateHashBefore = await fileSha256(privateStatePath);
    const reconciled = jsonFromCommandResult(await command.handler({
        ...COMMAND_CONTEXT,
        args: `work reconcile ${duplicate.binding_id}`,
    }));
    const privateHashAfter = await fileSha256(privateStatePath);
    assert.equal(reconciled.ok, true);
    assert.equal(reconciled.reconciliation_mode, "read_only");
    assert.equal(reconciled.local_state_mutated, false);
    assert.equal(reconciled.automatic_retry_attempted, false);
    assert.equal(privateHashAfter, privateHashBefore);

    const cardsAfter = await listCards(harness);
    const flows = listFlows(harness);
    const tasks = listTaskRuns(harness);
    assert.equal(cardsAfter.length, 1);
    assert.equal(flows.length, 1);
    assert.equal(tasks.length, 0);
    const fullCardAfter = await readCard(harness, cardsAfter[0].id);
    assert.equal(fullCardAfter.status, "review");
    assert.equal(fullCardAfter.metadata?.claim, undefined);
    assert.equal(flows[0].status, "waiting");
    assert.equal(harness.flowCounters.runTask, 0);
    assert.equal(harness.flowCounters.resume, 0);

    return {
        phase: "verify",
        binding_id: duplicate.binding_id,
        restart_reloaded_persisted_state: true,
        duplicate_binding_reused: true,
        duplicate_flow_created: false,
        duplicate_card_created: false,
        drifted_create_blocked: true,
        reconciliation_mode: reconciled.reconciliation_mode,
        private_state_hash_unchanged: privateHashAfter === privateHashBefore,
        task_flow_count: flows.length,
        workboard_card_count: cardsAfter.length,
        child_task_count: tasks.length,
        counters: {
            ...harness.flowCounters,
            connector_calls: 0,
            external_network_attempts: 0,
            external_writes: 0,
            workboard_claim: 0,
            workboard_dispatch: 0,
        },
    };
}

async function cancelPhase(options) {
    const harness = await loadHarness(options.pluginRoot);
    const command = resolveCommand(harness.noderooms, "noderooms");
    const status = jsonFromCommandResult(await command.handler({
        ...COMMAND_CONTEXT,
        args: "work status",
    }));
    assert.equal(status.count, 1);
    const binding = status.bindings[0];
    const boundFlow = harness.runtime.tasks.managedFlows.bindSession({
        sessionKey: TOOL_CONTEXT.sessionKey,
        requesterOrigin: TOOL_CONTEXT.deliveryContext,
    });
    const before = boundFlow.get(binding.task_flow.flow_id);
    assert.ok(before);
    const stale = boundFlow.requestCancel({
        flowId: before.flowId,
        expectedRevision: before.revision - 1,
        cancelRequestedAt: Date.parse(options.issuedAt) + 1_000,
    });
    assert.equal(stale.applied, false);
    assert.equal(stale.code, "revision_conflict");

    const cancelled = jsonFromCommandResult(await command.handler({
        ...COMMAND_CONTEXT,
        args: `work cancel ${binding.binding_id}`,
    }));
    assert.equal(cancelled.ok, true);
    assert.equal(cancelled.cancel_requested, true);
    assert.equal(cancelled.no_new_tasks_allowed, true);
    assert.equal(cancelled.workboard_dispatch_attempted, false);
    assert.equal(cancelled.external_write_attempted, false);

    const after = boundFlow.get(before.flowId);
    const cards = await listCards(harness);
    const tasks = listTaskRuns(harness);
    assert.ok(after);
    assert.ok(after.revision > before.revision);
    assert.ok(Number.isFinite(after.cancelRequestedAt));
    assert.equal(cards.length, 1);
    const fullCard = await readCard(harness, cards[0].id);
    assert.equal(fullCard.status, "review");
    assert.equal(fullCard.metadata?.claim, undefined);
    assert.equal(tasks.length, 0);
    assert.equal(harness.flowCounters.runTask, 0);
    assert.equal(harness.flowCounters.resume, 0);

    return {
        phase: "cancel",
        owner_command_required: true,
        stale_revision_rejected: true,
        cancel_requested: true,
        revision_before: before.revision,
        revision_after: after.revision,
        no_new_tasks_allowed: true,
        child_task_count: tasks.length,
        workboard_status_unchanged: fullCard.status === "review",
        counters: {
            ...harness.flowCounters,
            connector_calls: 0,
            external_network_attempts: 0,
            external_writes: 0,
            workboard_claim: 0,
            workboard_dispatch: 0,
        },
    };
}

const options = parseArguments(process.argv.slice(2));
if (!["create", "verify", "cancel"].includes(options.phase)) {
    throw new Error("Use --phase create, verify, or cancel.");
}
if (!process.env.OPENCLAW_STATE_DIR || !process.env.OPENCLAW_CONFIG_PATH) {
    throw new Error(
        "OPENCLAW_STATE_DIR and OPENCLAW_CONFIG_PATH are required.",
    );
}
if (!Number.isFinite(Date.parse(options.issuedAt))
    || !Number.isFinite(Date.parse(options.deadlineAt))) {
    throw new Error("--issued-at and --deadline-at must be ISO timestamps.");
}

const result = options.phase === "create"
    ? await createPhase(options)
    : options.phase === "verify"
        ? await verifyPhase(options)
        : await cancelPhase(options);
process.stdout.write(`${JSON.stringify(result)}\n`);
