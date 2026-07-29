import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import plugin from "../dist/index.js";
import {
    clearActivatedPluginRuntimeState,
    clearPluginLoaderCache,
    clearPluginRegistryLoadCache,
    loadOpenClawPlugins,
} from "../node_modules/openclaw/dist/plugins/loader.js";

const OWNER_ID = "owner-noderooms-isolation-test";
const CHANNEL = "discord";
const PLUGIN_ROOT = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
);
const GUEST_ENTER_PATH =
    "/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/enter";
const GUEST_FEED_PATH =
    "/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/feed";
const ACTION_STATUS_PATH =
    "/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/actions/status";
const ACTIONS_PATH =
    "/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/actions";

function sha256(value) {
    return createHash("sha256").update(value, "utf8").digest("hex");
}

function token(prefix, seed, length) {
    return `${prefix}${sha256(seed).slice(0, length)}`;
}

function jsonResponse(value, status = 200) {
    return new Response(JSON.stringify(value), {
        status,
        headers: { "content-type": "application/json; charset=utf-8" },
    });
}

function protocolStatus() {
    return {
        ok: true,
        gateway: "noderooms_action_idempotency",
        version: "1.3.0-alpha.1",
        protocol_version: "noderooms-action-idempotency-v1",
        protocol_ready: true,
        schema_ready: true,
        routes_ready: true,
        guest_auth_bridge_ready: true,
        write_bridge_ready: true,
        canonical_receipts_ready: true,
        server_idempotency_enforced: true,
        duplicate_write_prevented: true,
        unknown_outcome_replay_blocked: true,
        exactly_once_effect: false,
        action_types: ["guest_post", "guest_comment"],
        reservation_ttl_seconds: 7200,
        processing_stale_seconds: 120,
        idempotency_retention_days: 90,
        credentials_required_for_status: false,
        guest_pass_persisted: false,
        payload_persisted: false,
        fallback_to_legacy_direct_write: false,
    };
}

function canonicalReceipt(action) {
    return {
        ok: true,
        protocol_version: "noderooms-action-idempotency-v1",
        action_id: action.action_id,
        receipt_id: token("nrreceipt_", action.action_id, 32),
        action_type: action.action_type,
        action_status: "committed",
        idempotency_status: "created",
        fingerprint_sha256: action.fingerprint_sha256,
        server_idempotency_enforced: true,
        duplicate_write_prevented: true,
        unknown_outcome_replay_blocked: true,
        replay_blocked: true,
        public_write_attempted: true,
        dispatch_count: 1,
        exactly_once_effect: false,
        object_id: 901,
        public_url: "https://noderooms.com/noderooms-post/?post_id=901",
        error_code: null,
        error_message: null,
        created_at: "2026-07-28T16:00:00Z",
        updated_at: "2026-07-28T16:00:01Z",
        expires_at: "2026-07-28T18:00:00Z",
        committed_at: "2026-07-28T16:00:01Z",
    };
}

function createStubServer() {
    const calls = [];
    const entries = [];
    const guestPassByName = new Map();

    return {
        calls,
        entries,
        guestPassByName,
        async fetch(rawUrl, init = {}) {
            const url = new URL(rawUrl);
            const headers = new Headers(init.headers);
            const call = {
                method: init.method ?? "GET",
                path: url.pathname,
                search: url.search,
                authorization: headers.get("authorization"),
                body: typeof init.body === "string"
                    ? JSON.parse(init.body)
                    : null,
            };
            calls.push(call);

            if (url.pathname === GUEST_ENTER_PATH) {
                const signed = call.body;
                const guestPass = token(
                    "nrguest_",
                    `${signed.runtime_id}:${signed.agent_name}`,
                    64,
                );
                const guestId = token(
                    "nrog-",
                    `${signed.runtime_id}:${signed.agent_name}`,
                    32,
                );
                guestPassByName.set(signed.agent_name, guestPass);
                entries.push({
                    runtimeId: signed.runtime_id,
                    publicKey: signed.public_key,
                    agentName: signed.agent_name,
                    guestPass,
                });
                return jsonResponse({
                    ok: true,
                    guest_entered: true,
                    guest_id: guestId,
                    guest_pass: guestPass,
                    guest_pass_expires_at: "2099-01-01T00:00:00Z",
                    agent_id: entries.length,
                    agent_slug: `openclaw-guest-${sha256(signed.agent_name).slice(0, 12)}`,
                    agent_name: signed.agent_name,
                    badge: "UNVERIFIED OPENCLAW GUEST",
                    verified_identity: false,
                });
            }

            if (url.pathname === GUEST_FEED_PATH) {
                return jsonResponse({ ok: true, posts: [] });
            }

            if (url.pathname === ACTION_STATUS_PATH) {
                return jsonResponse(protocolStatus());
            }

            if (url.pathname === ACTIONS_PATH && call.method === "POST") {
                return jsonResponse(canonicalReceipt(call.body));
            }

            throw new Error(`Unexpected stubbed NodeRooms request: ${call.method} ${url}`);
        },
    };
}

function createCaptureApi({ stateDir, config }) {
    const registrations = {
        commands: [],
        hooks: [],
        tools: [],
    };
    const api = {
        config,
        pluginConfig: {
            trustLayer: { mode: "off" },
            workRuntime: { mode: "off" },
        },
        runtime: {
            state: { resolveStateDir: () => stateDir },
            gateway: {
                async request() {
                    throw new Error("Tool catalog is outside this isolation test.");
                },
            },
        },
        on(name, handler, options = {}) {
            registrations.hooks.push({ name, handler, options });
        },
        registerCommand(command) {
            registrations.commands.push(command);
        },
        registerTool(tool, options = {}) {
            registrations.tools.push({ tool, options });
        },
    };
    plugin.register(api);
    return registrations;
}

function toolContext(agent) {
    return {
        config: agent.config,
        runtimeConfig: agent.config,
        agentId: agent.id,
        agentDir: agent.agentDir,
        sessionKey: `agent:${agent.id}:main`,
        sessionId: `session-${agent.id}`,
        messageChannel: CHANNEL,
        requesterSenderId: OWNER_ID,
        senderIsOwner: true,
        deliveryContext: { channel: CHANNEL },
    };
}

function commandContext(agent, args, overrides = {}) {
    return {
        config: agent.config,
        agentId: agent.id,
        sessionKey: `agent:${agent.id}:main`,
        sessionId: `session-${agent.id}`,
        channel: CHANNEL,
        senderId: OWNER_ID,
        senderIsOwner: true,
        isAuthorizedSender: true,
        commandBody: `/noderooms ${args}`,
        args,
        ...overrides,
    };
}

async function resolveTool(registrations, name, context) {
    for (const registration of registrations.tools) {
        const declaredNames = registration.options.names
            ?? (registration.options.name ? [registration.options.name] : []);
        if (declaredNames.length > 0 && !declaredNames.includes(name)) {
            continue;
        }
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
    const command = registrations.commands.find((entry) => entry.name === name);
    assert.ok(command, `Registered command not found: ${name}`);
    return command;
}

function toolJson(result) {
    if (result?.details && typeof result.details === "object") {
        return structuredClone(result.details);
    }
    const text = result?.content?.find((entry) =>
        entry?.type === "text" && typeof entry.text === "string")?.text;
    assert.equal(typeof text, "string");
    return JSON.parse(text);
}

function commandJson(result) {
    assert.equal(typeof result?.text, "string");
    return JSON.parse(result.text);
}

async function createHarness(t, agentIds) {
    const root = await mkdtemp(path.join(os.tmpdir(), "nr-multi-agent-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const stateDir = path.join(root, "state");
    await mkdir(stateDir, { recursive: true, mode: 0o700 });
    const entries = agentIds.map((id, index) => ({
        id,
        default: index === 0,
        agentDir: path.join(stateDir, "agents", id, "agent"),
        workspace: path.join(root, "workspaces", id),
    }));
    const config = { agents: { list: entries } };
    const agents = entries.map((entry) => ({ ...entry, config }));
    const server = createStubServer();
    const previousFetch = globalThis.fetch;
    globalThis.fetch = server.fetch;
    t.after(() => {
        globalThis.fetch = previousFetch;
    });
    return {
        agents,
        registrations: createCaptureApi({ stateDir, config }),
        root,
        server,
        stateDir,
    };
}

async function createLoaderBackedHarness(t, agentIds) {
    const root = await mkdtemp(path.join(
        os.tmpdir(),
        "nr-loader-multi-agent-",
    ));
    t.after(() => rm(root, { recursive: true, force: true }));
    const stateDir = path.join(root, "state");
    const workspace = path.join(root, "workspace");
    await Promise.all([
        mkdir(stateDir, { recursive: true, mode: 0o700 }),
        mkdir(workspace, { recursive: true, mode: 0o700 }),
    ]);
    const entries = agentIds.map((id, index) => ({
        id,
        default: index === 0,
        agentDir: path.join(stateDir, "agents", id, "agent"),
        workspace: path.join(root, "workspaces", id),
    }));
    const config = {
        agents: { list: entries },
        plugins: {
            load: { paths: [PLUGIN_ROOT] },
            entries: {
                noderooms: {
                    enabled: true,
                    config: {
                        trustLayer: { mode: "off" },
                        workRuntime: { mode: "off" },
                    },
                },
            },
        },
    };
    const env = {
        ...process.env,
        OPENCLAW_STATE_DIR: stateDir,
        OPENCLAW_WORKSPACE_DIR: workspace,
    };
    const previousStateDir = process.env.OPENCLAW_STATE_DIR;
    const previousWorkspaceDir = process.env.OPENCLAW_WORKSPACE_DIR;
    process.env.OPENCLAW_STATE_DIR = stateDir;
    process.env.OPENCLAW_WORKSPACE_DIR = workspace;
    t.after(() => {
        if (previousStateDir === undefined) {
            delete process.env.OPENCLAW_STATE_DIR;
        }
        else {
            process.env.OPENCLAW_STATE_DIR = previousStateDir;
        }
        if (previousWorkspaceDir === undefined) {
            delete process.env.OPENCLAW_WORKSPACE_DIR;
        }
        else {
            process.env.OPENCLAW_WORKSPACE_DIR = previousWorkspaceDir;
        }
        clearActivatedPluginRuntimeState();
        clearPluginLoaderCache();
        clearPluginRegistryLoadCache();
    });

    clearActivatedPluginRuntimeState();
    clearPluginLoaderCache();
    clearPluginRegistryLoadCache();
    const registry = loadOpenClawPlugins({
        config,
        env,
        workspaceDir: workspace,
        onlyPluginIds: ["noderooms"],
        cache: false,
        activate: true,
        loadModules: true,
        throwOnLoadError: true,
    });
    const loaded = registry.plugins.find((entry) => entry.id === "noderooms");
    assert.equal(loaded?.status, "loaded");
    assert.equal(
        registry.diagnostics.filter((entry) =>
            entry.pluginId === "noderooms"
            && entry.level === "error").length,
        0,
    );

    const server = createStubServer();
    const previousFetch = globalThis.fetch;
    globalThis.fetch = server.fetch;
    t.after(() => {
        globalThis.fetch = previousFetch;
    });
    return {
        agents: entries.map((entry) => ({ ...entry, config })),
        registrations: {
            commands: registry.commands
                .filter((entry) => entry.pluginId === "noderooms")
                .map((entry) => entry.command),
            hooks: registry.typedHooks
                .filter((entry) => entry.pluginId === "noderooms"),
            tools: registry.tools
                .filter((entry) => entry.pluginId === "noderooms")
                .map((entry) => ({
                    tool: entry.factory,
                    options: {
                        names: entry.names,
                        optional: entry.optional,
                    },
                })),
        },
        root,
        server,
        stateDir,
    };
}

test("two OpenClaw Agents receive distinct identities and retain their own Guest Pass", async (t) => {
    const harness = await createHarness(t, ["alpha", "beta"]);
    const [alpha, beta] = harness.agents;
    const alphaContext = toolContext(alpha);
    const betaContext = toolContext(beta);
    const alphaEnter = await resolveTool(
        harness.registrations,
        "noderooms_enter",
        alphaContext,
    );
    const betaEnter = await resolveTool(
        harness.registrations,
        "noderooms_enter",
        betaContext,
    );

    await alphaEnter.execute("enter-alpha", { agent_name: "Agent Alpha" });
    await betaEnter.execute("enter-beta", { agent_name: "Agent Beta" });

    const alphaFeed = await resolveTool(
        harness.registrations,
        "noderooms_read_feed",
        alphaContext,
    );
    const betaFeed = await resolveTool(
        harness.registrations,
        "noderooms_read_feed",
        betaContext,
    );
    await alphaFeed.execute("feed-alpha", { limit: 1 });
    await betaFeed.execute("feed-beta", { limit: 1 });

    assert.equal(new Set(harness.server.entries.map((entry) => entry.runtimeId)).size, 2);
    assert.equal(new Set(harness.server.entries.map((entry) => entry.publicKey)).size, 2);
    const feedCalls = harness.server.calls.filter((call) =>
        call.path === GUEST_FEED_PATH);
    assert.deepEqual(
        feedCalls.map((call) => call.authorization),
        [
            `Bearer ${harness.server.guestPassByName.get("Agent Alpha")}`,
            `Bearer ${harness.server.guestPassByName.get("Agent Beta")}`,
        ],
    );

    for (const agent of harness.agents) {
        const identity = JSON.parse(await readFile(
            path.join(
                agent.agentDir,
                "plugins",
                "noderooms",
                "guest-identity.json",
            ),
            "utf8",
        ));
        assert.equal(identity.version, 1);
    }
});

test("nine concurrent Agents keep nine identity, Guest Pass, and read authorities", async (t) => {
    const harness = await createHarness(
        t,
        Array.from({ length: 9 }, (_, index) => `agent-${index + 1}`),
    );
    const contexts = harness.agents.map(toolContext);
    const enterTools = await Promise.all(contexts.map((context) =>
        resolveTool(harness.registrations, "noderooms_enter", context)));
    await Promise.all(enterTools.map((tool, index) =>
        tool.execute(`enter-${index + 1}`, {
            agent_name: `Isolation Agent ${index + 1}`,
        })));

    assert.equal(harness.server.entries.length, 9);
    assert.equal(new Set(harness.server.entries.map((entry) => entry.runtimeId)).size, 9);
    assert.equal(new Set(harness.server.entries.map((entry) => entry.publicKey)).size, 9);
    assert.equal(new Set(harness.server.entries.map((entry) => entry.guestPass)).size, 9);

    const feedTools = await Promise.all(contexts.map((context) =>
        resolveTool(harness.registrations, "noderooms_read_feed", context)));
    await Promise.all(feedTools.map((tool, index) =>
        tool.execute(`feed-${index + 1}`, { limit: 1 })));
    const feedAuthorizations = harness.server.calls
        .filter((call) => call.path === GUEST_FEED_PATH)
        .map((call) => call.authorization);
    assert.equal(new Set(feedAuthorizations).size, 9);
    assert.deepEqual(
        new Set(feedAuthorizations),
        new Set(harness.server.entries.map((entry) =>
            `Bearer ${entry.guestPass}`)),
    );
});

test("Owner commit routes through the exact intent Agent and missing or foreign agentId fails closed", async (t) => {
    const harness = await createHarness(t, ["alpha", "beta"]);
    const [alpha, beta] = harness.agents;
    const alphaContext = toolContext(alpha);
    const betaContext = toolContext(beta);
    const command = resolveCommand(harness.registrations, "noderooms");

    const alphaEnter = await resolveTool(
        harness.registrations,
        "noderooms_enter",
        alphaContext,
    );
    const betaEnter = await resolveTool(
        harness.registrations,
        "noderooms_enter",
        betaContext,
    );
    await alphaEnter.execute("enter-alpha", { agent_name: "Agent Alpha" });
    await betaEnter.execute("enter-beta", { agent_name: "Agent Beta" });

    const prepare = await resolveTool(
        harness.registrations,
        "noderooms_create_guest_post",
        alphaContext,
    );
    const firstIntent = toolJson(await prepare.execute("prepare-alpha", {
        room_slug: "playground",
        body: "Alpha-owned commit routing proof.",
    }));
    const firstCommit = commandJson(await command.handler(
        commandContext(alpha, `commit ${firstIntent.intent_id}`),
    ));
    assert.equal(firstCommit.committed, true);
    const firstActionCall = harness.server.calls.find((call) =>
        call.path === ACTIONS_PATH && call.method === "POST");
    assert.equal(
        firstActionCall.authorization,
        `Bearer ${harness.server.guestPassByName.get("Agent Alpha")}`,
    );

    const missingIntent = toolJson(await prepare.execute("prepare-missing", {
        room_slug: "playground",
        body: "Missing Agent context must not dispatch.",
    }));
    const actionCallsBeforeMissing = harness.server.calls.filter((call) =>
        call.path === ACTIONS_PATH && call.method === "POST").length;
    const missingResult = commandJson(await command.handler(commandContext(
        alpha,
        `commit ${missingIntent.intent_id}`,
        { agentId: undefined },
    )));
    assert.equal(missingResult.ok, false);
    assert.equal(missingResult.error, "OPENCLAW_AGENT_CONTEXT_REQUIRED");
    assert.equal(harness.server.calls.filter((call) =>
        call.path === ACTIONS_PATH && call.method === "POST").length,
    actionCallsBeforeMissing);

    const foreignIntent = toolJson(await prepare.execute("prepare-foreign", {
        room_slug: "playground",
        body: "Foreign Agent context must not dispatch.",
    }));
    const foreignResult = commandJson(await command.handler(
        commandContext(beta, `commit ${foreignIntent.intent_id}`),
    ));
    assert.equal(foreignResult.ok, false);
    assert.equal(foreignResult.error, "ACTION_INTENT_AGENT_MISMATCH");
    assert.equal(harness.server.calls.filter((call) =>
        call.path === ACTIONS_PATH && call.method === "POST").length,
    actionCallsBeforeMissing);

    const betaFeed = await resolveTool(
        harness.registrations,
        "noderooms_read_feed",
        betaContext,
    );
    await betaFeed.execute("beta-still-readable", { limit: 1 });
});

test("cross-Agent read context is rejected before network use", async (t) => {
    const harness = await createHarness(t, ["alpha", "beta"]);
    const [alpha, beta] = harness.agents;
    const callsBefore = harness.server.calls.length;

    const mismatchedRead = await resolveTool(
        harness.registrations,
        "noderooms_read_feed",
        {
            ...toolContext(alpha),
            agentDir: beta.agentDir,
        },
    );
    const mismatch = toolJson(await mismatchedRead.execute(
        "mismatched-read",
        { limit: 1 },
    ));
    assert.equal(mismatch.ok, false);
    assert.equal(mismatch.error, "OPENCLAW_AGENT_DIRECTORY_MISMATCH");

    const missingEnter = await resolveTool(
        harness.registrations,
        "noderooms_enter",
        {
            ...toolContext(alpha),
            agentId: undefined,
        },
    );
    const missing = toolJson(await missingEnter.execute(
        "missing-agent-enter",
        { agent_name: "Missing Agent" },
    ));
    assert.equal(missing.ok, false);
    assert.equal(missing.error, "OPENCLAW_AGENT_CONTEXT_REQUIRED");
    assert.equal(harness.server.calls.length, callsBefore);
});

test("Gateway restart discards live credentials while preserving only the same Agent identity", async (t) => {
    const harness = await createHarness(t, ["alpha"]);
    const [alpha] = harness.agents;
    const alphaContext = toolContext(alpha);
    const enter = await resolveTool(
        harness.registrations,
        "noderooms_enter",
        alphaContext,
    );
    await enter.execute("enter-before-restart", {
        agent_name: "Restart Agent",
    });
    const firstRuntimeId = harness.server.entries.at(-1).runtimeId;
    const stopHook = harness.registrations.hooks.find((hook) =>
        hook.name === "gateway_stop");
    assert.ok(stopHook);
    await stopHook.handler();

    const restarted = createCaptureApi({
        stateDir: harness.stateDir,
        config: alpha.config,
    });
    const command = resolveCommand(restarted, "noderooms");
    const leaseStatus = commandJson(await command.handler(
        commandContext(alpha, "lease"),
    ));
    assert.equal(leaseStatus.guest_pass_held_in_memory, false);
    assert.equal(leaseStatus.provider_session_held_in_memory, false);
    assert.equal(leaseStatus.run_lease_held_in_memory, false);

    const restartedFeed = await resolveTool(
        restarted,
        "noderooms_read_feed",
        alphaContext,
    );
    const enterCallsBeforeRead = harness.server.entries.length;
    await restartedFeed.execute("feed-after-restart", { limit: 1 });
    assert.equal(harness.server.entries.length, enterCallsBeforeRead + 1);
    assert.equal(harness.server.entries.at(-1).runtimeId, firstRuntimeId);
    assert.equal(
        JSON.parse(await readFile(
            path.join(
                alpha.agentDir,
                "plugins",
                "noderooms",
                "guest-identity.json",
            ),
            "utf8",
        )).runtime_id,
        firstRuntimeId,
    );
});

test("real OpenClaw loader executes isolated enter, read, and exact-Agent Owner commit", async (t) => {
    const harness = await createLoaderBackedHarness(t, ["alpha", "beta"]);
    const [alpha, beta] = harness.agents;
    const alphaContext = toolContext(alpha);
    const betaContext = toolContext(beta);
    const alphaEnter = await resolveTool(
        harness.registrations,
        "noderooms_enter",
        alphaContext,
    );
    const betaEnter = await resolveTool(
        harness.registrations,
        "noderooms_enter",
        betaContext,
    );
    await alphaEnter.execute("loader-enter-alpha", {
        agent_name: "Loader Alpha",
    });
    await betaEnter.execute("loader-enter-beta", {
        agent_name: "Loader Beta",
    });

    const alphaFeed = await resolveTool(
        harness.registrations,
        "noderooms_read_feed",
        alphaContext,
    );
    await alphaFeed.execute("loader-feed-alpha", { limit: 1 });
    assert.equal(
        harness.server.calls.at(-1).authorization,
        `Bearer ${harness.server.guestPassByName.get("Loader Alpha")}`,
    );

    const prepare = await resolveTool(
        harness.registrations,
        "noderooms_create_guest_post",
        alphaContext,
    );
    const intent = toolJson(await prepare.execute("loader-prepare-alpha", {
        room_slug: "playground",
        body: "Real loader multi-Agent commit routing proof.",
    }));
    const command = resolveCommand(harness.registrations, "noderooms");
    const committed = commandJson(await command.handler(commandContext(
        alpha,
        `commit ${intent.intent_id}`,
    )));
    assert.equal(committed.committed, true);
    assert.equal(
        harness.server.calls.at(-1).authorization,
        `Bearer ${harness.server.guestPassByName.get("Loader Alpha")}`,
    );
    assert.equal(
        new Set(harness.server.entries.map((entry) => entry.runtimeId)).size,
        2,
    );
});
