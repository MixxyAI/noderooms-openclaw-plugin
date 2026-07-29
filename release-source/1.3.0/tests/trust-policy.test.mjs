import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { TrustEventLedger } from "../src/trust-ledger.js";
import { NodeRoomsTrustMiddleware } from "../src/trust-middleware.js";
import { normalizeTrustLayerConfig } from "../src/trust-policy.js";

function config(mode, approval = "none", risk = approval === "allow-once" ? "high" : "medium") {
    return normalizeTrustLayerConfig({
        trustLayer: {
            mode,
            ledgerMaxEntries: 8,
            rules: [{
                toolName: "github_create_pull_request",
                requiredScope: "connector.github.pull_request.draft",
                risk,
                approval,
            }],
        },
    });
}

function internalEnforceConfig(approval = "none", risk = approval === "allow-once" ? "high" : "medium") {
    const normalized = config("observe", approval, risk);
    return Object.freeze({
        ...normalized,
        mode: "enforce",
        enforceActivationBlocked: false,
    });
}

function safeLease(overrides = {}) {
    return {
        run_lease_held_in_memory: true,
        run_lease_bound_agent_id: "agent-main",
        run_lease_scopes: ["connector.github.pull_request.draft"],
        run_id: "nrrun_test",
        ...overrides,
    };
}

async function withMiddleware(mode, approval, safeState, fn) {
    const dir = await mkdtemp(path.join(os.tmpdir(), "nr-trust-test-"));
    const filePath = path.join(dir, "trust-events-v1.json");
    const ledger = new TrustEventLedger({ filePath, maxEntries: 8 });
    const middleware = new NodeRoomsTrustMiddleware({
        config: mode === "enforce"
            ? internalEnforceConfig(approval)
            : config(mode, approval),
        safeState: () => safeState,
        ledger,
    });
    try {
        await fn({ middleware, filePath, ledger });
    } finally {
        await rm(dir, { recursive: true, force: true });
    }
}

test("trust layer defaults off with no rules", () => {
    const value = normalizeTrustLayerConfig({});
    assert.equal(value.mode, "off");
    assert.deepEqual(value.rules, []);
    assert.equal(value.ledgerMaxEntries, 256);
    assert.equal(value.liveEnforceAllowed, false);
    assert.equal(value.enforceActivationBlocked, false);
});

test("Alpha1 public configuration cannot activate enforce mode", () => {
    const value = config("enforce");
    assert.equal(value.mode, "off");
    assert.equal(value.liveEnforceAllowed, false);
    assert.equal(value.enforceActivationBlocked, true);
});

test("high and critical rules always require allow-once approval", () => {
    for (const risk of ["high", "critical"]) {
        const value = config("observe", "none", risk);
        assert.equal(value.rules[0].risk, risk);
        assert.equal(value.rules[0].approval, "allow-once");
    }
    assert.equal(config("observe", "none", "medium").rules[0].approval, "none");
});

test("invalid and duplicate rules are removed", () => {
    const value = normalizeTrustLayerConfig({
        trustLayer: {
            mode: "observe",
            rules: [
                { toolName: "noderooms_comment", requiredScope: "connector.bad.write" },
                { toolName: "github_create_issue", requiredScope: "connector.github.issue.draft" },
                { toolName: "github_create_issue", requiredScope: "connector.github.issue.other" },
                { toolName: "*", requiredScope: "connector.wildcard.write" },
            ],
        },
    });
    assert.deepEqual(value.rules, [{
        toolName: "github_create_issue",
        requiredScope: "connector.github.issue.draft",
        risk: "medium",
        approval: "none",
    }]);
});

test("observe mode records a would-block decision but does not block", async () => {
    await withMiddleware("observe", "none", {
        run_lease_held_in_memory: false,
        run_lease_bound_agent_id: null,
        run_lease_scopes: [],
    }, async ({ middleware, filePath }) => {
        const result = await middleware.beforeToolCall({
            toolName: "github_create_pull_request",
            toolCallId: "call_1",
            params: { title: "secret title", body: "private body" },
        }, {
            agentId: "agent-main",
            runId: "run_1",
            channel: "discord",
        });
        assert.equal(result, undefined);
        const stored = JSON.parse(await readFile(filePath, "utf8"));
        assert.equal(stored.entries[0].decision, "would_block_no_lease");
        assert.deepEqual(stored.entries[0].parameter_names, ["body", "title"]);
        const serialized = JSON.stringify(stored);
        assert.doesNotMatch(serialized, /secret title/);
        assert.doesNotMatch(serialized, /private body/);
    });
});

test("enforce mode blocks a governed tool without a lease", async () => {
    await withMiddleware("enforce", "none", {
        run_lease_held_in_memory: false,
        run_lease_bound_agent_id: null,
        run_lease_scopes: [],
    }, async ({ middleware }) => {
        const result = await middleware.beforeToolCall({
            toolName: "github_create_pull_request",
            params: {},
        }, { agentId: "agent-main" });
        assert.equal(result.block, true);
        assert.match(result.blockReason, /NodeRooms trust policy denied/);
    });
});

test("enforce mode blocks agent mismatch and missing scope", async () => {
    await withMiddleware("enforce", "none", safeLease({
        run_lease_bound_agent_id: "agent-other",
    }), async ({ middleware }) => {
        const result = await middleware.beforeToolCall({
            toolName: "github_create_pull_request",
            params: {},
        }, { agentId: "agent-main" });
        assert.equal(result.block, true);
    });

    await withMiddleware("enforce", "none", safeLease({
        run_lease_scopes: ["connector.github.repository.read"],
    }), async ({ middleware }) => {
        const result = await middleware.beforeToolCall({
            toolName: "github_create_pull_request",
            params: {},
        }, { agentId: "agent-main" });
        assert.equal(result.block, true);
    });
});

test("enforce mode allows an exact scope match without approval", async () => {
    await withMiddleware("enforce", "none", safeLease(), async ({ middleware }) => {
        const result = await middleware.beforeToolCall({
            toolName: "github_create_pull_request",
            params: {},
        }, { agentId: "agent-main" });
        assert.equal(result, undefined);
    });
});

test("high-risk configured action requests allow-once only", async () => {
    await withMiddleware("enforce", "allow-once", safeLease(), async ({ middleware, ledger }) => {
        const result = await middleware.beforeToolCall({
            toolName: "github_create_pull_request",
            toolCallId: "call_approval",
            params: {},
        }, {
            agentId: "agent-main",
            runId: "run_approval",
        });
        assert.deepEqual(result.requireApproval.allowedDecisions, ["allow-once", "deny"]);
        assert.equal(result.requireApproval.timeoutBehavior, "deny");
        assert.equal(result.requireApproval.severity, "warning");
        await result.requireApproval.onResolution("allow-once");
        const summary = await ledger.summary();
        assert.equal(summary.entry_count, 2);
    });
});

test("internal enforce path fails closed on policy and audit errors", async () => {
    const policyFailure = new NodeRoomsTrustMiddleware({
        config: internalEnforceConfig(),
        safeState: () => {
            throw new Error("policy unavailable");
        },
        ledger: {
            append: async () => undefined,
            summary: async () => ({ entry_count: 1 }),
            clearRuntimeCache: () => undefined,
        },
    });
    const policyResult = await policyFailure.beforeToolCall({
        toolName: "github_create_pull_request",
        params: {},
    }, { agentId: "agent-main" });
    assert.equal(policyResult.block, true);
    assert.match(policyResult.blockReason, /could not be evaluated safely/);

    const auditFailure = new NodeRoomsTrustMiddleware({
        config: internalEnforceConfig(),
        safeState: safeLease,
        ledger: {
            append: async () => {
                throw new Error("ledger unavailable");
            },
            summary: async () => ({ entry_count: 0 }),
            clearRuntimeCache: () => undefined,
        },
    });
    const auditResult = await auditFailure.beforeToolCall({
        toolName: "github_create_pull_request",
        params: {},
    }, { agentId: "agent-main" });
    assert.equal(auditResult.block, true);
    assert.match(auditResult.blockReason, /audit ledger was unavailable/);
});

test("NodeRooms tools and unlisted tools are never governed", async () => {
    await withMiddleware("enforce", "none", {
        run_lease_held_in_memory: false,
        run_lease_bound_agent_id: null,
        run_lease_scopes: [],
    }, async ({ middleware, ledger }) => {
        assert.equal(await middleware.beforeToolCall({
            toolName: "noderooms_comment",
            params: {},
        }, { agentId: "agent-main" }), undefined);
        assert.equal(await middleware.beforeToolCall({
            toolName: "web_search",
            params: {},
        }, { agentId: "agent-main" }), undefined);
        const summary = await ledger.summary();
        assert.equal(summary.entry_count, 0);
    });
});

test("after hook stores outcome metadata but not raw results", async () => {
    await withMiddleware("observe", "none", safeLease(), async ({ middleware, filePath }) => {
        await middleware.afterToolCall({
            toolName: "github_create_pull_request",
            toolCallId: "call_after",
            durationMs: 125,
            result: { token: "must-not-persist" },
        }, {
            agentId: "agent-main",
            runId: "run_after",
        });
        const stored = JSON.parse(await readFile(filePath, "utf8"));
        assert.equal(stored.entries[0].outcome, "success");
        assert.equal(stored.entries[0].duration_ms, 125);
        assert.doesNotMatch(JSON.stringify(stored), /must-not-persist/);
    });
});
