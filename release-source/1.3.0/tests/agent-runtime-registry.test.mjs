import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";

import {
    AgentRuntimeRegistry,
    MAX_AGENT_RUNTIMES,
    requireCanonicalOpenClawAgentDir,
    requireCanonicalOpenClawAgentId,
} from "../src/state.js";
import { createInMemorySecretStore } from "../src/sdk/memory-secret-store.js";

const LIVE_UNTIL = "2099-01-01T00:00:00.000Z";

function createRegistry(options = {}) {
    return new AgentRuntimeRegistry({
        maxRuntimes: options.maxRuntimes,
        createRuntime({ agentId }) {
            const secretStore = createInMemorySecretStore();
            return {
                sdk: Object.freeze({ agentId }),
                secretStore,
                clearSecrets() {
                    secretStore.clearSecrets();
                },
            };
        },
    });
}

function agentContext(index) {
    const agentId = `agent-${index}`;
    return {
        agentId,
        agentDir: path.resolve(`/tmp/noderooms-registry/${agentId}`),
    };
}

test("nine runtime bundles keep distinct Guest, provider session, and run lease state", () => {
    const registry = createRegistry();
    const runtimes = Array.from({ length: 9 }, (_, offset) => {
        const index = offset + 1;
        const runtime = registry.resolve(agentContext(index));
        runtime.secretStore.setGuestPass({
            guestId: `nrog-${String(index).padStart(32, "0")}`,
            guestPass: `nrguest_${String(index).padStart(64, "0")}`,
            expiresAt: LIVE_UNTIL,
            agentId: index,
            agentSlug: `isolation-agent-${index}`,
        });
        runtime.secretStore.setSession({
            arrivalId: `nrea-${String(index).padStart(8, "0")}`,
            sessionId: `session-${index}`,
            sessionSecret: `session-secret-${index}`,
            sessionExpiresAt: LIVE_UNTIL,
        });
        runtime.secretStore.setRunLease({
            runId: `run-${index}`,
            runSecret: `run-secret-${index}`,
            expiresAt: LIVE_UNTIL,
            leaseHeaders: { "X-NodeRooms-Run": `run-${index}` },
            leasePolicyId: `nrlp-${String(index).padStart(8, "0")}`,
            scopes: [`agent.scope.${index}`],
            rooms: [`room-${index}`],
        });
        runtime.secretStore.bindRunLeaseAgent(runtime.agentId);
        return runtime;
    });

    assert.equal(registry.size(), 9);
    assert.equal(new Set(runtimes.map((runtime) => runtime.sdk)).size, 9);
    assert.equal(new Set(runtimes.map((runtime) => runtime.secretStore)).size, 9);

    const states = runtimes.map((runtime) => runtime.secretStore.safeState());
    assert.equal(new Set(states.map((state) => state.guest_id)).size, 9);
    assert.equal(new Set(states.map((state) => state.session_id)).size, 9);
    assert.equal(new Set(states.map((state) => state.run_id)).size, 9);
    assert.equal(
        new Set(states.map((state) => state.run_lease_bound_agent_id)).size,
        9,
    );

    for (let offset = 0; offset < runtimes.length; offset += 1) {
        const index = offset + 1;
        const runtime = runtimes[offset];
        assert.equal(
            runtime.secretStore.guestHeaders().Authorization,
            `Bearer nrguest_${String(index).padStart(64, "0")}`,
        );
        assert.equal(
            runtime.secretStore.requireSession().sessionSecret,
            `session-secret-${index}`,
        );
        assert.equal(
            registry.safeState(runtime.agentId).openclaw_agent_id,
            runtime.agentId,
        );
    }
});

test("runtime registry rejects missing context, directory drift, collisions, and overflow", () => {
    const registry = createRegistry({ maxRuntimes: 2 });
    const first = agentContext(1);
    registry.resolve(first);

    assert.throws(
        () => registry.resolve({ agentDir: first.agentDir }),
        (error) => error?.code === "OPENCLAW_AGENT_CONTEXT_REQUIRED",
    );
    assert.throws(
        () => registry.resolve({
            agentId: first.agentId,
            agentDir: path.resolve("/tmp/noderooms-registry/drift"),
        }),
        (error) => error?.code === "AGENT_RUNTIME_DIRECTORY_DRIFT",
    );
    assert.throws(
        () => registry.resolve({
            agentId: "agent-collision",
            agentDir: first.agentDir,
        }),
        (error) => error?.code === "AGENT_RUNTIME_DIRECTORY_COLLISION",
    );

    registry.resolve(agentContext(2));
    assert.throws(
        () => registry.resolve(agentContext(3)),
        (error) => error?.code === "AGENT_RUNTIME_LIMIT_REACHED",
    );
});

test("clearAll destroys every live secret before dropping runtime references", () => {
    const registry = createRegistry();
    const runtime = registry.resolve(agentContext(1));
    runtime.secretStore.setGuestPass({
        guestId: `nrog-${"1".repeat(32)}`,
        guestPass: `nrguest_${"1".repeat(64)}`,
        expiresAt: LIVE_UNTIL,
        agentId: 1,
        agentSlug: "agent-one",
    });
    runtime.secretStore.setSession({
        arrivalId: "nrea-11111111",
        sessionId: "session-1",
        sessionSecret: "session-secret-1",
        sessionExpiresAt: LIVE_UNTIL,
    });
    runtime.secretStore.setRunLease({
        runId: "run-1",
        runSecret: "run-secret-1",
        expiresAt: LIVE_UNTIL,
        leaseHeaders: { "X-NodeRooms-Run": "run-1" },
    });

    registry.clearAll();

    assert.equal(registry.size(), 0);
    assert.equal(runtime.secretStore.safeState().guest_pass_held_in_memory, false);
    assert.equal(
        runtime.secretStore.safeState().provider_session_held_in_memory,
        false,
    );
    assert.equal(runtime.secretStore.safeState().run_lease_held_in_memory, false);
    assert.throws(
        () => runtime.secretStore.guestHeaders(),
        (error) => error?.code === "GUEST_PASS_UNAVAILABLE",
    );
});

test("canonical Agent context helpers reject aliases and non-absolute directories", () => {
    assert.equal(requireCanonicalOpenClawAgentId("agent-1"), "agent-1");
    assert.equal(
        requireCanonicalOpenClawAgentDir("/tmp/../tmp/noderooms-agent"),
        path.resolve("/tmp/noderooms-agent"),
    );
    assert.throws(
        () => requireCanonicalOpenClawAgentId("Agent-1"),
        (error) => error?.code === "OPENCLAW_AGENT_ID_INVALID",
    );
    assert.throws(
        () => requireCanonicalOpenClawAgentDir("relative/agent"),
        (error) => error?.code === "OPENCLAW_AGENT_DIRECTORY_INVALID",
    );
    assert.equal(MAX_AGENT_RUNTIMES, 256);
});
