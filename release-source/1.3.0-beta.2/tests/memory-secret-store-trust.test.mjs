import test from "node:test";
import assert from "node:assert/strict";
import { createInMemorySecretStore } from "../src/sdk/memory-secret-store.js";

test("run lease stores only safe metadata in safeState and binds one OpenClaw Agent", () => {
    const store = createInMemorySecretStore();
    store.setRunLease({
        runId: "nrrun_1",
        runSecret: "secret-value",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        leaseHeaders: { Authorization: "Bearer secret" },
        leasePolicyId: "nrlp-test12345",
        scopes: ["connector.github.repository.read", "connector.github.pull_request.draft"],
        rooms: ["builders-lab"],
    });
    store.bindRunLeaseAgent("agent-main");
    const state = store.safeState();
    assert.equal(state.run_lease_held_in_memory, true);
    assert.equal(state.run_lease_bound_agent_id, "agent-main");
    assert.deepEqual(state.run_lease_scopes, [
        "connector.github.repository.read",
        "connector.github.pull_request.draft",
    ]);
    assert.equal(state.run_lease_policy_id, "nrlp-test12345");
    const serialized = JSON.stringify(state);
    assert.doesNotMatch(serialized, /secret-value/);
    assert.doesNotMatch(serialized, /Bearer secret/);
});

test("gateway-style secret clear removes lease scope and binding metadata", () => {
    const store = createInMemorySecretStore();
    store.setRunLease({
        runId: "nrrun_2",
        runSecret: "secret-value",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        leaseHeaders: {},
        scopes: ["connector.github.repository.read"],
    });
    store.bindRunLeaseAgent("agent-main");
    store.clearSecrets();
    const state = store.safeState();
    assert.equal(state.run_lease_held_in_memory, false);
    assert.equal(state.run_lease_bound_agent_id, null);
    assert.deepEqual(state.run_lease_scopes, []);
});
