import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { NodeRoomsAgentRuntimeRegistry } from "../dist/agent-runtime.js";
import { loadOrCreateGuestIdentity } from "../dist/guest-identity.js";

function guestPass(agentId) {
    return {
        guestId: `${agentId}-guest`,
        agentId: 1,
        agentSlug: agentId,
        guestPass: `${agentId}-secret`,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
}

test("agent runtimes isolate identities, credentials, and restart cleanup", async (t) => {
    const root = await mkdtemp(path.join(tmpdir(), "nr-agent-runtime-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const stateDir = path.join(root, "state");
    const legacyIdentity = await loadOrCreateGuestIdentity(stateDir);
    const agentIds = Array.from({ length: 9 }, (_, index) => `agent-${index + 1}`);
    const registry = new NodeRoomsAgentRuntimeRegistry({
        stateDir,
        config: {
            agents: {
                list: agentIds.map((id, index) => ({ id, default: index === 0 })),
            },
        },
        resolveAgentDir: (agentId) => path.join(root, "agents", agentId),
    });

    const runtimes = agentIds.map((agentId) => registry.get(agentId));
    const proofs = await Promise.all(runtimes.map((runtime) =>
        runtime.sdk.guestEntrySigner.createSignedEntry(runtime.agentId)));
    const publicKeys = new Set(proofs.map((proof) => proof.public_key));
    const runtimeIds = new Set(proofs.map((proof) => proof.runtime_id));

    assert.equal(publicKeys.size, agentIds.length);
    assert.equal(runtimeIds.size, agentIds.length);
    assert.equal(proofs[0].public_key, legacyIdentity.public_key);

    runtimes[0].secretStore.setGuestPass(guestPass(agentIds[0]));
    assert.equal(registry.safeState(agentIds[0]).guest_pass_held_in_memory, true);
    assert.equal(registry.safeState(agentIds[1]).guest_pass_held_in_memory, false);

    registry.clearSecrets();
    for (const agentId of agentIds) {
        assert.equal(registry.safeState(agentId).guest_pass_held_in_memory, false);
    }
});
