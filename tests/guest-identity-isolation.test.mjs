import test from "node:test";
import assert from "node:assert/strict";
import {
    generateKeyPairSync,
    randomUUID,
} from "node:crypto";
import {
    mkdir,
    mkdtemp,
    readFile,
    rm,
    stat,
    writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { loadOrCreateGuestIdentity } from "../src/guest-identity.js";

function createIdentityFixture() {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicJwk = publicKey.export({ format: "jwk" });
    const privateJwk = privateKey.export({ format: "jwk" });
    return {
        version: 1,
        runtime_id: `openclaw-${randomUUID()}`,
        public_key: publicJwk.x,
        private_key: privateJwk,
        created_at: new Date().toISOString(),
    };
}

async function tempRoot(t) {
    const root = await mkdtemp(path.join(os.tmpdir(), "nr-identity-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    return root;
}

function identityPath(agentDir) {
    return path.join(
        agentDir,
        "plugins",
        "noderooms",
        "guest-identity.json",
    );
}

async function writeLegacyIdentity(stateDir, identity) {
    const directory = path.join(stateDir, "plugins", "noderooms");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const filePath = path.join(directory, "guest-identity.json");
    await writeFile(filePath, `${JSON.stringify(identity, null, 2)}\n`, {
        encoding: "utf8",
        mode: 0o600,
    });
    return filePath;
}

test("legacy single-Agent identity migrates exactly once to the canonical default Agent", async (t) => {
    const root = await tempRoot(t);
    const stateDir = path.join(root, "state");
    const mainDir = path.join(stateDir, "agents", "main", "agent");
    const otherDir = path.join(stateDir, "agents", "other", "agent");
    const legacyIdentity = createIdentityFixture();
    const legacyPath = await writeLegacyIdentity(stateDir, legacyIdentity);

    const otherIdentity = await loadOrCreateGuestIdentity({
        agentId: "other",
        agentDir: otherDir,
        legacyStateDir: stateDir,
        legacyIdentityOwnerAgentId: "main",
    });
    assert.notEqual(otherIdentity.runtime_id, legacyIdentity.runtime_id);
    assert.equal(
        JSON.parse(await readFile(legacyPath, "utf8")).runtime_id,
        legacyIdentity.runtime_id,
    );

    const migrated = await loadOrCreateGuestIdentity({
        agentId: "main",
        agentDir: mainDir,
        legacyStateDir: stateDir,
        legacyIdentityOwnerAgentId: "main",
    });
    assert.equal(migrated.runtime_id, legacyIdentity.runtime_id);
    assert.equal(migrated.public_key, legacyIdentity.public_key);
    await assert.rejects(readFile(legacyPath, "utf8"), { code: "ENOENT" });

    const persistedPath = identityPath(mainDir);
    const persisted = JSON.parse(await readFile(persistedPath, "utf8"));
    assert.equal(persisted.runtime_id, legacyIdentity.runtime_id);
    assert.equal((await stat(persistedPath)).mode & 0o777, 0o600);
    assert.equal((await stat(path.dirname(persistedPath))).mode & 0o777, 0o700);

    const reopened = await loadOrCreateGuestIdentity({
        agentId: "main",
        agentDir: mainDir,
        legacyStateDir: stateDir,
        legacyIdentityOwnerAgentId: "main",
    });
    assert.equal(reopened.runtime_id, legacyIdentity.runtime_id);
    assert.notEqual(reopened.runtime_id, otherIdentity.runtime_id);
});

test("reinstall preserves only the same Agent key and rotation cannot reuse another Agent key", async (t) => {
    const root = await tempRoot(t);
    const stateDir = path.join(root, "state");
    const alphaDir = path.join(stateDir, "agents", "alpha", "agent");
    const betaDir = path.join(stateDir, "agents", "beta", "agent");
    const context = (agentId, agentDir) => ({
        agentId,
        agentDir,
        legacyStateDir: stateDir,
        legacyIdentityOwnerAgentId: "alpha",
    });

    const alpha = await loadOrCreateGuestIdentity(context("alpha", alphaDir));
    const beta = await loadOrCreateGuestIdentity(context("beta", betaDir));
    const betaAfterReinstall = await loadOrCreateGuestIdentity(
        context("beta", betaDir),
    );
    assert.equal(betaAfterReinstall.runtime_id, beta.runtime_id);
    assert.equal(betaAfterReinstall.public_key, beta.public_key);
    assert.notEqual(beta.public_key, alpha.public_key);

    await rm(identityPath(betaDir));
    const rotatedBeta = await loadOrCreateGuestIdentity(
        context("beta", betaDir),
    );
    assert.notEqual(rotatedBeta.runtime_id, beta.runtime_id);
    assert.notEqual(rotatedBeta.public_key, beta.public_key);
    assert.notEqual(rotatedBeta.runtime_id, alpha.runtime_id);
    assert.notEqual(rotatedBeta.public_key, alpha.public_key);
});

test("invalid Agent-scoped identity fails closed without silent key replacement", async (t) => {
    const root = await tempRoot(t);
    const stateDir = path.join(root, "state");
    const agentDir = path.join(stateDir, "agents", "main", "agent");
    const context = {
        agentId: "main",
        agentDir,
        legacyStateDir: stateDir,
        legacyIdentityOwnerAgentId: "main",
    };
    await loadOrCreateGuestIdentity(context);
    const filePath = identityPath(agentDir);
    await writeFile(filePath, "{\"version\":1,\"runtime_id\":\"corrupt\"}\n", {
        encoding: "utf8",
        mode: 0o600,
    });

    await assert.rejects(
        loadOrCreateGuestIdentity(context),
        (error) => error?.code === "GUEST_IDENTITY_INVALID",
    );
    assert.equal(
        await readFile(filePath, "utf8"),
        "{\"version\":1,\"runtime_id\":\"corrupt\"}\n",
    );
});
