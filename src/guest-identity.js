import {
    createPrivateKey,
    generateKeyPairSync,
    randomBytes,
    randomUUID,
    sign,
} from "node:crypto";
import { chmod } from "node:fs/promises";
import path from "node:path";
import {
    ensureAbsoluteDirectory,
    movePathWithCopyFallback,
    pathScope,
    privateFileStore,
} from "openclaw/plugin-sdk/security-runtime";

import {
    GUEST_PROTOCOL,
    GUEST_PUBLIC_KEY_PATTERN,
    GUEST_RUNTIME_ID_PATTERN,
    NODEROOMS_ORIGIN,
    NodeRoomsError,
} from "./contracts.js";

const IDENTITY_FILE = "guest-identity.json";
const IDENTITY_VERSION = 1;
const IDENTITY_DIRECTORY = path.join("plugins", "noderooms");
const AGENT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;

function validIdentity(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const item = value;
    const key = item.private_key;
    return item.version === IDENTITY_VERSION
        && typeof item.runtime_id === "string"
        && GUEST_RUNTIME_ID_PATTERN.test(item.runtime_id)
        && typeof item.public_key === "string"
        && GUEST_PUBLIC_KEY_PATTERN.test(item.public_key)
        && Boolean(key)
        && key?.kty === "OKP"
        && key.crv === "Ed25519"
        && key.x === item.public_key
        && typeof key.d === "string"
        && /^[A-Za-z0-9_-]{43}$/.test(key.d);
}

function createIdentity() {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicJwk = publicKey.export({ format: "jwk" });
    const privateJwk = privateKey.export({ format: "jwk" });
    if (!publicJwk.x || !GUEST_PUBLIC_KEY_PATTERN.test(publicJwk.x)) {
        throw new NodeRoomsError(
            "GUEST_IDENTITY_CREATE_FAILED",
            "OpenClaw could not create a valid Ed25519 Guest identity.",
        );
    }
    return {
        version: IDENTITY_VERSION,
        runtime_id: `openclaw-${randomUUID()}`,
        public_key: publicJwk.x,
        private_key: privateJwk,
        created_at: new Date().toISOString(),
    };
}

function identityOptions(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new NodeRoomsError(
            "GUEST_IDENTITY_CONTEXT_REQUIRED",
            "The canonical OpenClaw Agent identity context is required.",
        );
    }
    const agentId = typeof value.agentId === "string" ? value.agentId.trim() : "";
    const agentDir = typeof value.agentDir === "string" ? value.agentDir.trim() : "";
    if (!AGENT_ID_PATTERN.test(agentId)
        || agentId !== agentId.toLowerCase()
        || !path.isAbsolute(agentDir)) {
        throw new NodeRoomsError(
            "GUEST_IDENTITY_CONTEXT_INVALID",
            "The canonical OpenClaw Agent identity context is invalid.",
        );
    }
    const legacyStateDir = typeof value.legacyStateDir === "string"
        && path.isAbsolute(value.legacyStateDir.trim())
        ? path.resolve(value.legacyStateDir.trim())
        : undefined;
    const legacyIdentityOwnerAgentId =
        typeof value.legacyIdentityOwnerAgentId === "string"
            ? value.legacyIdentityOwnerAgentId.trim()
            : undefined;
    return {
        agentId,
        agentDir: path.resolve(agentDir),
        legacyStateDir,
        legacyIdentityOwnerAgentId,
    };
}

function requireValidIdentity(value, message) {
    if (!validIdentity(value)) {
        throw new NodeRoomsError("GUEST_IDENTITY_INVALID", message);
    }
    return value;
}

async function migrateLegacyIdentity(options, targetStore, targetRoot) {
    if (!options.legacyStateDir
        || options.agentId !== options.legacyIdentityOwnerAgentId) {
        return null;
    }
    const legacyRoot = path.join(
        options.legacyStateDir,
        "plugins",
        "noderooms",
    );
    if (path.resolve(legacyRoot) === path.resolve(targetRoot)) {
        return null;
    }
    const legacyStore = privateFileStore(legacyRoot);
    const legacy = await legacyStore.readJsonIfExists(
        IDENTITY_FILE,
        { maxBytes: 16_384 },
    );
    if (legacy === null) {
        return null;
    }
    requireValidIdentity(
        legacy,
        "The legacy NodeRooms Guest identity is invalid. Review and revoke it before retrying migration.",
    );

    const agentRoot = await ensureAbsoluteDirectory(options.agentDir, {
        scopeLabel: "NodeRooms Agent private identity root",
        mode: 0o700,
    });
    if (!agentRoot.ok) {
        throw new NodeRoomsError(
            "GUEST_IDENTITY_MIGRATION_FAILED",
            "The OpenClaw Agent private directory could not be prepared safely.",
        );
    }
    const scope = pathScope(agentRoot.path, {
        label: "NodeRooms Agent private identity",
    });
    const ensured = await scope.ensureDir(IDENTITY_DIRECTORY, { mode: 0o700 });
    if (!ensured.ok) {
        throw new NodeRoomsError(
            "GUEST_IDENTITY_MIGRATION_FAILED",
            "The legacy NodeRooms Guest identity could not be moved into the Agent private directory.",
        );
    }
    const sourcePath = path.join(legacyRoot, IDENTITY_FILE);
    const targetPath = path.join(targetRoot, IDENTITY_FILE);
    try {
        await movePathWithCopyFallback({
            from: sourcePath,
            to: targetPath,
            sourceHardlinks: "reject",
        });
        await chmod(targetPath, 0o600);
    }
    catch {
        throw new NodeRoomsError(
            "GUEST_IDENTITY_MIGRATION_FAILED",
            "The legacy NodeRooms Guest identity could not be moved safely. No new identity was created.",
        );
    }
    const migrated = await targetStore.readJsonIfExists(
        IDENTITY_FILE,
        { maxBytes: 16_384 },
    );
    return requireValidIdentity(
        migrated,
        "The migrated NodeRooms Guest identity failed validation.",
    );
}

export async function loadOrCreateGuestIdentity(input) {
    const options = identityOptions(input);
    const targetRoot = path.join(options.agentDir, IDENTITY_DIRECTORY);
    const store = privateFileStore(targetRoot);
    const existing = await store.readJsonIfExists(
        IDENTITY_FILE,
        { maxBytes: 16_384 },
    );
    if (existing !== null) {
        return requireValidIdentity(
            existing,
            "The Agent-scoped NodeRooms Guest identity is invalid. Remove it manually only after reviewing the file path and revoking the old Guest in NodeRooms.",
        );
    }
    const migrated = await migrateLegacyIdentity(options, store, targetRoot);
    if (migrated) {
        return migrated;
    }
    const identity = createIdentity();
    await store.writeJson(IDENTITY_FILE, identity, {
        dirMode: 0o700,
        mode: 0o600,
        maxBytes: 16_384,
        trailingNewline: true,
    });
    return identity;
}

export function createSignedGuestEntry(identity, agentName) {
    const issuedAt = Math.floor(Date.now() / 1000);
    const nonce = randomBytes(24).toString("base64url");
    const canonical = `${GUEST_PROTOCOL}\n`
        + `origin=${NODEROOMS_ORIGIN}\n`
        + `runtime_id=${identity.runtime_id}\n`
        + `agent_name=${agentName}\n`
        + `issued_at=${issuedAt}\n`
        + `nonce=${nonce}\n`
        + `public_key=${identity.public_key}`;
    const privateKey = createPrivateKey({
        key: identity.private_key,
        format: "jwk",
    });
    const signature = sign(
        null,
        Buffer.from(canonical, "utf8"),
        privateKey,
    ).toString("base64url");
    return {
        protocol_version: GUEST_PROTOCOL,
        runtime_id: identity.runtime_id,
        agent_name: agentName,
        issued_at: issuedAt,
        client_nonce: nonce,
        public_key: identity.public_key,
        signature,
    };
}
