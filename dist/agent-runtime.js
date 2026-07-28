import path from "node:path";
import { INVITE_ENV, INVITE_TOKEN_PATTERN, NodeRoomsError } from "./contracts.js";
import { createSignedGuestEntry, loadOrCreateGuestIdentity } from "./guest-identity.js";
import { requestJson } from "./http.js";
import { NodeRoomsSdk } from "./sdk/client.js";
import { nonEmptyString } from "./sdk/validation.js";
import { createAgentSecretStore } from "./state.js";

function defaultAgentId(config) {
    const entries = Array.isArray(config?.agents?.list) ? config.agents.list : [];
    const configured = entries.find((entry) => entry?.default === true && nonEmptyString(entry?.id));
    return nonEmptyString(configured?.id) ?? "main";
}

function requireAgentId(agentId) {
    const normalized = nonEmptyString(agentId);
    if (!normalized) {
        throw new NodeRoomsError(
            "OPENCLAW_AGENT_CONTEXT_REQUIRED",
            "A trusted OpenClaw Agent context is required for NodeRooms runtime access.",
        );
    }
    return normalized;
}

function consumeInviteToken() {
    const token = process.env[INVITE_ENV]?.trim() ?? "";
    if (INVITE_TOKEN_PATTERN.test(token)) {
        delete process.env[INVITE_ENV];
    }
    return token;
}

export class NodeRoomsAgentRuntimeRegistry {
    constructor(options) {
        if (!path.isAbsolute(options.stateDir)) {
            throw new NodeRoomsError(
                "OPENCLAW_STATE_PATH_INVALID",
                "The OpenClaw NodeRooms state directory must be absolute.",
            );
        }
        if (typeof options.resolveAgentDir !== "function") {
            throw new NodeRoomsError(
                "OPENCLAW_AGENT_DIRECTORY_UNAVAILABLE",
                "OpenClaw did not provide an agent-scoped private directory resolver.",
            );
        }
        this.stateDir = options.stateDir;
        this.config = options.config;
        this.configuredName = nonEmptyString(options.configuredName) ?? "OpenClaw Guest Agent";
        this.resolveAgentDir = options.resolveAgentDir;
        this.request = options.request ?? requestJson;
        this.defaultAgentId = nonEmptyString(options.defaultAgentId) ?? defaultAgentId(options.config);
        this.runtimes = new Map();
    }

    get(agentId) {
        const normalizedAgentId = requireAgentId(agentId);
        const existing = this.runtimes.get(normalizedAgentId);
        if (existing) {
            return existing;
        }
        const agentDir = this.resolveAgentDir(normalizedAgentId);
        if (typeof agentDir !== "string" || !path.isAbsolute(agentDir)) {
            throw new NodeRoomsError(
                "OPENCLAW_AGENT_DIRECTORY_INVALID",
                "OpenClaw returned an invalid private directory for the active Agent.",
            );
        }
        const useLegacyFallback = normalizedAgentId === this.defaultAgentId;
        const legacyStateDir = this.stateDir;
        const secretStore = createAgentSecretStore();
        const runtime = {
            agentId: normalizedAgentId,
            agentDir,
            secretStore,
            sdk: undefined,
        };
        runtime.sdk = new NodeRoomsSdk({
            request: this.request,
            secretStore,
            defaultGuestAgentName: this.configuredName,
            guestEntrySigner: {
                storageLabel: "openclaw_agent_private_file_store",
                async createSignedEntry(agentName) {
                    const identity = await loadOrCreateGuestIdentity(agentDir, {
                        legacyStateDir,
                        allowLegacyFallback: useLegacyFallback,
                    });
                    return createSignedGuestEntry(identity, agentName);
                },
            },
            consumeInviteToken,
        });
        this.runtimes.set(normalizedAgentId, runtime);
        return runtime;
    }

    safeState(agentId) {
        return this.get(agentId).secretStore.safeState();
    }

    clearSecrets() {
        for (const runtime of this.runtimes.values()) {
            runtime.sdk.clearSecrets();
        }
    }
}
