import path from "node:path";

import { NodeRoomsError } from "./contracts.js";

export const MAX_AGENT_RUNTIMES = 256;
export const OPENCLAW_AGENT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;

const EMPTY_RUNTIME_STATE = Object.freeze({
    guest_pass_held_in_memory: false,
    guest_id: null,
    guest_agent_id: null,
    guest_agent_slug: null,
    guest_pass_expires_at: null,
    provider_session_held_in_memory: false,
    arrival_id: null,
    session_id: null,
    session_expires_at: null,
    run_lease_held_in_memory: false,
    run_id: null,
    run_lease_expires_at: null,
    run_lease_policy_id: null,
    run_lease_scopes: Object.freeze([]),
    run_lease_rooms: Object.freeze([]),
    run_lease_bound_agent_id: null,
    restart_behavior: "all_secrets_are_discarded_fail_closed",
});

export function requireCanonicalOpenClawAgentId(value) {
    if (typeof value !== "string") {
        throw new NodeRoomsError(
            "OPENCLAW_AGENT_CONTEXT_REQUIRED",
            "A trusted canonical OpenClaw Agent id is required for this NodeRooms operation.",
        );
    }
    const agentId = value.trim();
    if (!OPENCLAW_AGENT_ID_PATTERN.test(agentId)
        || agentId !== agentId.toLowerCase()) {
        throw new NodeRoomsError(
            "OPENCLAW_AGENT_ID_INVALID",
            "The OpenClaw Agent id is not in canonical form.",
        );
    }
    return agentId;
}

export function requireCanonicalOpenClawAgentDir(value) {
    if (typeof value !== "string" || !value.trim()) {
        throw new NodeRoomsError(
            "OPENCLAW_AGENT_DIRECTORY_REQUIRED",
            "The trusted OpenClaw Agent private directory is required for this NodeRooms operation.",
        );
    }
    const raw = value.trim();
    if (!path.isAbsolute(raw)) {
        throw new NodeRoomsError(
            "OPENCLAW_AGENT_DIRECTORY_INVALID",
            "The OpenClaw Agent private directory must be an absolute path.",
        );
    }
    return path.resolve(raw);
}

function assertRuntime(runtime, agentId, agentDir) {
    if (!runtime
        || typeof runtime !== "object"
        || !runtime.sdk
        || !runtime.secretStore
        || typeof runtime.secretStore.safeState !== "function"
        || typeof runtime.clearSecrets !== "function") {
        throw new NodeRoomsError(
            "AGENT_RUNTIME_CREATE_FAILED",
            "The isolated NodeRooms Agent runtime could not be created safely.",
        );
    }
    return {
        ...runtime,
        agentId,
        agentDir,
    };
}

export class AgentRuntimeRegistry {
    constructor(options) {
        if (!options || typeof options.createRuntime !== "function") {
            throw new NodeRoomsError(
                "AGENT_RUNTIME_FACTORY_REQUIRED",
                "An isolated NodeRooms Agent runtime factory is required.",
            );
        }
        const maxRuntimes = options.maxRuntimes ?? MAX_AGENT_RUNTIMES;
        if (!Number.isSafeInteger(maxRuntimes)
            || maxRuntimes < 1
            || maxRuntimes > MAX_AGENT_RUNTIMES) {
            throw new NodeRoomsError(
                "AGENT_RUNTIME_LIMIT_INVALID",
                "The NodeRooms Agent runtime limit is invalid.",
            );
        }
        this.createRuntime = options.createRuntime;
        this.maxRuntimes = maxRuntimes;
        this.runtimes = new Map();
        this.agentIdByDir = new Map();
    }

    resolve(context) {
        const agentId = requireCanonicalOpenClawAgentId(context?.agentId);
        const agentDir = requireCanonicalOpenClawAgentDir(context?.agentDir);
        const existing = this.runtimes.get(agentId);
        if (existing) {
            if (existing.agentDir !== agentDir) {
                throw new NodeRoomsError(
                    "AGENT_RUNTIME_DIRECTORY_DRIFT",
                    "The OpenClaw Agent private directory changed during this Gateway process.",
                );
            }
            return existing;
        }

        const boundAgentId = this.agentIdByDir.get(agentDir);
        if (boundAgentId && boundAgentId !== agentId) {
            throw new NodeRoomsError(
                "AGENT_RUNTIME_DIRECTORY_COLLISION",
                "Two OpenClaw Agents cannot share one NodeRooms private runtime directory.",
            );
        }
        if (this.runtimes.size >= this.maxRuntimes) {
            throw new NodeRoomsError(
                "AGENT_RUNTIME_LIMIT_REACHED",
                "The bounded NodeRooms Agent runtime registry is full.",
            );
        }

        const runtime = assertRuntime(
            this.createRuntime({ agentId, agentDir }),
            agentId,
            agentDir,
        );
        this.runtimes.set(agentId, runtime);
        this.agentIdByDir.set(agentDir, agentId);
        return runtime;
    }

    safeState(agentIdInput) {
        let agentId;
        try {
            agentId = requireCanonicalOpenClawAgentId(agentIdInput);
        }
        catch {
            return {
                ...EMPTY_RUNTIME_STATE,
                openclaw_agent_id: null,
                agent_runtime_loaded: false,
            };
        }
        const runtime = this.runtimes.get(agentId);
        return {
            ...(runtime ? runtime.secretStore.safeState() : EMPTY_RUNTIME_STATE),
            openclaw_agent_id: agentId,
            agent_runtime_loaded: Boolean(runtime),
        };
    }

    clearAll() {
        for (const runtime of this.runtimes.values()) {
            runtime.clearSecrets();
        }
        this.runtimes.clear();
        this.agentIdByDir.clear();
    }

    size() {
        return this.runtimes.size;
    }
}
