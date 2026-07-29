import type { JsonRecord, NodeRoomsSecretStore } from "./sdk/types.js";

export declare const MAX_AGENT_RUNTIMES = 256;
export declare const OPENCLAW_AGENT_ID_PATTERN: RegExp;

export declare function requireCanonicalOpenClawAgentId(value: unknown): string;
export declare function requireCanonicalOpenClawAgentDir(value: unknown): string;

export type IsolatedAgentRuntime = {
    agentId: string;
    agentDir: string;
    sdk: unknown;
    secretStore: NodeRoomsSecretStore;
    clearSecrets(): void;
};

export type AgentRuntimeRegistryOptions = {
    createRuntime(context: {
        agentId: string;
        agentDir: string;
    }): Omit<IsolatedAgentRuntime, "agentId" | "agentDir">;
    maxRuntimes?: number;
};

export declare class AgentRuntimeRegistry {
    private readonly createRuntime;
    private readonly maxRuntimes;
    private readonly runtimes;
    private readonly agentIdByDir;
    constructor(options: AgentRuntimeRegistryOptions);
    resolve(context: {
        agentId?: unknown;
        agentDir?: unknown;
    }): IsolatedAgentRuntime;
    safeState(agentId?: unknown): JsonRecord;
    clearAll(): void;
    size(): number;
}
