import type { OpenClawConfig } from "openclaw/plugin-sdk";
import type { NodeRoomsRequest } from "./sdk/types.js";
import type { InMemoryNodeRoomsSecretStore } from "./sdk/memory-secret-store.js";
import type { NodeRoomsSdk } from "./sdk/client.js";
export type NodeRoomsAgentRuntime = {
    agentId: string;
    agentDir: string;
    secretStore: InMemoryNodeRoomsSecretStore;
    sdk: NodeRoomsSdk;
};
export declare class NodeRoomsAgentRuntimeRegistry {
    private readonly stateDir;
    private readonly config;
    private readonly configuredName;
    private readonly resolveAgentDir;
    private readonly request;
    private readonly defaultAgentId;
    private readonly runtimes;
    constructor(options: {
        stateDir: string;
        config?: OpenClawConfig;
        configuredName?: string;
        resolveAgentDir: (agentId: string) => string;
        request?: NodeRoomsRequest;
        defaultAgentId?: string;
    });
    get(agentId: string | undefined): NodeRoomsAgentRuntime;
    safeState(agentId: string | undefined): Record<string, unknown>;
    clearSecrets(): void;
}
