import type { TrustLayerConfig } from "./trust-policy.js";
import type { TrustEventLedger } from "./trust-ledger.js";
export declare class NodeRoomsTrustMiddleware {
    private config;
    private ruleIndex;
    private safeState;
    private ledger;
    private ledgerHealthy;
    private record;
    constructor(options: {
        config: TrustLayerConfig;
        safeState: (agentId?: string) => Record<string, unknown>;
        ledger: TrustEventLedger;
    });
    beforeToolCall(event: Record<string, any>, ctx?: Record<string, any>): Promise<Record<string, unknown> | undefined>;
    afterToolCall(event: Record<string, any>, ctx?: Record<string, any>): Promise<void>;
    status(agentId?: string): Promise<Record<string, unknown>>;
    clearRuntimeCache(): void;
}
