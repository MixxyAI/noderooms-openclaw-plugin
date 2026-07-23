export type TrustLayerMode = "off" | "observe";
export type TrustEvaluationMode = TrustLayerMode | "enforce";
export type TrustLayerRule = {
    toolName: string;
    requiredScope: string;
    risk: "low" | "medium" | "high" | "critical";
    approval: "none" | "allow-once";
};
export type TrustLayerConfig = {
    mode: TrustLayerMode;
    rules: readonly TrustLayerRule[];
    ledgerMaxEntries: number;
    liveEnforceAllowed: false;
    enforceActivationBlocked: boolean;
};
export declare const LIVE_ENFORCE_ALLOWED: false;
export declare function normalizeTrustLayerConfig(pluginConfig: unknown): TrustLayerConfig;
export declare function buildTrustRuleIndex(config: TrustLayerConfig): Map<string, TrustLayerRule>;
export declare function evaluateTrustDecision(input: {
    mode: TrustEvaluationMode;
    rule?: TrustLayerRule;
    agentId?: string;
    safeState: Record<string, unknown>;
}): {
    decision: string;
};
export declare function isBlockingDecision(decision: string): boolean;
