export type TrustLayerMode = "off" | "observe" | "enforce";
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
};
export declare function normalizeTrustLayerConfig(pluginConfig: unknown): TrustLayerConfig;
export declare function buildTrustRuleIndex(config: TrustLayerConfig): Map<string, TrustLayerRule>;
export declare function evaluateTrustDecision(input: {
    mode: TrustLayerMode;
    rule?: TrustLayerRule;
    agentId?: string;
    safeState: Record<string, unknown>;
}): {
    decision: string;
};
export declare function isBlockingDecision(decision: string): boolean;
