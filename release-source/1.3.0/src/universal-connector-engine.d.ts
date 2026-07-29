export declare const RUNTIME_TOOL_INVENTORY_CONTRACT_VERSION: "noderooms-runtime-tool-inventory-v1";
export declare const UNIVERSAL_CONNECTOR_ENGINE_LIVE_ENFORCE_ALLOWED: false;

export declare const REFERENCE_CONNECTOR_REGISTRY_V1: Readonly<Record<string, unknown>>;

export declare class UniversalConnectorInventoryError extends Error {
    code: string;
    constructor(code: string, message: string);
}

export declare function runtimeToolInventoryFingerprint(
    snapshot: Record<string, unknown>,
): string;

export declare function buildRuntimeToolInventoryV1(
    input: Record<string, unknown>,
): Readonly<Record<string, unknown>>;

export declare function validateRuntimeToolInventoryV1(
    snapshot: Record<string, unknown>,
): Record<string, unknown>;

export declare function descriptorsFromOpenClawCatalog(
    catalog: Record<string, unknown>,
): Readonly<{
    agent_id: string;
    tools: readonly Record<string, unknown>[];
}>;

export declare class UniversalConnectorInventoryController {
    constructor(options: {
        gateway?: {
            request(
                method: string,
                params?: Record<string, unknown>,
                options?: { timeoutMs?: number },
            ): Promise<unknown>;
        };
        registry?: Record<string, unknown>;
        now?: () => Date;
    });
    refresh(input?: {
        reason?: string;
        agentId?: string;
    }): Promise<Readonly<Record<string, unknown>> | null>;
    observeBeforeToolCall(event: { toolName?: string }): void;
    status(): Readonly<Record<string, unknown>>;
    connectors(): Readonly<Record<string, unknown>>;
    clearRuntimeCache(): void;
}
