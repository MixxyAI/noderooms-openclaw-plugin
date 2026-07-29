import type { JsonRecord } from "./passport-runtime-binding.js";

export declare const LIVE_WORK_RUNTIME_ARMED_ALLOWED: false;
export declare const SAFE_WORK_RUNTIME_CONTRACT_VERSION:
    "noderooms-safe-work-runtime-binding-v1";

export type SafeWorkRuntimeConfig = Readonly<{
    mode: "off" | "shadow";
    boardId: string;
    maxEntries: number;
    armedActivationAllowed: false;
    armedActivationBlocked: boolean;
    automaticDispatchAllowed: false;
    automaticExternalWriteAllowed: false;
    automaticRetryAllowed: false;
}>;

export type RuntimeContextFingerprints = Readonly<{
    sessionFingerprintSha256: string;
    requesterOriginFingerprintSha256: string;
}>;

export type WorkRuntimeToolContext = {
    senderIsOwner?: boolean;
    agentId?: string;
    sessionKey?: string;
    messageChannel?: string;
    requesterSenderId?: string;
    deliveryContext?: JsonRecord;
};

export type WorkRuntimeCommandContext = {
    senderIsOwner?: boolean;
    isAuthorizedSender?: boolean;
    agentId?: string;
    sessionKey?: string;
    channel?: string;
    senderId?: string;
};

export type ManagedTaskFlowRuntime = {
    fromToolContext(ctx: WorkRuntimeToolContext): {
        createManaged(params: JsonRecord): JsonRecord;
    };
    bindSession(params: {
        sessionKey: string;
        requesterOrigin?: JsonRecord;
    }): {
        get(flowId: string): JsonRecord | undefined;
        requestCancel(params: JsonRecord): JsonRecord;
    };
};

export declare function normalizeSafeWorkRuntimeConfig(
    pluginConfig?: JsonRecord,
): SafeWorkRuntimeConfig;

export declare function runtimeContextFingerprints(input: {
    agentId: string;
    sessionKey: string;
    channel: string;
    requesterSenderId: string;
}): RuntimeContextFingerprints;

export declare function workboardCreateParamsFingerprint(
    params: JsonRecord,
): string;

export declare class SafeWorkRuntimeBindingController {
    constructor(options: {
        config: SafeWorkRuntimeConfig;
        stateFilePath: string;
        taskRuntime: ManagedTaskFlowRuntime;
        now?: () => number;
    });
    preflight(): JsonRecord;
    prepare(
        ctx: WorkRuntimeToolContext,
        workItemJson: string,
    ): Promise<JsonRecord>;
    beforeToolCall(
        event: JsonRecord,
        ctx?: JsonRecord,
    ): Promise<JsonRecord | undefined>;
    afterToolCall(event: JsonRecord): Promise<void>;
    list(ctx: WorkRuntimeCommandContext): Promise<JsonRecord>;
    reconcile(
        bindingId: string,
        ctx: WorkRuntimeCommandContext,
    ): Promise<JsonRecord>;
    cancel(
        bindingId: string,
        ctx: WorkRuntimeCommandContext,
    ): Promise<JsonRecord>;
    clearRuntimeCache(): void;
}
