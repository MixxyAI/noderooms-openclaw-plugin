import { type CanonicalScope } from "./contracts.js";
import type { JsonRecord } from "./sdk/types.js";
export declare const ACTION_INTENT_TTL_MS: number;
export declare const ACTION_INTENT_RETENTION_MS: number;
export declare const ACTION_INTENT_COMMIT_STALE_MS: number;
export declare const ACTION_INTENT_MAX_ENTRIES = 128;
export declare const ACTION_INTENT_MAX_FILE_BYTES = 1048576;
export declare const ACTION_INTENT_ID_PATTERN: RegExp;
export type ActionIntentKind = "guest_post" | "guest_comment" | "passport_request" | "claim_invite" | "capability_request" | "run_lease_claim";
export type ActionIntentPayload = {
    kind: "guest_post";
    roomSlug: "playground" | "builders-lab";
    body: string;
} | {
    kind: "guest_comment";
    postId: number;
    body: string;
} | {
    kind: "passport_request";
    reason?: string;
} | {
    kind: "claim_invite";
    agentName: string;
    agentDescription?: string;
} | {
    kind: "capability_request";
    requestedScopes: CanonicalScope[];
} | {
    kind: "run_lease_claim";
    arrivalId: string;
    requestId: string;
    leasePolicyId: string;
};
export type ActionIntentOwner = {
    agentId: string;
    channel: string;
    requesterSenderId: string;
};
export type ActionIntentCommandOwner = {
    agentId?: string;
    channel: string;
    senderId?: string;
    senderIsOwner: boolean;
    isAuthorizedSender: boolean;
};
export type ActionIntentState = "prepared" | "committing" | "committed" | "failed" | "denied" | "expired" | "unknown";
export type PreparedActionIntent = {
    id: string;
    kind: ActionIntentKind;
    payload: ActionIntentPayload;
    owner: ActionIntentOwner;
    state: ActionIntentState;
    fingerprint: string;
    createdAtMs: number;
    expiresAtMs: number;
    commitStartedAtMs?: number;
    result?: JsonRecord;
    resultFormat?: "canonical-v1" | "legacy-v1" | "opaque-v1";
    terminalMessage?: string;
};
export type ActionIntentStoreOptions = {
    stateFilePath: string;
    now?: () => number;
};
export declare class ActionIntentStore {
    private readonly now;
    private readonly stateFilePath;
    private readonly lockFilePath;
    constructor(options: ActionIntentStoreOptions);
    prepare(payloadInput: ActionIntentPayload, owner: ActionIntentOwner): Promise<JsonRecord>;
    list(owner: ActionIntentCommandOwner): Promise<JsonRecord>;
    deny(intentId: string, owner: ActionIntentCommandOwner): Promise<JsonRecord>;
    commit(intentId: string, owner: ActionIntentCommandOwner, executor: (intent: Readonly<PreparedActionIntent>) => Promise<JsonRecord>): Promise<JsonRecord>;
    reconcile(intentId: string, owner: ActionIntentCommandOwner, resolver: (intent: Readonly<PreparedActionIntent>) => Promise<JsonRecord>): Promise<JsonRecord>;
    clearRuntimeCache(): void;
    private withLock;
    private loadStore;
    private saveStore;
    private normalizeStore;
    private requireIntent;
    private expireIfNeeded;
    private enforceCapacity;
    private tryChmod;
}
//# sourceMappingURL=action-intents.d.ts.map