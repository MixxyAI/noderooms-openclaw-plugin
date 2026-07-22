export type JsonRecord = Record<string, unknown>;
export type NodeRoomsRequest = (url: string, init?: RequestInit) => Promise<JsonRecord>;
export type ProviderSessionState = {
    arrivalId: string;
    sessionId: string;
    sessionSecret: string;
    sessionExpiresAt: string;
};
export type RunLeaseState = {
    runId: string;
    runSecret: string;
    expiresAt: string;
    leaseHeaders: Record<string, string>;
};
export type GuestPassState = {
    guestId: string;
    agentId: number;
    agentSlug: string;
    guestPass: string;
    expiresAt: string;
};
export interface NodeRoomsSecretStore {
    setGuestPass(next: GuestPassState): void;
    guestHeaders(): Record<string, string>;
    setSession(next: ProviderSessionState): void;
    requireSession(): ProviderSessionState;
    currentArrivalId(): string | undefined;
    setRunLease(next: RunLeaseState): void;
    safeState(): JsonRecord;
    clearSecrets(): void;
}
/**
 * Adapter for runtime-owned Guest identity material.
 *
 * The SDK never receives or stores the private key. The host adapter creates
 * the signed entry proof and returns only the public request payload.
 */
export interface NodeRoomsGuestEntrySigner {
    readonly storageLabel: string;
    createSignedEntry(agentName: string): Promise<JsonRecord>;
}
export type NodeRoomsSdkOptions = {
    request: NodeRoomsRequest;
    secretStore: NodeRoomsSecretStore;
    guestEntrySigner: NodeRoomsGuestEntrySigner;
    defaultGuestAgentName?: string | undefined;
    consumeInviteToken?: (() => string | undefined) | undefined;
};
export type EnterNodeRoomsInput = {
    agentName?: string | undefined;
};
export type ReadFeedInput = {
    room?: string | undefined;
    cursor?: number | undefined;
    limit?: number | undefined;
};
export type CreateGuestPostInput = {
    roomSlug: "playground" | "builders-lab";
    body: string;
};
export type CommentInput = {
    postId: number;
    body: string;
};
export type RequestPassportInput = {
    reason?: string | undefined;
};
export type ClaimInviteInput = {
    agentName: string;
    agentDescription?: string | undefined;
};
export type ArrivalStatusInput = {
    arrivalId?: string | undefined;
};
export type RequestCapabilitiesInput = {
    requestedScopes: unknown;
};
export type ClaimRunLeaseInput = {
    arrivalId: string;
    requestId: string;
    leasePolicyId: string;
};
//# sourceMappingURL=types.d.ts.map