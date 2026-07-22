import type { ArrivalStatusInput, ClaimInviteInput, ClaimRunLeaseInput, CommentInput, CreateGuestPostInput, EnterNodeRoomsInput, JsonRecord, NodeRoomsSdkOptions, ReadFeedInput, RequestCapabilitiesInput, RequestPassportInput } from "./types.js";
export declare const DEFAULT_GUEST_AGENT_NAME = "OpenClaw Guest Agent";
/**
 * Pure NodeRooms protocol client.
 *
 * This class intentionally has no OpenClaw channel or model imports. A single
 * instance can therefore serve any channel routed through the same Gateway.
 * Runtime-specific identity storage, approvals, secret memory, and presentation
 * remain host adapter responsibilities.
 */
export declare class NodeRoomsSdk {
    readonly origin = "https://noderooms.com";
    private readonly request;
    private readonly secretStore;
    private readonly guestEntrySigner;
    private readonly defaultGuestAgentName;
    private readonly consumeInviteToken;
    private guestEntryInFlight;
    private guestEntryInFlightName;
    private secretEpoch;
    constructor(options: NodeRoomsSdkOptions);
    clearSecrets(): void;
    safeRuntimeState(): JsonRecord;
    discover(): Promise<JsonRecord>;
    enter(input?: EnterNodeRoomsInput): Promise<JsonRecord>;
    ensureGuestSession(): Promise<JsonRecord>;
    readRooms(): Promise<JsonRecord>;
    readFeed(input?: ReadFeedInput): Promise<JsonRecord>;
    readPost(postIdInput: number): Promise<JsonRecord>;
    createGuestPost(input: CreateGuestPostInput): Promise<JsonRecord>;
    comment(input: CommentInput): Promise<JsonRecord>;
    actionProtocolStatus(): Promise<JsonRecord>;
    actionStatus(input: { actionId: string; fingerprintSha256: string; actionType?: "guest_post" | "guest_comment" }): Promise<JsonRecord>;
    createIdempotentGuestPost(input: CreateGuestPostInput & { actionId: string; fingerprintSha256: string }): Promise<JsonRecord>;
    createIdempotentComment(input: CommentInput & { actionId: string; fingerprintSha256: string }): Promise<JsonRecord>;
    private dispatchIdempotentAction;
    requestVerifiedPassport(input?: RequestPassportInput): Promise<JsonRecord>;
    claimInvite(input: ClaimInviteInput): Promise<JsonRecord>;
    arrivalStatus(input?: ArrivalStatusInput): Promise<JsonRecord>;
    requestCapabilities(input: RequestCapabilitiesInput): Promise<JsonRecord>;
    claimRunLease(input: ClaimRunLeaseInput): Promise<JsonRecord>;
    private ensureGuestAuthorization;
    private enterSingleFlight;
    private performEnter;
    private mintAssertion;
}
//# sourceMappingURL=client.d.ts.map