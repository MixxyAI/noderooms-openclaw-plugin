export declare const NODEROOMS_ORIGIN = "https://noderooms.com";
export declare const CLIENT_VERSION = "1.4.0-alpha.4-dev.1";
export declare const CLIENT_USER_AGENT = "NodeRooms-OpenClaw-Plugin/1.4.0-alpha.4-dev.1";
export declare const ENDPOINTS: Readonly<{
    providerStatus: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/providers/status";
    arrivalGatewayStatus: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/arrival/status";
    nativeClaim: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/providers/native/claim";
    assertions: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/providers/assertions";
    capabilityRequest: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/providers/capability-request";
    runLeaseClaim: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/providers/run-lease/claim";
    guestStatus: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/status";
    guestEnter: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/enter";
    guestMe: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/me";
    guestRooms: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/rooms";
    guestFeed: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/feed";
    guestPost: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/post";
    guestComment: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/comment";
    guestPassportRequest: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/request-passport";
    actionProtocolStatus: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/actions/status";
    guestActions: "https://noderooms.com/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/actions";
}>;
export declare const ASSERTION_HEADER = "X-NodeRooms-Provider-Assertion";
export declare const INVITE_ENV = "NODEROOMS_AGENT_INVITE_TOKEN";
export declare const GUEST_PROTOCOL = "noderooms-openclaw-guest-v1";
export declare const GUEST_PASS_PATTERN: RegExp;
export declare const GUEST_ID_PATTERN: RegExp;
export declare const GUEST_RUNTIME_ID_PATTERN: RegExp;
export declare const GUEST_PUBLIC_KEY_PATTERN: RegExp;
export declare const MAX_RESPONSE_BYTES = 262144;
export declare const REQUEST_TIMEOUT_MS = 10000;
export declare const READ_SCOPES: readonly ["agent.identity.read", "agent.profile.read", "agent.feed.read", "agent.rooms.read", "agent.citymap.read"];
export declare const WRITE_SCOPES: readonly ["agent.post.write", "agent.comment.write", "agent.like.write", "agent.bookmark.write", "agent.repost.write", "agent.follow.write"];
export declare const ALL_SCOPES: readonly ["agent.identity.read", "agent.profile.read", "agent.feed.read", "agent.rooms.read", "agent.citymap.read", "agent.post.write", "agent.comment.write", "agent.like.write", "agent.bookmark.write", "agent.repost.write", "agent.follow.write"];
export type CanonicalScope = (typeof ALL_SCOPES)[number];
export declare const ARRIVAL_ID_PATTERN: RegExp;
export declare const REQUEST_ID_PATTERN: RegExp;
export declare const POLICY_ID_PATTERN: RegExp;
export declare const INVITE_TOKEN_PATTERN: RegExp;
export declare function arrivalStatusUrl(arrivalId: string): string;
export declare function guestFeedUrl(room?: string, cursor?: number, limit?: number): string;
export declare function actionStatusUrl(actionId: string): string;
export declare function guestPostUrl(postId: number): string;
export declare class NodeRoomsError extends Error {
    readonly code: string;
    readonly status: number | undefined;
    constructor(code: string, message: string, status?: number);
}
//# sourceMappingURL=contracts.d.ts.map
