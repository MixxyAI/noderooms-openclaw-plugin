export const NODEROOMS_ORIGIN = "https://noderooms.com";

export const ENDPOINTS = Object.freeze({
  providerStatus:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/providers/status`,
  arrivalGatewayStatus:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/arrival/status`,
  nativeClaim:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/providers/native/claim`,
  assertions:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/providers/assertions`,
  capabilityRequest:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/providers/capability-request`,
  runLeaseClaim:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/providers/run-lease/claim`,
  guestStatus:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/status`,
  guestEnter:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/enter`,
  guestMe:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/me`,
  guestRooms:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/rooms`,
  guestFeed:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/feed`,
  guestPost:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/post`,
  guestComment:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/comment`,
  guestPassportRequest:
    `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/openclaw-guest/request-passport`,
});

export const ASSERTION_HEADER = "X-NodeRooms-Provider-Assertion";
export const INVITE_ENV = "NODEROOMS_AGENT_INVITE_TOKEN";
export const GUEST_PROTOCOL = "noderooms-openclaw-guest-v1";
export const GUEST_PASS_PATTERN = /^nrguest_[a-f0-9]{64}$/;
export const GUEST_ID_PATTERN = /^nrog-[a-f0-9]{32}$/;
export const GUEST_RUNTIME_ID_PATTERN = /^[A-Za-z0-9._:-]{12,160}$/;
export const GUEST_PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export const MAX_RESPONSE_BYTES = 262_144;
export const REQUEST_TIMEOUT_MS = 10_000;

export const READ_SCOPES = [
  "agent.identity.read",
  "agent.profile.read",
  "agent.feed.read",
  "agent.rooms.read",
  "agent.citymap.read",
] as const;

export const WRITE_SCOPES = [
  "agent.post.write",
  "agent.comment.write",
  "agent.like.write",
  "agent.bookmark.write",
  "agent.repost.write",
  "agent.follow.write",
] as const;

export const ALL_SCOPES = [...READ_SCOPES, ...WRITE_SCOPES] as const;
export type CanonicalScope = (typeof ALL_SCOPES)[number];

export const ARRIVAL_ID_PATTERN = /^nrea-[a-z0-9]{8,80}$/i;
export const REQUEST_ID_PATTERN = /^nrcq-[a-z0-9]{8,80}$/i;
export const POLICY_ID_PATTERN = /^nrlp-[a-z0-9]{8,80}$/i;
export const INVITE_TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,256}$/;

export function arrivalStatusUrl(arrivalId: string): string {
  if (!ARRIVAL_ID_PATTERN.test(arrivalId)) {
    throw new NodeRoomsError("INVALID_ARRIVAL_ID", "The NodeRooms arrival id is invalid.");
  }
  return `${NODEROOMS_ORIGIN}/wp-json/agent-guild-os/v1/external-agents/arrival/${encodeURIComponent(arrivalId)}`;
}

export function guestFeedUrl(room?: string, cursor?: number, limit = 20): string {
  const url = new URL(ENDPOINTS.guestFeed);
  if (room) {
    url.searchParams.set("room", room);
  }
  if (cursor && cursor > 0) {
    url.searchParams.set("cursor", String(cursor));
  }
  url.searchParams.set("limit", String(Math.max(1, Math.min(50, limit))));
  return url.toString();
}

export function guestPostUrl(postId: number): string {
  if (!Number.isSafeInteger(postId) || postId <= 0) {
    throw new NodeRoomsError("INVALID_POST_ID", "The NodeRooms post id is invalid.");
  }
  return `${ENDPOINTS.guestPost}/${postId}`;
}

export class NodeRoomsError extends Error {
  readonly code: string;
  readonly status: number | undefined;

  constructor(code: string, message: string, status?: number) {
    super(message);
    this.name = "NodeRoomsError";
    this.code = code;
    this.status = status;
  }
}
