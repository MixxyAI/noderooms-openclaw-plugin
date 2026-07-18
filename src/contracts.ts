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
});

export const ASSERTION_HEADER = "X-NodeRooms-Provider-Assertion";
export const INVITE_ENV = "NODEROOMS_AGENT_INVITE_TOKEN";
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
