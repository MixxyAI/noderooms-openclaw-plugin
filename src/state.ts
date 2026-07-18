import { NodeRoomsError } from "./contracts.js";

type SessionState = {
  arrivalId: string;
  sessionId: string;
  sessionSecret: string;
  sessionExpiresAt: string;
};

type RunLeaseState = {
  runId: string;
  runSecret: string;
  expiresAt: string;
  leaseHeaders: Record<string, string>;
};

let session: SessionState | undefined;
let runLease: RunLeaseState | undefined;

function isExpired(isoTime: string): boolean {
  const parsed = Date.parse(isoTime);
  return !Number.isFinite(parsed) || parsed <= Date.now();
}

export function setSession(next: SessionState): void {
  clearSecrets();
  session = { ...next };
}

export function requireSession(): SessionState {
  if (!session || !session.sessionSecret || isExpired(session.sessionExpiresAt)) {
    clearSecrets();
    throw new NodeRoomsError(
      "PROVIDER_SESSION_UNAVAILABLE",
      "No live NodeRooms provider session is held in memory. Ask the Owner for a new one-use invite and claim it first.",
    );
  }
  return session;
}

export function currentArrivalId(): string | undefined {
  return session && !isExpired(session.sessionExpiresAt) ? session.arrivalId : undefined;
}

export function setRunLease(next: RunLeaseState): void {
  if (runLease) {
    runLease.runSecret = "";
    runLease.leaseHeaders = {};
  }
  runLease = { ...next, leaseHeaders: { ...next.leaseHeaders } };
}

export function safeState(): Record<string, unknown> {
  if (session && isExpired(session.sessionExpiresAt)) {
    session.sessionSecret = "";
    session = undefined;
  }
  if (runLease && isExpired(runLease.expiresAt)) {
    runLease.runSecret = "";
    runLease.leaseHeaders = {};
    runLease = undefined;
  }
  const liveSession = session && !isExpired(session.sessionExpiresAt) ? session : undefined;
  const liveLease = runLease && !isExpired(runLease.expiresAt) ? runLease : undefined;
  return {
    provider_session_held_in_memory: Boolean(liveSession?.sessionSecret),
    arrival_id: liveSession?.arrivalId ?? null,
    session_id: liveSession?.sessionId ?? null,
    session_expires_at: liveSession?.sessionExpiresAt ?? null,
    run_lease_held_in_memory: Boolean(liveLease?.runSecret),
    run_id: liveLease?.runId ?? null,
    run_lease_expires_at: liveLease?.expiresAt ?? null,
    restart_behavior: "all_secrets_are_discarded_fail_closed",
  };
}

export function clearSecrets(): void {
  if (session) {
    session.sessionSecret = "";
  }
  if (runLease) {
    runLease.runSecret = "";
    runLease.leaseHeaders = {};
  }
  session = undefined;
  runLease = undefined;
}
