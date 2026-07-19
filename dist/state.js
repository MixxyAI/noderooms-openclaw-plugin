import { NodeRoomsError } from "./contracts.js";
let session;
let runLease;
let guestPass;
function isExpired(isoTime) {
    const parsed = Date.parse(isoTime);
    return !Number.isFinite(parsed) || parsed <= Date.now();
}
export function setSession(next) {
    clearProviderSecrets();
    session = { ...next };
}
export function requireSession() {
    if (!session || !session.sessionSecret || isExpired(session.sessionExpiresAt)) {
        clearProviderSecrets();
        throw new NodeRoomsError("PROVIDER_SESSION_UNAVAILABLE", "No live NodeRooms provider session is held in memory. Ask the Owner for a new one-use invite and claim it first.");
    }
    return session;
}
export function currentArrivalId() {
    return session && !isExpired(session.sessionExpiresAt) ? session.arrivalId : undefined;
}
export function setRunLease(next) {
    if (runLease) {
        runLease.runSecret = "";
        runLease.leaseHeaders = {};
    }
    runLease = { ...next, leaseHeaders: { ...next.leaseHeaders } };
}
export function setGuestPass(next) {
    if (guestPass) {
        guestPass.guestPass = "";
    }
    guestPass = { ...next };
}
export function requireGuestPass() {
    if (!guestPass || !guestPass.guestPass || isExpired(guestPass.expiresAt)) {
        clearGuestPass();
        throw new NodeRoomsError("GUEST_PASS_UNAVAILABLE", "No live NodeRooms Guest Pass is held in memory. Enter NodeRooms again first.");
    }
    return { ...guestPass };
}
export function guestHeaders() {
    return { Authorization: `Bearer ${requireGuestPass().guestPass}` };
}
export function safeState() {
    if (session && isExpired(session.sessionExpiresAt)) {
        session.sessionSecret = "";
        session = undefined;
    }
    if (runLease && isExpired(runLease.expiresAt)) {
        runLease.runSecret = "";
        runLease.leaseHeaders = {};
        runLease = undefined;
    }
    if (guestPass && isExpired(guestPass.expiresAt)) {
        guestPass.guestPass = "";
        guestPass = undefined;
    }
    const liveSession = session && !isExpired(session.sessionExpiresAt) ? session : undefined;
    const liveLease = runLease && !isExpired(runLease.expiresAt) ? runLease : undefined;
    const liveGuest = guestPass && !isExpired(guestPass.expiresAt) ? guestPass : undefined;
    return {
        guest_pass_held_in_memory: Boolean(liveGuest?.guestPass),
        guest_id: liveGuest?.guestId ?? null,
        guest_agent_id: liveGuest?.agentId ?? null,
        guest_agent_slug: liveGuest?.agentSlug ?? null,
        guest_pass_expires_at: liveGuest?.expiresAt ?? null,
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
export function clearSecrets() {
    clearGuestPass();
    clearProviderSecrets();
}
function clearGuestPass() {
    if (guestPass) {
        guestPass.guestPass = "";
    }
    guestPass = undefined;
}
function clearProviderSecrets() {
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
//# sourceMappingURL=state.js.map