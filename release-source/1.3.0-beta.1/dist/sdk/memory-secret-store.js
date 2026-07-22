import { NodeRoomsError } from "../contracts.js";
function isExpired(isoTime) {
    const parsed = Date.parse(isoTime);
    return !Number.isFinite(parsed) || parsed <= Date.now();
}
export function createInMemorySecretStore() {
    let session;
    let runLease;
    let guestPass;
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
    return {
        setSession(next) {
            clearProviderSecrets();
            session = { ...next };
        },
        requireSession() {
            if (!session || !session.sessionSecret || isExpired(session.sessionExpiresAt)) {
                clearProviderSecrets();
                throw new NodeRoomsError("PROVIDER_SESSION_UNAVAILABLE", "No live NodeRooms provider session is held in memory. Ask the Owner for a new one-use invite and claim it first.");
            }
            return { ...session };
        },
        currentArrivalId() {
            return session && !isExpired(session.sessionExpiresAt) ? session.arrivalId : undefined;
        },
        setRunLease(next) {
            if (runLease) {
                runLease.runSecret = "";
                runLease.leaseHeaders = {};
            }
            runLease = { ...next, leaseHeaders: { ...next.leaseHeaders } };
        },
        setGuestPass(next) {
            if (guestPass) {
                guestPass.guestPass = "";
            }
            guestPass = { ...next };
        },
        requireGuestPass() {
            if (!guestPass || !guestPass.guestPass || isExpired(guestPass.expiresAt)) {
                clearGuestPass();
                throw new NodeRoomsError("GUEST_PASS_UNAVAILABLE", "No live NodeRooms Guest Pass is held in memory. Enter NodeRooms again first.");
            }
            return { ...guestPass };
        },
        guestHeaders() {
            return { Authorization: `Bearer ${this.requireGuestPass().guestPass}` };
        },
        safeState() {
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
            return {
                guest_pass_held_in_memory: Boolean(guestPass?.guestPass),
                guest_id: guestPass?.guestId ?? null,
                guest_agent_id: guestPass?.agentId ?? null,
                guest_agent_slug: guestPass?.agentSlug ?? null,
                guest_pass_expires_at: guestPass?.expiresAt ?? null,
                provider_session_held_in_memory: Boolean(session?.sessionSecret),
                arrival_id: session?.arrivalId ?? null,
                session_id: session?.sessionId ?? null,
                session_expires_at: session?.sessionExpiresAt ?? null,
                run_lease_held_in_memory: Boolean(runLease?.runSecret),
                run_id: runLease?.runId ?? null,
                run_lease_expires_at: runLease?.expiresAt ?? null,
                restart_behavior: "all_secrets_are_discarded_fail_closed",
            };
        },
        clearSecrets() {
            clearGuestPass();
            clearProviderSecrets();
        },
    };
}
