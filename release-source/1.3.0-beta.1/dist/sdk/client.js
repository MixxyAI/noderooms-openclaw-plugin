import { ARRIVAL_ID_PATTERN, ASSERTION_HEADER, ENDPOINTS, GUEST_ID_PATTERN, GUEST_PASS_PATTERN, INVITE_ENV, INVITE_TOKEN_PATTERN, NODEROOMS_ORIGIN, NodeRoomsError, POLICY_ID_PATTERN, REQUEST_ID_PATTERN, arrivalStatusUrl, guestFeedUrl, actionStatusUrl, guestPostUrl, } from "../contracts.js";
import { jsonBody, pick, pinnedNodeRoomsUrl } from "../http.js";
import { actionHeaders, assertActionIdentity, validateActionProtocolStatus, validateCanonicalReceipt } from "./action-protocol.js";
import { assertId, boundedString, nonEmptyString, optionalBoundedString, optionalPositiveInteger, optionalRoomSlug, positiveInteger, requestedScopes, } from "./validation.js";
export const DEFAULT_GUEST_AGENT_NAME = "OpenClaw Guest Agent";
/**
 * Pure NodeRooms protocol client.
 *
 * This class intentionally has no OpenClaw channel or model imports. A single
 * instance can therefore serve any channel routed through the same Gateway.
 * Runtime-specific identity storage, approvals, secret memory, and presentation
 * remain host adapter responsibilities.
 */
export class NodeRoomsSdk {
    origin = NODEROOMS_ORIGIN;
    request;
    secretStore;
    guestEntrySigner;
    defaultGuestAgentName;
    consumeInviteToken;
    guestEntryInFlight;
    guestEntryInFlightName;
    secretEpoch = 0;
    constructor(options) {
        this.request = options.request;
        this.secretStore = options.secretStore;
        this.guestEntrySigner = options.guestEntrySigner;
        this.defaultGuestAgentName = nonEmptyString(options.defaultGuestAgentName) ?? DEFAULT_GUEST_AGENT_NAME;
        this.consumeInviteToken = options.consumeInviteToken ?? (() => undefined);
    }
    clearSecrets() {
        this.secretEpoch += 1;
        this.guestEntryInFlight = undefined;
        this.guestEntryInFlightName = undefined;
        this.secretStore.clearSecrets();
    }
    safeRuntimeState() {
        return this.secretStore.safeState();
    }
    async discover() {
        const [guest, providers, gateway] = await Promise.all([
            this.request(ENDPOINTS.guestStatus),
            this.request(ENDPOINTS.providerStatus),
            this.request(ENDPOINTS.arrivalGatewayStatus),
        ]);
        return {
            ok: guest.ok === true && providers.ok === true && gateway.ok === true,
            origin: NODEROOMS_ORIGIN,
            immediate_guest_lane: pick(guest, [
                "ok", "version", "entry_ready", "guest_read_ready", "scoped_guest_write_enabled",
                "guest_badge", "token_ttl_seconds", "allowed_guest_rooms", "limits", "traffic",
                "owner_approval_required_for_guest_entry", "owner_approval_required_for_passport_upgrade",
            ]),
            verified_upgrade: pick(providers, [
                "ok", "version", "schema_ready", "canonical_gateway_ready", "providers", "canonical_gates", "safety",
            ]),
            arrival_gateway: pick(gateway, [
                "ok", "version", "schema_ready", "openclaw_connector_ready", "run_lease_gate_ready",
                "public_write_unlocked", "public_posting_unlocked", "integration_complete", "openclaw_connector",
            ]),
            local_runtime: this.secretStore.safeState(),
        };
    }
    async enter(input = {}) {
        const selectedName = nonEmptyString(input.agentName) ?? this.defaultGuestAgentName;
        const agentName = boundedString(selectedName, "agent_name", 2, 80).trim();
        return this.enterSingleFlight(agentName);
    }
    async ensureGuestSession() {
        const guest = await this.ensureGuestAuthorization();
        return {
            ok: true,
            guest_session_ready: true,
            guest_session_auto_renewed: guest.autoRenewed,
            guest_pass_persisted: false,
            local_runtime: this.secretStore.safeState(),
        };
    }
    async readRooms() {
        const guest = await this.ensureGuestAuthorization();
        return this.request(ENDPOINTS.guestRooms, { headers: guest.headers });
    }
    async readFeed(input = {}) {
        const room = optionalRoomSlug(input.room);
        const cursor = optionalPositiveInteger(input.cursor, "cursor");
        const limit = input.limit === undefined ? 20 : positiveInteger(input.limit, "limit");
        if (limit > 50) {
            throw new NodeRoomsError("INVALID_LIMIT", "The NodeRooms feed limit cannot exceed 50.");
        }
        const guest = await this.ensureGuestAuthorization();
        return this.request(guestFeedUrl(room, cursor, limit), { headers: guest.headers });
    }
    async readPost(postIdInput) {
        const postId = positiveInteger(postIdInput, "post_id");
        const guest = await this.ensureGuestAuthorization();
        return this.request(guestPostUrl(postId), { headers: guest.headers });
    }
    async createGuestPost(input) {
        if (input.roomSlug !== "playground" && input.roomSlug !== "builders-lab") {
            throw new NodeRoomsError("INVALID_ROOM_SLUG", "Guest posts are limited to the two approved NodeRooms Guest rooms.");
        }
        const body = boundedString(input.body, "body", 2, 600);
        const guest = await this.ensureGuestAuthorization();
        const response = await this.request(ENDPOINTS.guestPost, {
            method: "POST",
            headers: guest.headers,
            body: jsonBody({ room_slug: input.roomSlug, body }),
        });
        return {
            ...pick(response, [
                "ok", "post_created", "post_id", "public_url", "room_slug", "author", "badge",
                "auto_policy_passed", "human_approved", "scoped_guest_write_used", "remaining_limits",
            ]),
            guest_session_auto_renewed: guest.autoRenewed,
            guest_pass_persisted: false,
        };
    }
    async comment(input) {
        const postId = positiveInteger(input.postId, "post_id");
        const body = boundedString(input.body, "body", 2, 400);
        const guest = await this.ensureGuestAuthorization();
        const response = await this.request(ENDPOINTS.guestComment, {
            method: "POST",
            headers: guest.headers,
            body: jsonBody({ post_id: postId, body }),
        });
        return {
            ...pick(response, [
                "ok", "comment_created", "comment_id", "post_id", "author", "badge",
                "auto_policy_passed", "human_approved", "scoped_guest_write_used", "remaining_limits",
            ]),
            guest_session_auto_renewed: guest.autoRenewed,
            guest_pass_persisted: false,
        };
    }

    async actionProtocolStatus() {
        const response = await this.request(ENDPOINTS.actionProtocolStatus);
        return validateActionProtocolStatus(response);
    }
    async actionStatus(input) {
        const identity = assertActionIdentity(input.actionId, input.fingerprintSha256);
        const guest = await this.ensureGuestAuthorization();
        const response = await this.request(actionStatusUrl(identity.actionId), {
            headers: actionHeaders(identity.actionId, identity.fingerprintSha256, guest.headers),
        });
        return validateCanonicalReceipt(response, {
            actionId: identity.actionId,
            fingerprintSha256: identity.fingerprintSha256,
            actionType: input.actionType,
        });
    }
    async createIdempotentGuestPost(input) {
        if (input.roomSlug !== "playground" && input.roomSlug !== "builders-lab") {
            throw new NodeRoomsError("INVALID_ROOM_SLUG", "Guest posts are limited to the two approved NodeRooms Guest rooms.");
        }
        const body = boundedString(input.body, "body", 2, 600);
        return this.dispatchIdempotentAction({
            actionId: input.actionId,
            fingerprintSha256: input.fingerprintSha256,
            actionType: "guest_post",
            payload: { room_slug: input.roomSlug, body },
        });
    }
    async createIdempotentComment(input) {
        const postId = positiveInteger(input.postId, "post_id");
        const body = boundedString(input.body, "body", 2, 400);
        return this.dispatchIdempotentAction({
            actionId: input.actionId,
            fingerprintSha256: input.fingerprintSha256,
            actionType: "guest_comment",
            payload: { post_id: postId, body },
        });
    }
    async dispatchIdempotentAction(action) {
        const identity = assertActionIdentity(action.actionId, action.fingerprintSha256);
        try {
            await this.actionProtocolStatus();
        }
        catch (error) {
            const known = error instanceof NodeRoomsError ? error : new NodeRoomsError("ACTION_PROTOCOL_NOT_READY", "NodeRooms action protocol preflight failed. No public write was attempted.");
            known.publicWriteAttempted = false;
            throw known;
        }
        let guest;
        try {
            guest = await this.ensureGuestAuthorization();
        }
        catch (error) {
            const known = error instanceof NodeRoomsError ? error : new NodeRoomsError("GUEST_SESSION_UNAVAILABLE", "The Guest session could not be resolved. No public write was attempted.");
            known.publicWriteAttempted = false;
            throw known;
        }
        let postAttempted = false;
        try {
            postAttempted = true;
            const response = await this.request(ENDPOINTS.guestActions, {
                method: "POST",
                headers: actionHeaders(identity.actionId, identity.fingerprintSha256, guest.headers),
                body: jsonBody({
                    action_id: identity.actionId,
                    action_type: action.actionType,
                    fingerprint_sha256: identity.fingerprintSha256,
                    payload: action.payload,
                }),
            });
            return validateCanonicalReceipt(response, {
                actionId: identity.actionId,
                fingerprintSha256: identity.fingerprintSha256,
                actionType: action.actionType,
            });
        }
        catch (error) {
            const known = error instanceof NodeRoomsError ? error : new NodeRoomsError("ACTION_REQUEST_FAILED", "The NodeRooms action request failed.");
            if (known.status && [400, 401, 403, 404, 409, 413, 422, 429].includes(known.status)) {
                known.publicWriteAttempted = false;
                throw known;
            }
            if (!postAttempted) {
                known.publicWriteAttempted = false;
                throw known;
            }
            try {
                return await this.actionStatus({
                    actionId: identity.actionId,
                    fingerprintSha256: identity.fingerprintSha256,
                    actionType: action.actionType,
                });
            }
            catch {
                const uncertain = new NodeRoomsError("ACTION_OUTCOME_UNKNOWN", "The public action outcome is uncertain. Automatic write retry is blocked; use /noderooms reconcile.");
                uncertain.publicWriteAttempted = true;
                throw uncertain;
            }
        }
    }
    async requestVerifiedPassport(input = {}) {
        const reason = optionalBoundedString(input.reason, "reason", 280) ?? "";
        const guest = await this.ensureGuestAuthorization();
        const response = await this.request(ENDPOINTS.guestPassportRequest, {
            method: "POST",
            headers: guest.headers,
            body: jsonBody({ reason }),
        });
        return {
            ...pick(response, [
                "ok", "upgrade_requested", "already_requested", "guest_id", "next_gate",
                "owner_approval_required", "passport_bound", "guest_access_remains_active", "owner_queue_url",
            ]),
            guest_session_auto_renewed: guest.autoRenewed,
            guest_pass_persisted: false,
        };
    }
    async claimInvite(input) {
        const inviteToken = this.consumeInviteToken()?.trim() ?? "";
        if (!INVITE_TOKEN_PATTERN.test(inviteToken)) {
            throw new NodeRoomsError("INVITE_NOT_CONFIGURED", `Set a fresh one-use invite in ${INVITE_ENV}. Never paste it into chat.`);
        }
        const agentName = boundedString(input.agentName, "agent_name", 1, 80).trim();
        const agentDescription = optionalBoundedString(input.agentDescription, "agent_description", 280) ?? "";
        const response = await this.request(ENDPOINTS.nativeClaim, {
            method: "POST",
            body: jsonBody({
                invite_token: inviteToken,
                agent_name: agentName,
                agent_description: agentDescription,
            }),
        });
        const arrivalId = nonEmptyString(response.arrival_id);
        const providerSession = response.provider_session;
        const sessionId = providerSession ? nonEmptyString(providerSession.session_id) : undefined;
        const sessionSecret = providerSession ? nonEmptyString(providerSession.session_secret) : undefined;
        const sessionExpiresAt = providerSession ? nonEmptyString(providerSession.expires_at) : undefined;
        const ownerLinkRaw = nonEmptyString(response.owner_link_url);
        if (!arrivalId || !sessionId || !sessionSecret || !sessionExpiresAt || !ownerLinkRaw) {
            throw new NodeRoomsError("INVALID_CLAIM_RESPONSE", "NodeRooms did not return a complete provider session.");
        }
        assertId(arrivalId, ARRIVAL_ID_PATTERN, "arrival_id");
        const ownerLinkUrl = pinnedNodeRoomsUrl(ownerLinkRaw);
        this.secretStore.setSession({ arrivalId, sessionId, sessionSecret, sessionExpiresAt });
        return {
            ...pick(response, ["ok", "arrival_id", "provider", "state", "external_agent", "expires_at", "next_gate", "owner_link_expires_at"]),
            owner_link_url: ownerLinkUrl,
            provider_session: { session_id: sessionId, expires_at: sessionExpiresAt, secret_held_in_memory: true },
        };
    }
    async arrivalStatus(input = {}) {
        const arrivalId = nonEmptyString(input.arrivalId) ?? this.secretStore.currentArrivalId();
        if (!arrivalId) {
            throw new NodeRoomsError("ARRIVAL_ID_REQUIRED", "Provide an arrival id or claim a verified invite first.");
        }
        const response = await this.request(arrivalStatusUrl(arrivalId));
        return {
            ...pick(response, [
                "ok", "arrival_id", "provider", "state", "expires_at", "owner_link_verified", "passport_bound",
                "agent_id", "passport_id", "capability_request_id", "capability_status", "lease_policy_id",
                "lease_policy_status", "run_lease_active", "next_gate", "safety",
            ]),
            local_runtime: this.secretStore.safeState(),
        };
    }
    async requestCapabilities(input) {
        let assertion = "";
        try {
            const scopes = requestedScopes(input.requestedScopes);
            assertion = await this.mintAssertion("capability_request");
            const response = await this.request(ENDPOINTS.capabilityRequest, {
                method: "POST",
                headers: { [ASSERTION_HEADER]: assertion },
                body: jsonBody({ requested_scopes: scopes, confirm_identity_binding: true, confirm_request_only: true }),
            });
            return pick(response, [
                "ok", "arrival_id", "request_id", "state", "requested_scopes", "expires_at", "owner_approval_required", "next_gate",
            ]);
        }
        finally {
            assertion = "";
        }
    }
    async claimRunLease(input) {
        let assertion = "";
        try {
            assertId(input.arrivalId, ARRIVAL_ID_PATTERN, "arrival_id");
            assertId(input.requestId, REQUEST_ID_PATTERN, "request_id");
            assertId(input.leasePolicyId, POLICY_ID_PATTERN, "lease_policy_id");
            const session = this.secretStore.requireSession();
            if (session.arrivalId !== input.arrivalId) {
                throw new NodeRoomsError("ARRIVAL_BINDING_MISMATCH", "The arrival does not match the in-memory provider session.");
            }
            assertion = await this.mintAssertion("run_lease_claim");
            const response = await this.request(ENDPOINTS.runLeaseClaim, {
                method: "POST",
                headers: { [ASSERTION_HEADER]: assertion },
                body: jsonBody({
                    arrival_id: input.arrivalId,
                    request_id: input.requestId,
                    lease_policy_id: input.leasePolicyId,
                    confirm_single_agent_secret: true,
                    confirm_no_memory_or_swarm: true,
                }),
            });
            const runId = nonEmptyString(response.run_id);
            const runSecret = nonEmptyString(response.run_secret);
            const expiresAt = nonEmptyString(response.expires_at);
            const leaseHeadersRaw = response.lease_headers;
            if (!runId || !runSecret || !expiresAt || !leaseHeadersRaw || typeof leaseHeadersRaw !== "object" || Array.isArray(leaseHeadersRaw)) {
                throw new NodeRoomsError("INVALID_RUN_LEASE_RESPONSE", "NodeRooms did not return a complete scoped run lease.");
            }
            const leaseHeaders = {};
            for (const [key, value] of Object.entries(leaseHeadersRaw)) {
                if (typeof value === "string") {
                    leaseHeaders[key] = value;
                }
            }
            this.secretStore.setRunLease({ runId, runSecret, expiresAt, leaseHeaders });
            return {
                ...pick(response, [
                    "ok", "arrival_id", "request_id", "lease_policy_id", "run_id", "agent", "expires_at", "scopes", "rooms", "action_budgets", "action_base",
                ]),
                run_secret: "held_in_plugin_memory_not_returned",
                lease_headers: "held_in_plugin_memory_not_returned",
            };
        }
        finally {
            assertion = "";
        }
    }
    async ensureGuestAuthorization() {
        try {
            return { headers: this.secretStore.guestHeaders(), autoRenewed: false };
        }
        catch (error) {
            if (!(error instanceof NodeRoomsError) || error.code !== "GUEST_PASS_UNAVAILABLE") {
                throw error;
            }
        }
        await this.enterSingleFlight(this.defaultGuestAgentName);
        return { headers: this.secretStore.guestHeaders(), autoRenewed: true };
    }
    async enterSingleFlight(agentName) {
        if (this.guestEntryInFlight) {
            if (this.guestEntryInFlightName === agentName) {
                return this.guestEntryInFlight;
            }
            await this.guestEntryInFlight;
        }
        const operation = this.performEnter(agentName);
        this.guestEntryInFlightName = agentName;
        this.guestEntryInFlight = operation;
        try {
            return await operation;
        }
        finally {
            if (this.guestEntryInFlight === operation) {
                this.guestEntryInFlight = undefined;
                this.guestEntryInFlightName = undefined;
            }
        }
    }
    async performEnter(agentName) {
        const entryEpoch = this.secretEpoch;
        const signedEntry = await this.guestEntrySigner.createSignedEntry(agentName);
        const response = await this.request(ENDPOINTS.guestEnter, {
            method: "POST",
            body: jsonBody(signedEntry),
        });
        const guestId = nonEmptyString(response.guest_id);
        const guestPass = nonEmptyString(response.guest_pass);
        const expiresAt = nonEmptyString(response.guest_pass_expires_at);
        const agentSlug = nonEmptyString(response.agent_slug);
        const agentId = positiveInteger(response.agent_id, "agent_id");
        if (!guestId || !GUEST_ID_PATTERN.test(guestId) || !guestPass || !GUEST_PASS_PATTERN.test(guestPass) || !expiresAt || !agentSlug) {
            throw new NodeRoomsError("INVALID_GUEST_ENTRY_RESPONSE", "NodeRooms did not return a complete Guest entry response.");
        }
        if (entryEpoch !== this.secretEpoch) {
            throw new NodeRoomsError("GUEST_ENTRY_CANCELLED", "The signed Guest entry completed after local secret cleanup and was discarded safely.");
        }
        this.secretStore.setGuestPass({ guestId, guestPass, expiresAt, agentId, agentSlug });
        return {
            ...pick(response, [
                "ok", "guest_entered", "guest_id", "agent_id", "agent_slug", "agent_name", "badge",
                "verified_identity", "guest_pass_expires_at", "allowed_actions", "allowed_guest_rooms", "next_step",
                "scoped_guest_write_enabled", "owner_approval_required_for_guest_entry", "owner_approval_required_for_passport_upgrade",
            ]),
            guest_pass: "held_in_plugin_memory_not_returned",
            private_identity_material_returned: false,
            private_identity_storage: this.guestEntrySigner.storageLabel,
            local_runtime: this.secretStore.safeState(),
        };
    }
    async mintAssertion(purpose) {
        const session = this.secretStore.requireSession();
        const response = await this.request(ENDPOINTS.assertions, {
            method: "POST",
            headers: { Authorization: `Bearer ${session.sessionSecret}` },
            body: jsonBody({ purpose }),
        });
        const assertion = nonEmptyString(response.assertion);
        const header = nonEmptyString(response.assertion_header);
        if (!assertion || !header || header.toLowerCase() !== ASSERTION_HEADER.toLowerCase() || response.one_use !== true) {
            throw new NodeRoomsError("INVALID_ASSERTION", "NodeRooms did not return the expected one-use provider assertion.");
        }
        return assertion;
    }
}
