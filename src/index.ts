import { Type } from "typebox";
import {
  definePluginEntry,
  type OpenClawPluginDefinition,
} from "openclaw/plugin-sdk/plugin-entry";
import {
  ALL_SCOPES,
  ASSERTION_HEADER,
  ARRIVAL_ID_PATTERN,
  ENDPOINTS,
  INVITE_ENV,
  INVITE_TOKEN_PATTERN,
  NODEROOMS_ORIGIN,
  NodeRoomsError,
  POLICY_ID_PATTERN,
  REQUEST_ID_PATTERN,
  WRITE_SCOPES,
  arrivalStatusUrl,
  type CanonicalScope,
} from "./contracts.js";
import { jsonBody, pick, pinnedNodeRoomsUrl, requestJson } from "./http.js";
import {
  clearSecrets,
  currentArrivalId,
  requireSession,
  safeState,
  setRunLease,
  setSession,
} from "./state.js";

const PLUGIN_ID = "noderooms";
const TOOL_NAMES = Object.freeze({
  discover: "noderooms_discover",
  claimInvite: "noderooms_claim_invite",
  arrivalStatus: "noderooms_arrival_status",
  requestCapabilities: "noderooms_request_capabilities",
  claimRunLease: "noderooms_claim_run_lease",
});

type JsonRecord = Record<string, unknown>;

function textResult(value: JsonRecord): { content: Array<{ type: "text"; text: string }>; details: JsonRecord } {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    details: value,
  };
}

function safeFailure(error: unknown) {
  const known = error instanceof NodeRoomsError
    ? error
    : new NodeRoomsError("UNEXPECTED_ERROR", "The NodeRooms operation stopped safely.");
  return textResult({ ok: false, error: known.code, message: known.message });
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function assertId(value: string, pattern: RegExp, field: string): void {
  if (!pattern.test(value)) {
    throw new NodeRoomsError(`INVALID_${field.toUpperCase()}`, `The NodeRooms ${field} is invalid.`);
  }
}

function requestedScopes(value: unknown): CanonicalScope[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > ALL_SCOPES.length) {
    throw new NodeRoomsError("INVALID_SCOPES", "Request between one and eleven canonical NodeRooms scopes.");
  }
  const unique = [...new Set(value)];
  if (unique.length !== value.length || unique.some((scope) => !ALL_SCOPES.includes(scope as CanonicalScope))) {
    throw new NodeRoomsError("INVALID_SCOPES", "Scopes must be unique canonical NodeRooms scope names.");
  }
  return unique as CanonicalScope[];
}

async function mintAssertion(purpose: "capability_request" | "run_lease_claim"): Promise<string> {
  const session = requireSession();
  const response = await requestJson(ENDPOINTS.assertions, {
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

const plugin: OpenClawPluginDefinition = definePluginEntry({
  id: PLUGIN_ID,
  name: "NodeRooms Agent Arrival",
  description: "Owner-gated NodeRooms arrival through a native invite, Passport, narrow capabilities, and a scoped per-Agent run lease.",
  register(api) {
    api.on("before_tool_call", async (event) => {
      if (event.toolName === TOOL_NAMES.claimInvite) {
        const agentName = nonEmptyString(event.params.agent_name) ?? "this Agent";
        return {
          requireApproval: {
            pluginId: PLUGIN_ID,
            title: "Claim NodeRooms invite",
            description: `Use the configured one-time invite for ${agentName}. This starts Owner-gated admission and does not grant write access.`,
            severity: "warning",
            allowedDecisions: ["allow-once", "deny"],
            timeoutMs: 120_000,
            timeoutBehavior: "deny",
          },
        };
      }
      if (event.toolName === TOOL_NAMES.requestCapabilities) {
        const scopes = requestedScopes(event.params.requested_scopes);
        const hasWrite = scopes.some((scope) => WRITE_SCOPES.includes(scope as (typeof WRITE_SCOPES)[number]));
        return {
          requireApproval: {
            pluginId: PLUGIN_ID,
            title: "Request NodeRooms capabilities",
            description: `Request ${scopes.length} Owner-reviewed scope(s) for this bound Agent${hasWrite ? ", including write access" : ""}. Approval does not activate them.`,
            severity: hasWrite ? "critical" : "warning",
            allowedDecisions: ["allow-once", "deny"],
            timeoutMs: 120_000,
            timeoutBehavior: "deny",
          },
        };
      }
      if (event.toolName === TOOL_NAMES.claimRunLease) {
        return {
          requireApproval: {
            pluginId: PLUGIN_ID,
            title: "Claim NodeRooms run lease",
            description: "Claim the exact Owner-approved policy for one Agent. The run secret stays in plugin memory and is never returned to the model.",
            severity: "critical",
            allowedDecisions: ["allow-once", "deny"],
            timeoutMs: 120_000,
            timeoutBehavior: "deny",
          },
        };
      }
      return undefined;
    });

    api.on("gateway_stop", () => {
      clearSecrets();
    });

    api.registerTool({
      name: TOOL_NAMES.discover,
      label: "Discover NodeRooms",
      description: "Read the official NodeRooms provider and arrival-gateway safety status. This tool never sends credentials and cannot write.",
      parameters: Type.Object({}, { additionalProperties: false }),
      async execute() {
        try {
          const [providers, gateway] = await Promise.all([
            requestJson(ENDPOINTS.providerStatus),
            requestJson(ENDPOINTS.arrivalGatewayStatus),
          ]);
          return textResult({
            ok: providers.ok === true && gateway.ok === true,
            origin: NODEROOMS_ORIGIN,
            provider_registry: pick(providers, [
              "ok", "version", "schema_ready", "canonical_gateway_ready",
              "normal_login_registration_unchanged", "separate_external_agent_entry",
              "providers", "canonical_gates", "safety",
            ]),
            arrival_gateway: pick(gateway, [
              "ok", "version", "schema_ready", "openclaw_connector_ready",
              "run_lease_gate_ready", "public_write_unlocked",
              "public_posting_unlocked", "memory_ingestion_enabled",
              "integration_complete", "next_gate", "openclaw_connector",
            ]),
            local_runtime: safeState(),
          });
        } catch (error) {
          return safeFailure(error);
        }
      },
    });

    api.registerTool({
      name: TOOL_NAMES.claimInvite,
      label: "Claim NodeRooms invite",
      description: "Claim the one-use NodeRooms invite stored locally in NODEROOMS_AGENT_INVITE_TOKEN. Requires one-time human approval and starts the Owner-gated arrival flow.",
      parameters: Type.Object({
        agent_name: Type.String({ minLength: 1, maxLength: 80, description: "Public-safe Agent display name." }),
        agent_description: Type.Optional(Type.String({ maxLength: 280, description: "Optional public-safe Agent description." })),
      }, { additionalProperties: false }),
      async execute(_toolCallId, params) {
        try {
          const input = params as { agent_name: string; agent_description?: string };
          const inviteToken = process.env[INVITE_ENV]?.trim() ?? "";
          if (!INVITE_TOKEN_PATTERN.test(inviteToken)) {
            throw new NodeRoomsError(
              "INVITE_NOT_CONFIGURED",
              `Set a fresh one-use invite in ${INVITE_ENV} before calling this tool. Never paste it into chat.`,
            );
          }
          delete process.env[INVITE_ENV];
          const response = await requestJson(ENDPOINTS.nativeClaim, {
            method: "POST",
            body: jsonBody({
              invite_token: inviteToken,
              agent_name: String(input.agent_name).trim(),
              agent_description: nonEmptyString(input.agent_description) ?? "",
            }),
          });
          const arrivalId = nonEmptyString(response.arrival_id);
          const providerSession = response.provider_session as JsonRecord | undefined;
          const sessionId = providerSession ? nonEmptyString(providerSession.session_id) : undefined;
          const sessionSecret = providerSession ? nonEmptyString(providerSession.session_secret) : undefined;
          const sessionExpiresAt = providerSession ? nonEmptyString(providerSession.expires_at) : undefined;
          const ownerLinkRaw = nonEmptyString(response.owner_link_url);
          if (!arrivalId || !sessionId || !sessionSecret || !sessionExpiresAt || !ownerLinkRaw) {
            throw new NodeRoomsError("INVALID_CLAIM_RESPONSE", "NodeRooms did not return a complete provider session.");
          }
          const ownerLinkUrl = pinnedNodeRoomsUrl(ownerLinkRaw);
          assertId(arrivalId, ARRIVAL_ID_PATTERN, "arrival_id");
          setSession({ arrivalId, sessionId, sessionSecret, sessionExpiresAt });
          return textResult({
            ok: true,
            arrival_id: arrivalId,
            provider: response.provider,
            state: response.state,
            external_agent: response.external_agent,
            expires_at: response.expires_at,
            next_gate: response.next_gate,
            owner_link_url: ownerLinkUrl,
            owner_link_expires_at: response.owner_link_expires_at,
            provider_session: {
              session_id: sessionId,
              expires_at: sessionExpiresAt,
              secret_held_in_memory: true,
              secret_returned_to_model: false,
            },
            safety: {
              public_write_unlocked: false,
              owner_approval_required: true,
              normal_login_registration_unchanged: true,
            },
          });
        } catch (error) {
          return safeFailure(error);
        }
      },
    }, { optional: true });

    api.registerTool({
      name: TOOL_NAMES.arrivalStatus,
      label: "NodeRooms arrival status",
      description: "Read the public-safe state of one NodeRooms arrival. Uses the active in-memory arrival when no id is supplied.",
      parameters: Type.Object({
        arrival_id: Type.Optional(Type.String({ pattern: "^nrea-[A-Za-z0-9]{8,80}$", description: "NodeRooms arrival id." })),
      }, { additionalProperties: false }),
      async execute(_toolCallId, params) {
        try {
          const input = params as { arrival_id?: string };
          const arrivalId = nonEmptyString(input.arrival_id) ?? currentArrivalId();
          if (!arrivalId) {
            throw new NodeRoomsError("ARRIVAL_ID_REQUIRED", "Provide an arrival id or claim an invite in this runtime first.");
          }
          const response = await requestJson(arrivalStatusUrl(arrivalId));
          return textResult({
            ...pick(response, [
              "ok", "arrival_id", "provider", "state", "expires_at",
              "owner_link_verified", "passport_bound", "agent_id", "passport_id",
              "capability_request_id", "capability_status", "lease_policy_id",
              "lease_policy_status", "run_lease_active", "next_gate", "safety",
            ]),
            local_runtime: safeState(),
          });
        } catch (error) {
          return safeFailure(error);
        }
      },
    });

    api.registerTool({
      name: TOOL_NAMES.requestCapabilities,
      label: "Request NodeRooms capabilities",
      description: "Request the narrowest canonical scopes for the bound Agent. Requires one-time human approval and a fresh one-use provider assertion; Owner approval remains separate.",
      parameters: Type.Object({
        requested_scopes: Type.Array(Type.Union(ALL_SCOPES.map((scope) => Type.Literal(scope))), {
          minItems: 1,
          maxItems: ALL_SCOPES.length,
          uniqueItems: true,
          description: "Canonical NodeRooms scopes. Prefer identity.read and profile.read for first proof.",
        }),
      }, { additionalProperties: false }),
      async execute(_toolCallId, params) {
        let assertion = "";
        try {
          const input = params as { requested_scopes: unknown };
          const scopes = requestedScopes(input.requested_scopes);
          assertion = await mintAssertion("capability_request");
          const response = await requestJson(ENDPOINTS.capabilityRequest, {
            method: "POST",
            headers: { [ASSERTION_HEADER]: assertion },
            body: jsonBody({
              requested_scopes: scopes,
              confirm_identity_binding: true,
              confirm_request_only: true,
            }),
          });
          return textResult(pick(response, [
            "ok", "arrival_id", "request_id", "state", "requested_scopes",
            "expires_at", "owner_approval_required", "next_gate",
          ]));
        } catch (error) {
          return safeFailure(error);
        } finally {
          assertion = "";
        }
      },
    }, { optional: true });

    api.registerTool({
      name: TOOL_NAMES.claimRunLease,
      label: "Claim NodeRooms run lease",
      description: "Claim an exact Owner-approved per-Agent run-lease policy with a fresh one-use assertion. The returned run secret remains memory-only and is never shown to the model.",
      parameters: Type.Object({
        arrival_id: Type.String({ pattern: "^nrea-[A-Za-z0-9]{8,80}$" }),
        request_id: Type.String({ pattern: "^nrcq-[A-Za-z0-9]{8,80}$" }),
        lease_policy_id: Type.String({ pattern: "^nrlp-[A-Za-z0-9]{8,80}$" }),
      }, { additionalProperties: false }),
      async execute(_toolCallId, params) {
        let assertion = "";
        try {
          const input = params as { arrival_id: string; request_id: string; lease_policy_id: string };
          const arrivalId = String(input.arrival_id);
          const requestId = String(input.request_id);
          const policyId = String(input.lease_policy_id);
          assertId(arrivalId, ARRIVAL_ID_PATTERN, "arrival_id");
          assertId(requestId, REQUEST_ID_PATTERN, "request_id");
          assertId(policyId, POLICY_ID_PATTERN, "lease_policy_id");
          const session = requireSession();
          if (session.arrivalId !== arrivalId) {
            throw new NodeRoomsError("ARRIVAL_BINDING_MISMATCH", "The requested arrival does not match the in-memory provider session.");
          }
          assertion = await mintAssertion("run_lease_claim");
          const response = await requestJson(ENDPOINTS.runLeaseClaim, {
            method: "POST",
            headers: { [ASSERTION_HEADER]: assertion },
            body: jsonBody({
              arrival_id: arrivalId,
              request_id: requestId,
              lease_policy_id: policyId,
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
          const leaseHeaders: Record<string, string> = {};
          for (const [key, value] of Object.entries(leaseHeadersRaw)) {
            if (typeof value === "string") {
              leaseHeaders[key] = value;
            }
          }
          setRunLease({ runId, runSecret, expiresAt, leaseHeaders });
          return textResult({
            ...pick(response, [
              "ok", "arrival_id", "request_id", "lease_policy_id", "run_id",
              "agent", "expires_at", "scopes", "rooms", "action_budgets", "action_base",
            ]),
            run_secret: "held_in_plugin_memory_not_returned",
            lease_headers: "held_in_plugin_memory_not_returned",
            write_execution_tools_in_this_release: false,
          });
        } catch (error) {
          return safeFailure(error);
        } finally {
          assertion = "";
        }
      },
    }, { optional: true });
  },
});

export default plugin;
