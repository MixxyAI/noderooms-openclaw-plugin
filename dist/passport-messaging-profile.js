import { sha256Fingerprint } from "./passport-runtime-binding.js";

export const PASSPORT_MESSAGING_CONTRACT_VERSION =
    "noderooms-passport-messaging-profile-v1";
export const PASSPORT_MESSAGING_DEVELOPMENT_IDENTITY =
    "1.4.0-alpha.3-dev.1";
export const PASSPORT_MESSAGING_LIVE_USE_ALLOWED = false;
export const PASSPORT_MESSAGING_RUNTIME_VALIDATION_STATUS =
    "external_validation_pending";

const PROFILE_ID_PATTERN = /^nrc003_[a-z0-9][a-z0-9._-]{2,95}$/;
const OWNER_ID_PATTERN = /^[A-Za-z0-9._:@/-]{1,160}$/;
const VERSION_PATTERN =
    /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/;
const CHANNEL_PATTERN = /^[a-z][a-z0-9_-]{1,31}$/;
const PACKAGE_PATTERN = /^@[a-z0-9_-]+\/[a-z0-9_-]+$/;
const SCOPE_PATTERN =
    /^connector\.[a-z][a-z0-9_]{1,31}\.[a-z][a-z0-9_]{1,47}\.[a-z][a-z0-9_]{1,47}$/;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;

const OFFICIAL_CHANNEL_IDS = Object.freeze([
    "discord",
    "msteams",
    "signal",
    "sms",
    "whatsapp",
]);
const ROUTE_IDS = Object.freeze([...OFFICIAL_CHANNEL_IDS, "viber"].toSorted());
const ROUTE_STATUS = new Set([
    "official_plugin_pending_runtime",
    "bundled_plugin_pending_runtime",
    "external_adapter_pending",
]);
const DISTRIBUTIONS = new Set([
    "official_downloadable",
    "bundled_or_official_downloadable",
    "external_unresolved",
]);
const TARGET_KINDS = new Set([
    "direct_e164",
    "direct_user",
    "guild_channel",
    "team_channel",
    "external_adapter_pending",
]);

export const PASSPORT_MESSAGE_SEND_PROJECTION_SCHEMA = Object.freeze({
    type: "object",
    additionalProperties: false,
    required: [
        "action",
        "channel",
        "accountId",
        "target",
        "message",
        "idempotencyKey",
    ],
    properties: {
        action: { const: "send" },
        channel: { enum: OFFICIAL_CHANNEL_IDS },
        accountId: {
            type: "string",
            minLength: 1,
            maxLength: 128,
        },
        target: {
            type: "string",
            minLength: 1,
            maxLength: 256,
        },
        message: {
            type: "string",
            minLength: 1,
            maxLength: 4000,
        },
        idempotencyKey: {
            type: "string",
            minLength: 16,
            maxLength: 160,
            pattern: "^[A-Za-z0-9._:-]+$",
        },
    },
});

export class PassportMessagingProfileError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "PassportMessagingProfileError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new PassportMessagingProfileError(code, message);
}

function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, required, optional, label) {
    if (!isRecord(value)) {
        fail("MESSAGING_PROFILE_INVALID", `${label} must be an object.`);
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail(
                "MESSAGING_PROFILE_INVALID",
                `${label} contains unsupported field ${key}.`,
            );
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail("MESSAGING_PROFILE_INVALID", `${label} is missing ${key}.`);
        }
    }
}

function exactString(value, pattern, label, maxLength = 512) {
    if (typeof value !== "string"
        || value.length < 1
        || value.length > maxLength
        || !pattern.test(value)) {
        fail("MESSAGING_PROFILE_INVALID", `${label} is invalid.`);
    }
    return value;
}

function exactStringArray(value, allowed, label) {
    if (!Array.isArray(value) || value.length < 1) {
        fail("MESSAGING_PROFILE_INVALID", `${label} must be non-empty.`);
    }
    const normalized = value.map((entry, index) =>
        exactString(entry, CHANNEL_PATTERN, `${label}[${index}]`, 64));
    if (new Set(normalized).size !== normalized.length
        || normalized.some((entry) => !allowed.has(entry))) {
        fail("MESSAGING_PROFILE_INVALID", `${label} is invalid.`);
    }
    return Object.freeze(normalized.toSorted());
}

function validateRoute(route, index, openclawVersion) {
    const label = `route_registry.routes[${index}]`;
    assertExactKeys(
        route,
        [
            "channel_id",
            "plugin_package",
            "distribution",
            "status",
            "scope",
            "allowed_target_kinds",
            "runtime_version_capture_required",
            "exact_account_required",
            "exact_target_required",
            "text_only_first_proof",
            "provider_limits_runtime_capture_required",
            "live_authority_allowed",
        ],
        [],
        label,
    );
    exactString(route.channel_id, CHANNEL_PATTERN, `${label}.channel_id`, 32);
    exactString(route.scope, SCOPE_PATTERN, `${label}.scope`, 150);
    if (!ROUTE_STATUS.has(route.status)
        || !DISTRIBUTIONS.has(route.distribution)) {
        fail("MESSAGING_ROUTE_STATUS_INVALID", `${label} status is invalid.`);
    }
    const targetKinds = exactStringArray(
        route.allowed_target_kinds,
        TARGET_KINDS,
        `${label}.allowed_target_kinds`,
    );
    const isViber = route.channel_id === "viber";
    if (isViber) {
        if (route.plugin_package !== "external:unresolved"
            || route.distribution !== "external_unresolved"
            || route.status !== "external_adapter_pending"
            || targetKinds.length !== 1
            || targetKinds[0] !== "external_adapter_pending") {
            fail(
                "MESSAGING_VIBER_BOUNDARY_INVALID",
                "Viber must remain an unresolved external adapter.",
            );
        }
    } else {
        exactString(
            route.plugin_package,
            PACKAGE_PATTERN,
            `${label}.plugin_package`,
            128,
        );
        if (!OFFICIAL_CHANNEL_IDS.includes(route.channel_id)
            || route.status === "external_adapter_pending") {
            fail(
                "MESSAGING_ROUTE_STATUS_INVALID",
                `${label} is not an official OpenClaw channel route.`,
            );
        }
    }
    if (route.runtime_version_capture_required !== true
        || route.exact_account_required !== true
        || route.exact_target_required !== true
        || route.text_only_first_proof !== true
        || route.provider_limits_runtime_capture_required !== true
        || route.live_authority_allowed !== false) {
        fail(
            "MESSAGING_ROUTE_AUTHORITY_INVALID",
            `${label} crosses the contract-only boundary.`,
        );
    }
    return Object.freeze({
        channel_id: route.channel_id,
        plugin_package: route.plugin_package,
        distribution: route.distribution,
        status: route.status,
        scope: route.scope,
        allowed_target_kinds: targetKinds,
        owner: Object.freeze({
            kind: "channel",
            owner_id: route.channel_id,
            resolution: isViber ? "unresolved" : "exact_name_only",
            openclaw_version: openclawVersion,
            runtime_plugin_version: "capture_required",
        }),
        credential_custodian: "openclaw",
        noderooms_stores_provider_credentials: false,
        runtime_version_capture_required: true,
        exact_account_required: true,
        exact_target_required: true,
        text_only_first_proof: true,
        provider_limits_runtime_capture_required: true,
        live_authority_allowed: false,
    });
}

function profileProjection(profile) {
    return {
        contract_version: profile.contract_version,
        development_identity: profile.development_identity,
        activation_state: profile.activation_state,
        live_messaging_use_allowed: profile.live_messaging_use_allowed,
        runtime_validation_status: profile.runtime_validation_status,
        profile_id: profile.profile_id,
        captured_at: profile.captured_at,
        runtime_binding: profile.runtime_binding,
        passport_gate: profile.passport_gate,
        inbound_boundary: profile.inbound_boundary,
        outbound_dispatch: profile.outbound_dispatch,
        routes: profile.routes,
        microsoft_future: profile.microsoft_future,
        receipt: profile.receipt,
        safety: profile.safety,
    };
}

export function passportMessagingProfileFingerprint(profile) {
    return sha256Fingerprint(profileProjection(profile));
}

export function buildPassportMessagingProfileV1(input) {
    assertExactKeys(
        input,
        [
            "profile_id",
            "captured_at",
            "openclaw_version",
            "message_tool_name",
            "message_tool_schema_status",
            "route_registry",
            "agent_id",
        ],
        [],
        "messaging profile input",
    );
    exactString(input.profile_id, PROFILE_ID_PATTERN, "profile_id", 101);
    const capturedAt = Date.parse(input.captured_at);
    if (!Number.isFinite(capturedAt)) {
        fail("MESSAGING_PROFILE_INVALID", "captured_at is invalid.");
    }
    exactString(
        input.openclaw_version,
        VERSION_PATTERN,
        "openclaw_version",
        128,
    );
    if (input.openclaw_version !== "2026.7.1-2"
        || input.message_tool_name !== "message"
        || input.message_tool_schema_status
            !== "narrowed_projection_runtime_capture_pending") {
        fail(
            "MESSAGING_RUNTIME_BINDING_INVALID",
            "The exact C003 OpenClaw message-tool binding is unavailable.",
        );
    }
    exactString(input.agent_id, OWNER_ID_PATTERN, "agent_id", 160);

    const registry = input.route_registry;
    assertExactKeys(
        registry,
        [
            "contract_version",
            "development_identity",
            "openclaw_version",
            "activation_state",
            "live_messaging_use_allowed",
            "routes",
            "microsoft_future",
        ],
        [],
        "route_registry",
    );
    if (registry.contract_version
            !== "noderooms-passport-messaging-route-registry-v1"
        || registry.development_identity
            !== PASSPORT_MESSAGING_DEVELOPMENT_IDENTITY
        || registry.openclaw_version !== input.openclaw_version
        || registry.activation_state !== "contract_only"
        || registry.live_messaging_use_allowed !== false
        || !Array.isArray(registry.routes)
        || registry.routes.length !== ROUTE_IDS.length) {
        fail(
            "MESSAGING_ROUTE_REGISTRY_INVALID",
            "The C003 route registry is invalid.",
        );
    }
    assertExactKeys(
        registry.microsoft_future,
        ["outlook_mail", "calendar"],
        [],
        "route_registry.microsoft_future",
    );
    if (registry.microsoft_future.outlook_mail !== "planned_c004_read_draft"
        || registry.microsoft_future.calendar !== "not_in_c003") {
        fail(
            "MESSAGING_MICROSOFT_SCOPE_INVALID",
            "Microsoft mail or calendar scope leaked into Teams messaging.",
        );
    }
    const routes = registry.routes
        .map((route, index) =>
            validateRoute(route, index, input.openclaw_version))
        .toSorted((left, right) =>
            left.channel_id.localeCompare(right.channel_id));
    if (JSON.stringify(routes.map((route) => route.channel_id))
        !== JSON.stringify(ROUTE_IDS)) {
        fail(
            "MESSAGING_ROUTE_SET_INVALID",
            "C003 route set is missing, duplicated, or drifted.",
        );
    }
    const scopes = routes.map((route) => route.scope);
    if (new Set(scopes).size !== scopes.length) {
        fail("MESSAGING_ROUTE_SET_INVALID", "C003 scopes must be unique.");
    }

    const projectionFingerprint =
        sha256Fingerprint(PASSPORT_MESSAGE_SEND_PROJECTION_SCHEMA);
    const profile = {
        contract_version: PASSPORT_MESSAGING_CONTRACT_VERSION,
        development_identity: PASSPORT_MESSAGING_DEVELOPMENT_IDENTITY,
        activation_state: "contract_only",
        live_messaging_use_allowed: PASSPORT_MESSAGING_LIVE_USE_ALLOWED,
        runtime_validation_status:
            PASSPORT_MESSAGING_RUNTIME_VALIDATION_STATUS,
        profile_id: input.profile_id,
        captured_at: new Date(capturedAt).toISOString(),
        runtime_binding: Object.freeze({
            openclaw_version: input.openclaw_version,
            tool_owner: "openclaw_builtin",
            tool_name: input.message_tool_name,
            action: "send",
            message_tool_schema_status: input.message_tool_schema_status,
            runtime_message_schema_fingerprint_sha256:
                "capture_required",
            noderooms_projection_schema:
                PASSPORT_MESSAGE_SEND_PROJECTION_SCHEMA,
            noderooms_projection_schema_fingerprint_sha256:
                projectionFingerprint,
            raw_tool_schema_stored: false,
        }),
        passport_gate: Object.freeze({
            agent_id_fingerprint_sha256: sha256Fingerprint({
                role: "passport_messaging_agent",
                agent_id: input.agent_id,
            }),
            verified_human_owner_required: true,
            verified_agent_passport_required: true,
            exact_runtime_binding_required: true,
            per_agent_run_lease_required: true,
            lease_scope_must_equal_route_scope: true,
            lease_channel_must_equal_route_channel: true,
            lease_account_fingerprint_required: true,
            lease_target_fingerprint_required: true,
            max_actions_per_lease: 1,
            shared_credential_allowed: false,
            wildcard_scope_allowed: false,
            automatic_owner_decision_allowed: false,
        }),
        inbound_boundary: Object.freeze({
            pairing_or_allowlist_required: true,
            input_trust: "untrusted_external_content",
            automatic_action_from_inbound_content_allowed: false,
            memory_ingestion_enabled: false,
            swarm_enabled: false,
        }),
        outbound_dispatch: Object.freeze({
            action: "send",
            content_mode: "text_only_first_proof",
            exact_channel_required: true,
            exact_account_required: true,
            exact_target_required: true,
            exact_payload_fingerprint_required: true,
            approval_policy: "allow_once",
            replay_semantics: "at_most_once_dispatch",
            dispatch_attempt_ceiling: 1,
            provider_idempotency_key_required: true,
            automatic_retry_allowed: false,
            unknown_outcome_policy: "seal_and_reconcile_read_only_or_stop",
            cross_channel_fallback_allowed: false,
            automatic_recipient_selection_allowed: false,
        }),
        routes: Object.freeze(routes),
        microsoft_future: Object.freeze({
            teams_channel_id: "msteams",
            outlook_mail: "planned_c004_read_draft",
            calendar: "not_in_c003",
            shared_microsoft_authority_allowed: false,
        }),
        receipt: Object.freeze({
            profile: "signed_external_action_receipt_v2",
            signature_required: true,
            fields: Object.freeze([
                "agent_fingerprint",
                "approval_fingerprint",
                "channel_id",
                "connector_version_fingerprint",
                "dispatch_attempt_count",
                "lease_fingerprint",
                "outcome",
                "payload_fingerprint",
                "provider_message_id_fingerprint",
                "target_fingerprint",
                "timestamp",
            ]),
            stores_raw_message: false,
            stores_raw_target: false,
            stores_provider_credentials: false,
            exactly_once_effect_claim_allowed: false,
        }),
        safety: Object.freeze({
            grants_authority: false,
            executes_tools: false,
            invokes_connector: false,
            sends_message: false,
            retries_unknown_send: false,
            enables_viber: false,
            enables_outlook_mail: false,
            enables_calendar: false,
            stores_provider_credentials: false,
            stores_raw_message: false,
            stores_raw_target: false,
            stores_raw_provider_result: false,
            wildcard_activation_allowed: false,
            shared_credential_allowed: false,
            public_write_unlocked: false,
            memory_ingestion_enabled: false,
            swarm_enabled: false,
        }),
    };
    profile.profile_fingerprint_sha256 =
        passportMessagingProfileFingerprint(profile);
    return Object.freeze(profile);
}

export function validatePassportMessagingProfileV1(profile) {
    assertExactKeys(
        profile,
        [
            "contract_version",
            "development_identity",
            "activation_state",
            "live_messaging_use_allowed",
            "runtime_validation_status",
            "profile_id",
            "captured_at",
            "runtime_binding",
            "passport_gate",
            "inbound_boundary",
            "outbound_dispatch",
            "routes",
            "microsoft_future",
            "receipt",
            "safety",
            "profile_fingerprint_sha256",
        ],
        [],
        "messaging profile",
    );
    if (profile.contract_version !== PASSPORT_MESSAGING_CONTRACT_VERSION
        || profile.development_identity
            !== PASSPORT_MESSAGING_DEVELOPMENT_IDENTITY
        || profile.activation_state !== "contract_only"
        || profile.live_messaging_use_allowed !== false
        || profile.runtime_validation_status
            !== PASSPORT_MESSAGING_RUNTIME_VALIDATION_STATUS
        || profile.safety?.grants_authority !== false
        || profile.safety?.executes_tools !== false
        || profile.safety?.invokes_connector !== false
        || profile.safety?.sends_message !== false
        || profile.safety?.enables_viber !== false
        || profile.safety?.enables_outlook_mail !== false
        || profile.safety?.enables_calendar !== false
        || profile.outbound_dispatch?.approval_policy !== "allow_once"
        || profile.outbound_dispatch?.dispatch_attempt_ceiling !== 1
        || profile.outbound_dispatch?.automatic_retry_allowed !== false
        || profile.passport_gate?.max_actions_per_lease !== 1
        || profile.receipt?.signature_required !== true
        || profile.receipt?.exactly_once_effect_claim_allowed !== false) {
        fail(
            "MESSAGING_PROFILE_SAFETY_INVALID",
            "C003 safety boundary has drifted.",
        );
    }
    exactString(
        profile.profile_fingerprint_sha256,
        SHA256_PATTERN,
        "profile_fingerprint_sha256",
        71,
    );
    if (profile.profile_fingerprint_sha256
        !== passportMessagingProfileFingerprint(profile)) {
        fail(
            "MESSAGING_PROFILE_FINGERPRINT_DRIFT",
            "C003 profile fingerprint has drifted.",
        );
    }
    return Object.freeze(profile);
}
