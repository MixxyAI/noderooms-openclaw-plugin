import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Compile } from "typebox/compile";

import {
    buildPassportMessagingProfileV1,
    PASSPORT_MESSAGE_SEND_PROJECTION_SCHEMA,
    PassportMessagingProfileError,
    passportMessagingProfileFingerprint,
    validatePassportMessagingProfileV1,
} from "../src/passport-messaging-profile.js";
import { sha256Fingerprint } from "../src/passport-runtime-binding.js";
import {
    buildPassportMessagingProof,
} from "../scripts/passport-messaging-proof.mjs";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const [routeRegistry, profileSchema, sourceModule, pluginIndex] =
    await Promise.all([
        readJson("contracts/reference/passport-messaging-routes.v1.json"),
        readJson("contracts/passport-messaging-profile-v1.schema.json"),
        readFile(
            new URL("../src/passport-messaging-profile.js", import.meta.url),
            "utf8",
        ),
        readFile(new URL("../src/index.js", import.meta.url), "utf8"),
    ]);

function profileInput(overrides = {}) {
    return {
        profile_id: "nrc003_passport_messaging_001",
        captured_at: "2026-07-30T15:10:00Z",
        openclaw_version: "2026.7.1-2",
        message_tool_name: "message",
        message_tool_schema_status:
            "narrowed_projection_runtime_capture_pending",
        route_registry: structuredClone(routeRegistry),
        agent_id: "passport_messaging_agent",
        ...overrides,
    };
}

function expectCode(code, operation) {
    assert.throws(
        operation,
        (error) =>
            error instanceof PassportMessagingProfileError
            && error.code === code,
    );
}

test("C003 registry names five official OpenClaw channels and one pending external adapter", () => {
    const profile = buildPassportMessagingProfileV1(profileInput());
    const byId = new Map(
        profile.routes.map((route) => [route.channel_id, route]),
    );
    assert.deepEqual([...byId.keys()], [
        "discord",
        "msteams",
        "signal",
        "sms",
        "viber",
        "whatsapp",
    ]);
    for (const channelId of [
        "discord",
        "msteams",
        "signal",
        "sms",
        "whatsapp",
    ]) {
        assert.equal(byId.get(channelId).owner.resolution, "exact_name_only");
        assert.equal(
            byId.get(channelId).runtime_version_capture_required,
            true,
        );
        assert.equal(byId.get(channelId).live_authority_allowed, false);
    }
    assert.equal(byId.get("viber").owner.resolution, "unresolved");
    assert.equal(byId.get("viber").status, "external_adapter_pending");
    assert.equal(profile.safety.enables_viber, false);
});

test("C003 JSON Schema freezes contract-only, no-send, and no-retry boundaries", () => {
    assert.equal(
        profileSchema.properties.development_identity.const,
        "1.4.0-alpha.3-dev.1",
    );
    assert.equal(
        profileSchema.properties.live_messaging_use_allowed.const,
        false,
    );
    assert.equal(
        profileSchema.$defs.outboundDispatch.properties
            .automatic_retry_allowed.const,
        false,
    );
    assert.equal(
        profileSchema.$defs.safety.properties.sends_message.const,
        false,
    );
    const validator = Compile(profileSchema);
    const profile = buildPassportMessagingProfileV1(profileInput());
    assert.equal(validator.Check(profile), true);
    const unsafe = structuredClone(profile);
    unsafe.safety.sends_message = true;
    assert.equal(validator.Check(unsafe), false);
});

test("message projection is exact send-only and separately fingerprinted", () => {
    const profile = buildPassportMessagingProfileV1(profileInput());
    assert.equal(profile.runtime_binding.tool_name, "message");
    assert.equal(profile.runtime_binding.action, "send");
    assert.equal(
        profile.runtime_binding.runtime_message_schema_fingerprint_sha256,
        "capture_required",
    );
    assert.deepEqual(
        profile.runtime_binding.noderooms_projection_schema,
        PASSPORT_MESSAGE_SEND_PROJECTION_SCHEMA,
    );
    assert.equal(
        profile.runtime_binding
            .noderooms_projection_schema_fingerprint_sha256,
        sha256Fingerprint(PASSPORT_MESSAGE_SEND_PROJECTION_SCHEMA),
    );
    assert.deepEqual(
        PASSPORT_MESSAGE_SEND_PROJECTION_SCHEMA.required,
        [
            "action",
            "channel",
            "accountId",
            "target",
            "message",
            "idempotencyKey",
        ],
    );
    assert.equal(
        PASSPORT_MESSAGE_SEND_PROJECTION_SCHEMA.additionalProperties,
        false,
    );
});

test("Passport gate binds one Agent, Owner, channel, account, target, and one-action lease", () => {
    const profile = buildPassportMessagingProfileV1(profileInput());
    assert.equal(profile.passport_gate.verified_human_owner_required, true);
    assert.equal(profile.passport_gate.verified_agent_passport_required, true);
    assert.equal(profile.passport_gate.exact_runtime_binding_required, true);
    assert.equal(profile.passport_gate.per_agent_run_lease_required, true);
    assert.equal(
        profile.passport_gate.lease_scope_must_equal_route_scope,
        true,
    );
    assert.equal(
        profile.passport_gate.lease_channel_must_equal_route_channel,
        true,
    );
    assert.equal(profile.passport_gate.lease_account_fingerprint_required, true);
    assert.equal(profile.passport_gate.lease_target_fingerprint_required, true);
    assert.equal(profile.passport_gate.max_actions_per_lease, 1);
    assert.equal(profile.passport_gate.shared_credential_allowed, false);
    assert.equal(profile.passport_gate.wildcard_scope_allowed, false);
    assert.equal(
        profile.passport_gate.automatic_owner_decision_allowed,
        false,
    );
});

test("outbound send is allow-once, at-most-once, and never auto-retried or rerouted", () => {
    const profile = buildPassportMessagingProfileV1(profileInput());
    assert.equal(profile.outbound_dispatch.approval_policy, "allow_once");
    assert.equal(
        profile.outbound_dispatch.replay_semantics,
        "at_most_once_dispatch",
    );
    assert.equal(profile.outbound_dispatch.dispatch_attempt_ceiling, 1);
    assert.equal(
        profile.outbound_dispatch.provider_idempotency_key_required,
        true,
    );
    assert.equal(profile.outbound_dispatch.automatic_retry_allowed, false);
    assert.equal(
        profile.outbound_dispatch.unknown_outcome_policy,
        "seal_and_reconcile_read_only_or_stop",
    );
    assert.equal(
        profile.outbound_dispatch.cross_channel_fallback_allowed,
        false,
    );
    assert.equal(
        profile.outbound_dispatch.automatic_recipient_selection_allowed,
        false,
    );
});

test("incoming messages remain paired or allowlisted untrusted data", () => {
    const profile = buildPassportMessagingProfileV1(profileInput());
    assert.equal(profile.inbound_boundary.pairing_or_allowlist_required, true);
    assert.equal(
        profile.inbound_boundary.input_trust,
        "untrusted_external_content",
    );
    assert.equal(
        profile.inbound_boundary
            .automatic_action_from_inbound_content_allowed,
        false,
    );
    assert.equal(profile.inbound_boundary.memory_ingestion_enabled, false);
    assert.equal(profile.inbound_boundary.swarm_enabled, false);
});

test("Microsoft Teams cannot silently grant Outlook Mail or Calendar authority", () => {
    const profile = buildPassportMessagingProfileV1(profileInput());
    assert.equal(profile.microsoft_future.teams_channel_id, "msteams");
    assert.equal(
        profile.microsoft_future.outlook_mail,
        "planned_c004_read_draft",
    );
    assert.equal(profile.microsoft_future.calendar, "not_in_c003");
    assert.equal(
        profile.microsoft_future.shared_microsoft_authority_allowed,
        false,
    );
    assert.equal(profile.safety.enables_outlook_mail, false);
    assert.equal(profile.safety.enables_calendar, false);
});

test("receipt is signed and stores only fingerprints and bounded metadata", () => {
    const profile = buildPassportMessagingProfileV1(profileInput());
    assert.equal(profile.receipt.signature_required, true);
    assert.equal(profile.receipt.stores_raw_message, false);
    assert.equal(profile.receipt.stores_raw_target, false);
    assert.equal(profile.receipt.stores_provider_credentials, false);
    assert.equal(profile.receipt.exactly_once_effect_claim_allowed, false);
    assert.ok(profile.receipt.fields.includes("target_fingerprint"));
    assert.ok(profile.receipt.fields.includes("payload_fingerprint"));
    assert.ok(
        profile.receipt.fields.includes("provider_message_id_fingerprint"),
    );
    const serialized = JSON.stringify(profile);
    assert.doesNotMatch(serialized, /\+15551234567/);
    assert.doesNotMatch(serialized, /raw message body/i);
});

test("route, runtime, Viber, Microsoft, and authority drift fail closed", () => {
    const runtimeDrift = profileInput({ openclaw_version: "2026.7.2" });
    expectCode(
        "MESSAGING_RUNTIME_BINDING_INVALID",
        () => buildPassportMessagingProfileV1(runtimeDrift),
    );

    const missingRoute = profileInput();
    missingRoute.route_registry.routes.pop();
    expectCode(
        "MESSAGING_ROUTE_REGISTRY_INVALID",
        () => buildPassportMessagingProfileV1(missingRoute),
    );

    const activeRoute = profileInput();
    activeRoute.route_registry.routes[0].live_authority_allowed = true;
    expectCode(
        "MESSAGING_ROUTE_AUTHORITY_INVALID",
        () => buildPassportMessagingProfileV1(activeRoute),
    );

    const viberDrift = profileInput();
    const viber = viberDrift.route_registry.routes.find(
        (route) => route.channel_id === "viber",
    );
    viber.plugin_package = "@openclaw/viber";
    expectCode(
        "MESSAGING_VIBER_BOUNDARY_INVALID",
        () => buildPassportMessagingProfileV1(viberDrift),
    );

    const microsoftDrift = profileInput();
    microsoftDrift.route_registry.microsoft_future.outlook_mail = "send";
    expectCode(
        "MESSAGING_MICROSOFT_SCOPE_INVALID",
        () => buildPassportMessagingProfileV1(microsoftDrift),
    );
});

test("secret-like fields and fingerprint tampering are rejected", () => {
    const unsafeInput = profileInput();
    unsafeInput.provider_token = "must-not-enter-c003";
    expectCode(
        "MESSAGING_PROFILE_INVALID",
        () => buildPassportMessagingProfileV1(unsafeInput),
    );

    const profile = buildPassportMessagingProfileV1(profileInput());
    assert.equal(
        profile.profile_fingerprint_sha256,
        passportMessagingProfileFingerprint(profile),
    );
    const unsafe = structuredClone(profile);
    unsafe.safety.sends_message = true;
    unsafe.profile_fingerprint_sha256 =
        passportMessagingProfileFingerprint(unsafe);
    expectCode(
        "MESSAGING_PROFILE_SAFETY_INVALID",
        () => validatePassportMessagingProfileV1(unsafe),
    );
    const tampered = structuredClone(profile);
    tampered.routes[0].scope = "connector.discord.message.other";
    expectCode(
        "MESSAGING_PROFILE_FINGERPRINT_DRIFT",
        () => validatePassportMessagingProfileV1(tampered),
    );
});

test("C003 remains disconnected from the live plugin and side effects", () => {
    assert.doesNotMatch(pluginIndex, /passport-messaging-profile/);
    assert.doesNotMatch(pluginIndex, /buildPassportMessagingProfileV1/);
    assert.match(
        sourceModule,
        /PASSPORT_MESSAGING_LIVE_USE_ALLOWED = false/,
    );
    assert.match(sourceModule, /external_validation_pending/);
    assert.doesNotMatch(sourceModule, /\bfetch\(/);
    assert.doesNotMatch(sourceModule, /tools\.invoke/);
    assert.doesNotMatch(sourceModule, /runMessageAction/);
});

test("C003 proof closes passport messaging contract with zero live authority", async () => {
    const proof = await buildPassportMessagingProof();
    assert.equal(proof.development_identity, "1.4.0-alpha.3-dev.1");
    assert.equal(proof.status, "contract_only");
    assert.equal(
        proof.runtime_validation_status,
        "external_validation_pending",
    );
    assert.deepEqual(proof.official_channels, [
        "discord",
        "msteams",
        "signal",
        "sms",
        "whatsapp",
    ]);
    assert.deepEqual(proof.pending_external_channels, ["viber"]);
    assert.equal(proof.passport.verified_owner_required, true);
    assert.equal(proof.passport.verified_passport_required, true);
    assert.equal(proof.passport.per_agent_lease_required, true);
    assert.equal(proof.passport.max_actions_per_lease, 1);
    assert.equal(proof.dispatch.approval_policy, "allow_once");
    assert.equal(proof.dispatch.dispatch_attempt_ceiling, 1);
    assert.equal(proof.dispatch.automatic_retry_allowed, false);
    assert.equal(proof.receipt.signature_required, true);
    assert.equal(proof.safety.grants_authority, false);
    assert.equal(proof.safety.executes_tools, false);
    assert.equal(proof.safety.invokes_connector, false);
    assert.equal(proof.safety.sends_message, false);
    assert.equal(proof.closure.c003_contract_acceptance, "pass");
    assert.equal(
        proof.closure.external_openclaw_validation_pending,
        true,
    );
    console.log("NR_OC_CONNECTOR_BETA_C003=PASS");
});
