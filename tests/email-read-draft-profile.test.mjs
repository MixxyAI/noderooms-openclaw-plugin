import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Compile } from "typebox/compile";

import {
    buildEmailReadDraftProfileV1,
    EmailReadDraftProfileError,
    emailReadDraftProfileFingerprint,
    validateEmailReadDraftProfileV1,
} from "../src/email-read-draft-profile.js";
import { sha256Fingerprint } from "../src/passport-runtime-binding.js";
import {
    buildRuntimeToolInventoryV1,
} from "../src/universal-connector-engine.js";
import {
    buildEmailReadDraftProof,
} from "../scripts/email-read-draft-proof.mjs";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const [
    descriptorFixture,
    registryFixture,
    profileSchema,
    sourceModule,
    pluginIndex,
] = await Promise.all([
    readJson(
        "contracts/fixtures/"
        + "gmail-read-draft.runtime-tool-descriptor-v1.json",
    ),
    readJson("contracts/reference/gmail-read-draft.v1.json"),
    readJson("contracts/email-read-draft-profile-v1.schema.json"),
    readFile(
        new URL("../src/email-read-draft-profile.js", import.meta.url),
        "utf8",
    ),
    readFile(new URL("../src/index.js", import.meta.url), "utf8"),
]);

function inventory(overrides = {}) {
    const descriptor = structuredClone(descriptorFixture);
    const registry = structuredClone(registryFixture);
    overrides.mutateDescriptor?.(descriptor);
    overrides.mutateRegistry?.(registry);
    return buildRuntimeToolInventoryV1({
        captured_at: descriptor.captured_at,
        refresh_reason: descriptor.refresh_reason,
        inventory_generation: descriptor.inventory_generation,
        source: descriptor.source,
        tools: descriptor.tools,
        registry,
    });
}

function profileInput(overrides = {}) {
    return {
        profile_id: "nrc002_gmail_read_draft_001",
        captured_at: "2026-07-30T13:21:00Z",
        inventory_snapshot: inventory(),
        owner_version: "0.1.5",
        version_source: "contract_fixture",
        account_binding_fingerprint_sha256: sha256Fingerprint({
            provider: "gmail",
            account_ref: "fixture-account-001",
        }),
        reader_agent_id: "mail_reader",
        drafter_agent_id: "mail_drafter",
        ...overrides,
    };
}

function expectCode(code, operation) {
    assert.throws(
        operation,
        (error) =>
            error instanceof EmailReadDraftProfileError
            && error.code === code,
    );
}

test("C002 registry binds exact Gmail search, read, and draft schemas", () => {
    assert.equal(registryFixture.activation_state, "contract_only");
    assert.equal(registryFixture.live_enforce_allowed, false);
    assert.equal(registryFixture.profiles.length, 3);
    const profiles = new Map(
        registryFixture.profiles.map((profile) => [
            profile.tool_name,
            profile,
        ]),
    );
    for (const descriptor of descriptorFixture.tools) {
        const profile = profiles.get(descriptor.tool_name);
        assert.ok(profile);
        assert.equal(
            profile.tool_schema_fingerprint,
            sha256Fingerprint(descriptor.input_schema),
        );
        assert.deepEqual(
            profile.tool_input_schema,
            descriptor.input_schema,
        );
        assert.equal(profile.status, "reference_only");
        assert.equal(profile.provider, "gmail");
        assert.equal(profile.connector_id, "openclaw.codex.gmail-app");
        assert.equal(profile.connector_version, "0.1.5");
    }
});

test("C002 JSON Schema freezes contract-only and no-send boundaries", () => {
    assert.equal(profileSchema.additionalProperties, false);
    assert.equal(
        profileSchema.properties.development_identity.const,
        "1.4.0-alpha.2-dev.1",
    );
    assert.equal(
        profileSchema.properties.activation_state.const,
        "contract_only",
    );
    assert.equal(
        profileSchema.properties.live_email_use_allowed.const,
        false,
    );
    assert.equal(
        profileSchema.properties.runtime_validation_status.const,
        "external_validation_pending",
    );
    assert.equal(
        profileSchema.$defs.safety.properties.sends_email.const,
        false,
    );
    const validator = Compile(profileSchema);
    const profile = buildEmailReadDraftProfileV1(profileInput());
    assert.equal(validator.Check(profile), true);
    const unsafe = structuredClone(profile);
    unsafe.drafter.send_capability_present = true;
    assert.equal(validator.Check(unsafe), false);
});

test("reader Agent has only replay-safe Gmail search and thread read", () => {
    const profile = validateEmailReadDraftProfileV1(
        buildEmailReadDraftProfileV1(profileInput()),
    );
    assert.deepEqual(profile.reader.allowed_tool_names, [
        "gmail_read_email_thread",
        "gmail_search_emails",
    ]);
    assert.equal(profile.reader.input_trust, "untrusted_external_content");
    assert.equal(profile.reader.sandbox_mode, "all");
    assert.equal(profile.reader.sandbox_scope, "session");
    assert.equal(profile.reader.workspace_access, "none");
    assert.equal(profile.reader.handoff_policy, "summary_only");
    assert.equal(profile.reader.memory_ingestion_enabled, false);
    assert.equal(profile.reader.swarm_enabled, false);
    for (const tool of profile.reader.tools) {
        assert.equal(tool.side_effect_class, "read");
        assert.equal(tool.replay_semantics, "replay_safe_read");
        assert.equal(tool.approval_policy, "none");
        assert.equal(tool.receipt_profile, "read_observation_v1");
        assert.equal(tool.enforce_eligible, false);
    }
});

test("draft is unsent, recipient-bound, Owner-reviewed, and allow-once", () => {
    const profile = buildEmailReadDraftProfileV1(profileInput());
    assert.equal(profile.drafter.tool.tool_name, "gmail_create_draft");
    assert.equal(profile.drafter.tool.side_effect_class, "write");
    assert.equal(profile.drafter.tool.risk, "high");
    assert.equal(
        profile.drafter.tool.replay_semantics,
        "at_most_once_dispatch",
    );
    assert.equal(profile.drafter.tool.approval_policy, "allow_once");
    assert.equal(
        profile.drafter.mailbox_effect,
        "create_unsent_draft_only",
    );
    assert.equal(
        profile.drafter.exact_recipient_resolution_required,
        true,
    );
    assert.equal(
        profile.drafter.automatic_recipient_selection_allowed,
        false,
    );
    assert.equal(profile.drafter.human_owner_review_required, true);
    assert.equal(profile.drafter.send_capability_present, false);
    assert.equal(profile.drafter.forward_capability_present, false);
    assert.equal(profile.drafter.destructive_capability_present, false);
});

test("send, forward, mutation, and destructive Gmail tools stay forbidden", () => {
    const profile = buildEmailReadDraftProfileV1(profileInput());
    for (const toolName of [
        "gmail_send_email",
        "gmail_send_draft",
        "gmail_forward_emails",
        "gmail_archive_emails",
        "gmail_apply_labels_to_emails",
        "gmail_delete_emails",
    ]) {
        assert.ok(profile.forbidden_tool_names.includes(toolName));
    }
    assert.equal(profile.safety.sends_email, false);
    assert.equal(profile.safety.forwards_email, false);
    assert.equal(profile.safety.mutates_labels, false);
    assert.equal(profile.safety.archives_email, false);
    assert.equal(profile.safety.deletes_email, false);
});

test("schema, owner, version, and semantic drift fail closed", () => {
    expectCode(
        "EMAIL_PROFILE_SCHEMA_DRIFT",
        () => buildEmailReadDraftProfileV1({
            ...profileInput(),
            inventory_snapshot: inventory({
                mutateDescriptor(descriptor) {
                    descriptor.tools[0].input_schema.properties.query
                        .maxLength = 8192;
                },
            }),
        }),
    );
    expectCode(
        "EMAIL_PROFILE_OWNER_DRIFT",
        () => buildEmailReadDraftProfileV1({
            ...profileInput(),
            inventory_snapshot: inventory({
                mutateDescriptor(descriptor) {
                    descriptor.tools[0].owner.owner_id = "gmail-drifted";
                },
            }),
        }),
    );
    expectCode(
        "EMAIL_PROFILE_VERSION_SOURCE_INVALID",
        () => buildEmailReadDraftProfileV1(profileInput({
            owner_version: "9.9.9",
        })),
    );
    expectCode(
        "EMAIL_PROFILE_SEMANTICS_DRIFT",
        () => buildEmailReadDraftProfileV1({
            ...profileInput(),
            inventory_snapshot: inventory({
                mutateDescriptor(descriptor) {
                    descriptor.tools[2].declared_replay_safe = true;
                },
            }),
        }),
    );
});

test("missing, extra, or cross-Agent tool authority is rejected", () => {
    expectCode(
        "EMAIL_PROFILE_TOOL_SET_INVALID",
        () => buildEmailReadDraftProfileV1({
            ...profileInput(),
            inventory_snapshot: inventory({
                mutateDescriptor(descriptor) {
                    descriptor.tools.pop();
                },
                mutateRegistry(registry) {
                    registry.profiles.pop();
                },
            }),
        }),
    );
    expectCode(
        "EMAIL_PROFILE_AGENT_ISOLATION_INVALID",
        () => buildEmailReadDraftProfileV1(profileInput({
            drafter_agent_id: "mail_reader",
        })),
    );
});

test("secret-like, raw mailbox, and recipient fields cannot enter C002 state", () => {
    const unsafe = profileInput();
    unsafe.provider_token = "must-not-enter-state";
    expectCode(
        "EMAIL_PROFILE_INVALID",
        () => buildEmailReadDraftProfileV1(unsafe),
    );
    const profile = buildEmailReadDraftProfileV1(profileInput());
    const serialized = JSON.stringify(profile);
    assert.doesNotMatch(serialized, /must-not-enter-state/);
    assert.doesNotMatch(serialized, /fixture-account-001/);
    assert.doesNotMatch(serialized, /@example\.com/);
    assert.equal(profile.safety.stores_provider_credentials, false);
    assert.equal(profile.safety.stores_raw_email_content, false);
    assert.equal(profile.safety.stores_raw_draft_content, false);
    assert.equal(profile.safety.stores_raw_recipient_values, false);
});

test("profile fingerprint detects tool and safety drift", () => {
    const profile = buildEmailReadDraftProfileV1(profileInput());
    assert.equal(
        profile.profile_fingerprint_sha256,
        emailReadDraftProfileFingerprint(profile),
    );
    const unsafe = structuredClone(profile);
    unsafe.safety.sends_email = true;
    unsafe.profile_fingerprint_sha256 =
        emailReadDraftProfileFingerprint(unsafe);
    expectCode(
        "EMAIL_PROFILE_SAFETY_INVALID",
        () => validateEmailReadDraftProfileV1(unsafe),
    );
    const tampered = structuredClone(profile);
    tampered.drafter.tool.input_schema_fingerprint_sha256 =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    expectCode(
        "EMAIL_PROFILE_FINGERPRINT_DRIFT",
        () => validateEmailReadDraftProfileV1(tampered),
    );
});

test("C002 remains disconnected from the live plugin and side effects", () => {
    assert.doesNotMatch(pluginIndex, /email-read-draft-profile/);
    assert.doesNotMatch(pluginIndex, /buildEmailReadDraftProfileV1/);
    assert.match(
        sourceModule,
        /EMAIL_READ_DRAFT_LIVE_USE_ALLOWED = false/,
    );
    assert.match(
        sourceModule,
        /external_validation_pending/,
    );
    assert.doesNotMatch(sourceModule, /\bfetch\(/);
    assert.doesNotMatch(sourceModule, /"tools\.invoke"/);
    assert.doesNotMatch(sourceModule, /"tools\.catalog"/);
    assert.doesNotMatch(sourceModule, /\.runTask\(/);
    assert.doesNotMatch(sourceModule, /\.request\(/);
});

test("C002 proof closes read and draft contract with zero live authority", async () => {
    const proof = await buildEmailReadDraftProof();
    assert.equal(proof.development_identity, "1.4.0-alpha.2-dev.1");
    assert.equal(proof.status, "contract_only");
    assert.equal(
        proof.runtime_validation_status,
        "external_validation_pending",
    );
    assert.equal(proof.inventory.inventory_tool_count, 3);
    assert.equal(proof.inventory.schema_verified_tool_count, 3);
    assert.equal(proof.inventory.unclassified_tool_count, 0);
    assert.equal(proof.inventory.drifted_tool_count, 0);
    assert.equal(proof.reader.isolated_agent, true);
    assert.equal(proof.reader.summary_only_handoff, true);
    assert.equal(proof.draft.approval_policy, "allow_once");
    assert.equal(proof.draft.send_capability_present, false);
    assert.equal(proof.safety.grants_authority, false);
    assert.equal(proof.safety.executes_tools, false);
    assert.equal(proof.safety.invokes_email_connector, false);
    assert.equal(proof.safety.reads_live_mailbox, false);
    assert.equal(proof.safety.creates_live_draft, false);
    assert.equal(proof.safety.sends_email, false);
    assert.equal(proof.closure.c002_contract_acceptance, "pass");
    assert.equal(
        proof.closure.external_openclaw_validation_pending,
        true,
    );
    console.log("NR_OC_CONNECTOR_BETA_C002=PASS");
});
