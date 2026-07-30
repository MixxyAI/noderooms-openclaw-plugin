import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Compile } from "typebox/compile";

import {
    buildConnectorBetaFoundationV1,
    ConnectorBetaFoundationError,
    connectorBetaFoundationFingerprint,
    validateConnectorBetaFoundationV1,
} from "../src/connector-beta-foundation.js";
import {
    buildRuntimeToolInventoryV1,
    runtimeToolInventoryFingerprint,
} from "../src/universal-connector-engine.js";
import {
    buildConnectorBetaFoundationProof,
} from "../scripts/connector-beta-foundation-proof.mjs";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const [
    descriptorFixture,
    referenceRegistry,
    foundationFixture,
    foundationSchema,
    sourceModule,
    pluginIndex,
] = await Promise.all([
    readJson(
        "contracts/fixtures/"
        + "github-draft-pr.runtime-tool-descriptor-v1.json",
    ),
    readJson("contracts/reference/github-draft-pr.v1.json"),
    readJson(
        "contracts/fixtures/"
        + "connector-beta.github-reference-foundation-v1.json",
    ),
    readJson("contracts/openclaw-connector-beta-foundation-v1.schema.json"),
    readFile(
        new URL("../src/connector-beta-foundation.js", import.meta.url),
        "utf8",
    ),
    readFile(new URL("../src/index.js", import.meta.url), "utf8"),
]);

function inventory(overrides = {}) {
    const descriptor = structuredClone(descriptorFixture);
    const registry = structuredClone(referenceRegistry);
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

function foundationInput(overrides = {}) {
    return {
        foundation_id: "nrcbf_2026-07-30.001",
        capture_kind: "contract_fixture",
        captured_at: "2026-07-30T10:30:00Z",
        openclaw_version: "2026.7.1-2",
        plugin_api_version: "2026.7.1-2",
        inventory_snapshot: inventory(),
        connector_candidates: [{
            connector_key: "nrcbc_github_draft_pr_reference_v1",
            family: "reference",
            owner_version: "0.0.0-reference.1",
            version_source: "contract_fixture",
            tool_names: ["github_create_pull_request"],
        }],
        ...overrides,
    };
}

function expectCode(code, operation) {
    assert.throws(
        operation,
        (error) =>
            error instanceof ConnectorBetaFoundationError
            && error.code === code,
    );
}

test("C001 JSON Schema freezes the discovery-only development boundary", () => {
    assert.equal(foundationSchema.additionalProperties, false);
    assert.equal(
        foundationSchema.properties.contract_version.const,
        "noderooms-openclaw-connector-beta-foundation-v1",
    );
    assert.equal(
        foundationSchema.properties.development_identity.const,
        "1.4.0-alpha.1-dev.1",
    );
    assert.equal(
        foundationSchema.properties.activation_state.const,
        "discovery_only",
    );
    assert.equal(
        foundationSchema.properties.live_connector_use_allowed.const,
        false,
    );
    assert.deepEqual(
        foundationSchema.$defs.connector.properties.family.enum,
        ["email", "discord", "whatsapp", "sms", "reference"],
    );
    assert.equal(
        foundationSchema.$defs.connector.properties
            .noderooms_stores_provider_credentials.const,
        false,
    );
    assert.equal(
        foundationSchema.$defs.tool.properties.enforce_eligible.const,
        false,
    );
    assert.equal(
        foundationSchema.$defs.safety.properties
            .performs_external_write.const,
        false,
    );
    const validator = Compile(foundationSchema);
    assert.equal(validator.Check(foundationFixture), true);
    const unsafeFixture = structuredClone(foundationFixture);
    unsafeFixture.live_connector_use_allowed = true;
    assert.equal(validator.Check(unsafeFixture), false);
});

test("reference fixture binds exact owner version, tool, and schema fingerprint", () => {
    const snapshot = validateConnectorBetaFoundationV1(
        buildConnectorBetaFoundationV1(foundationInput()),
    );
    assert.deepEqual(snapshot, foundationFixture);
    assert.equal(snapshot.metrics.connector_count, 1);
    assert.equal(snapshot.metrics.tool_binding_count, 1);
    assert.equal(snapshot.metrics.schema_verified_tool_count, 1);
    assert.equal(snapshot.metrics.unclassified_tool_count, 0);
    assert.equal(snapshot.metrics.drifted_tool_count, 0);
    const connector = snapshot.connectors[0];
    assert.deepEqual(connector.owner, {
        kind: "mcp",
        owner_id: "github",
        resolution: "exact",
        owner_version: "0.0.0-reference.1",
        version_source: "contract_fixture",
    });
    assert.equal(connector.credential_custodian, "openclaw");
    assert.equal(connector.noderooms_stores_provider_credentials, false);
    const tool = connector.tools[0];
    assert.equal(tool.tool_name, "github_create_pull_request");
    assert.equal(
        tool.input_schema_fingerprint_sha256,
        "sha256:c12e12e4f6a0d03d85c46dbe4e17cfe814f7a988f56ecc4c2b40089d621f8c37",
    );
    assert.equal(tool.approval_policy, "allow_once");
    assert.equal(tool.enforce_eligible, false);
    assert.equal(tool.authority_status, "discovery_only_no_authority");
});

test("missing schema and schema drift fail before a connector can bind", () => {
    const schemaUnavailable = foundationInput({
        inventory_snapshot: inventory({
            mutateDescriptor(descriptor) {
                delete descriptor.tools[0].input_schema;
            },
        }),
    });
    expectCode(
        "CONNECTOR_BETA_SCHEMA_UNAVAILABLE",
        () => buildConnectorBetaFoundationV1(schemaUnavailable),
    );

    const schemaDrift = foundationInput({
        inventory_snapshot: inventory({
            mutateDescriptor(descriptor) {
                descriptor.tools[0].input_schema.properties.draft = {
                    type: "boolean",
                };
            },
        }),
    });
    expectCode(
        "CONNECTOR_BETA_SCHEMA_DRIFT",
        () => buildConnectorBetaFoundationV1(schemaDrift),
    );
});

test("unresolved owner and unprofiled tool remain outside C001 coverage", () => {
    const unresolved = foundationInput({
        inventory_snapshot: inventory({
            mutateDescriptor(descriptor) {
                descriptor.tools[0].owner.resolution = "unresolved";
            },
        }),
    });
    expectCode(
        "CONNECTOR_BETA_OWNER_UNRESOLVED",
        () => buildConnectorBetaFoundationV1(unresolved),
    );

    const missingTool = foundationInput();
    missingTool.connector_candidates[0].tool_names =
        ["gmail_send_unverified"];
    expectCode(
        "CONNECTOR_BETA_TOOL_NOT_IN_INVENTORY",
        () => buildConnectorBetaFoundationV1(missingTool),
    );
});

test("capture kind and exact version provenance cannot be mixed", () => {
    const wrongSource = foundationInput();
    wrongSource.connector_candidates[0].version_source =
        "runtime_plugin_manifest";
    expectCode(
        "CONNECTOR_BETA_CAPTURE_SOURCE_MISMATCH",
        () => buildConnectorBetaFoundationV1(wrongSource),
    );

    const falseFamily = foundationInput();
    falseFamily.connector_candidates[0].family = "email";
    expectCode(
        "CONNECTOR_BETA_FAMILY_INVALID",
        () => buildConnectorBetaFoundationV1(falseFamily),
    );

    const wildcardVersion = foundationInput();
    wildcardVersion.connector_candidates[0].owner_version = "*";
    expectCode(
        "CONNECTOR_BETA_CONTRACT_INVALID",
        () => buildConnectorBetaFoundationV1(wildcardVersion),
    );
});

test("duplicate connector and tool bindings fail closed", () => {
    const duplicateConnector = foundationInput();
    duplicateConnector.connector_candidates.push(
        structuredClone(duplicateConnector.connector_candidates[0]),
    );
    expectCode(
        "CONNECTOR_BETA_CONNECTOR_DUPLICATE",
        () => buildConnectorBetaFoundationV1(duplicateConnector),
    );

    const reusedTool = foundationInput();
    reusedTool.connector_candidates.push({
        ...structuredClone(reusedTool.connector_candidates[0]),
        connector_key: "nrcbc_second_reference_v1",
    });
    expectCode(
        "CONNECTOR_BETA_TOOL_REUSED",
        () => buildConnectorBetaFoundationV1(reusedTool),
    );
});

test("secret-like or raw provider fields are rejected instead of persisted", () => {
    const secretField = foundationInput();
    secretField.connector_candidates[0].provider_token =
        "fixture-secret-must-not-enter-output";
    expectCode(
        "CONNECTOR_BETA_CONTRACT_INVALID",
        () => buildConnectorBetaFoundationV1(secretField),
    );
    assert.doesNotMatch(
        JSON.stringify(buildConnectorBetaFoundationV1(foundationInput())),
        /fixture-secret-must-not-enter-output/,
    );
});

test("active inventory metadata cannot cross the C001 non-live boundary", () => {
    const activeInventory = structuredClone(inventory());
    activeInventory.registry_binding.activation_state = "active";
    activeInventory.registry_binding.live_enforce_allowed = true;
    activeInventory.snapshot_fingerprint_sha256 =
        runtimeToolInventoryFingerprint(activeInventory);
    const input = foundationInput({ inventory_snapshot: activeInventory });
    expectCode(
        "CONNECTOR_BETA_INVENTORY_BOUNDARY_INVALID",
        () => buildConnectorBetaFoundationV1(input),
    );
});

test("foundation fingerprint detects metadata and safety drift", () => {
    const snapshot = buildConnectorBetaFoundationV1(foundationInput());
    assert.equal(
        snapshot.foundation_fingerprint_sha256,
        connectorBetaFoundationFingerprint(snapshot),
    );
    const tampered = structuredClone(snapshot);
    tampered.connectors[0].owner.owner_version = "9.9.9";
    expectCode(
        "CONNECTOR_BETA_FINGERPRINT_DRIFT",
        () => validateConnectorBetaFoundationV1(tampered),
    );

    const unsafe = structuredClone(snapshot);
    unsafe.safety.performs_external_write = true;
    expectCode(
        "CONNECTOR_BETA_SAFETY_INVALID",
        () => validateConnectorBetaFoundationV1(unsafe),
    );
});

test("C001 source stays disconnected from live plugin and side effects", () => {
    assert.doesNotMatch(pluginIndex, /connector-beta-foundation/);
    assert.doesNotMatch(pluginIndex, /buildConnectorBetaFoundationV1/);
    assert.match(
        sourceModule,
        /CONNECTOR_BETA_LIVE_CONNECTOR_USE_ALLOWED = false/,
    );
    assert.doesNotMatch(sourceModule, /\bfetch\(/);
    assert.doesNotMatch(sourceModule, /"tools\.invoke"/);
    assert.doesNotMatch(sourceModule, /"tools\.catalog"/);
    assert.doesNotMatch(sourceModule, /\.runTask\(/);
    assert.doesNotMatch(sourceModule, /\.resume\(/);
    assert.doesNotMatch(sourceModule, /child_process/);
});

test("C001 proof closes reference binding with zero live authority", async () => {
    const proof = await buildConnectorBetaFoundationProof();
    assert.equal(proof.development_identity, "1.4.0-alpha.1-dev.1");
    assert.equal(proof.reference_fixture.fixture_matches, true);
    assert.equal(proof.reference_fixture.schema_verified, true);
    assert.equal(
        proof.reference_fixture.authority_status,
        "discovery_only_no_authority",
    );
    assert.deepEqual(
        proof.future_connector_families,
        ["email", "discord", "whatsapp", "sms"],
    );
    assert.deepEqual(proof.safety, {
        live_connector_use_allowed: false,
        authority_granted: false,
        tool_execution_attempted: false,
        connector_call_attempted: false,
        external_network_attempted: false,
        external_write_attempted: false,
        provider_credentials_stored: false,
        raw_schema_stored: false,
        raw_parameters_stored: false,
        raw_results_stored: false,
        owner_decision_automated: false,
        gateway_modified: false,
        production_modified: false,
        publish_attempted: false,
    });
    assert.equal(proof.closure.c001_acceptance, "pass");
    assert.equal(proof.closure.c002_email_runtime_enabled, false);
    assert.equal(proof.closure.c003_messaging_runtime_enabled, false);
    assert.equal(proof.closure.c004_provider_write_enabled, false);
    console.log("NR_OC_CONNECTOR_BETA_C001=PASS");
});
