import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
    buildRuntimeToolInventoryV1,
    descriptorsFromOpenClawCatalog,
    REFERENCE_CONNECTOR_REGISTRY_V1,
    runtimeToolInventoryFingerprint,
    UniversalConnectorInventoryController,
    UniversalConnectorInventoryError,
    validateRuntimeToolInventoryV1,
} from "../src/universal-connector-engine.js";
import {
    buildUniversalConnectorInventoryProof,
} from "../scripts/universal-connector-inventory-proof.mjs";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const [descriptorFixture, catalogFixture, referenceRegistry, inventorySchema] =
    await Promise.all([
        readJson(
            "contracts/fixtures/"
            + "github-draft-pr.runtime-tool-descriptor-v1.json",
        ),
        readJson(
            "contracts/fixtures/"
            + "openclaw-tools-catalog.schema-unavailable-v1.json",
        ),
        readJson("contracts/reference/github-draft-pr.v1.json"),
        readJson("contracts/runtime-tool-inventory-v1.schema.json"),
    ]);

function inventoryInput(overrides = {}) {
    return {
        captured_at: descriptorFixture.captured_at,
        refresh_reason: descriptorFixture.refresh_reason,
        inventory_generation: descriptorFixture.inventory_generation,
        source: structuredClone(descriptorFixture.source),
        tools: structuredClone(descriptorFixture.tools),
        registry: structuredClone(referenceRegistry),
        ...overrides,
    };
}

function expectCode(code, operation) {
    assert.throws(
        operation,
        (error) =>
            error instanceof UniversalConnectorInventoryError
            && error.code === code,
    );
}

test("004A JSON Schema freezes inventory-only authority and exact coverage fields", () => {
    assert.equal(inventorySchema.additionalProperties, false);
    assert.equal(
        inventorySchema.properties.contract_version.const,
        "noderooms-runtime-tool-inventory-v1",
    );
    assert.equal(inventorySchema.properties.activation_state.const, "inventory_only");
    assert.equal(inventorySchema.properties.live_enforce_allowed.const, false);
    assert.equal(
        inventorySchema.$defs.metrics.properties
            .inventory_completeness_percent.const,
        100,
    );
    assert.equal(
        inventorySchema.$defs.tool.properties.enforce_eligible.const,
        false,
    );
    assert.equal(
        inventorySchema.$defs.safety.properties.grants_authority.const,
        false,
    );
    assert.equal(
        inventorySchema.$defs.safety.properties.performs_external_write.const,
        false,
    );
});

test("compiled GitHub Draft PR reference profile matches the canonical registry", () => {
    const compiled = REFERENCE_CONNECTOR_REGISTRY_V1.profiles[0];
    const canonical = referenceRegistry.profiles[0];
    for (const key of [
        "profile_id",
        "scope",
        "status",
        "provider",
        "connector_id",
        "connector_version",
        "tool_name",
        "tool_schema_fingerprint",
        "action",
        "resource_type",
        "risk",
        "side_effect_class",
        "replay_semantics",
        "approval_policy",
        "receipt_profile",
    ]) {
        assert.deepEqual(compiled[key], canonical[key]);
    }
    assert.deepEqual(
        compiled.tool_input_schema,
        canonical.tool_input_schema,
    );
});

test("exact GitHub descriptor inventories every mandatory 4A dimension", () => {
    const snapshot = validateRuntimeToolInventoryV1(
        buildRuntimeToolInventoryV1(inventoryInput()),
    );
    assert.equal(snapshot.metrics.source_tool_count, 1);
    assert.equal(snapshot.metrics.inventory_tool_count, 1);
    assert.equal(snapshot.metrics.inventory_completeness_percent, 100);
    assert.equal(snapshot.metrics.classification_coverage_percent, 100);
    assert.equal(snapshot.metrics.side_effecting_unclassified_tool_count, 0);
    const tool = snapshot.tools[0];
    assert.equal(tool.tool_name, "github_create_pull_request");
    assert.deepEqual(tool.owner, {
        kind: "mcp",
        owner_id: "github",
        resolution: "exact",
    });
    assert.equal(
        tool.actual_input_schema_fingerprint_sha256,
        "sha256:c12e12e4f6a0d03d85c46dbe4e17cfe814f7a988f56ecc4c2b40089d621f8c37",
    );
    assert.equal(
        tool.actual_input_schema_fingerprint_sha256,
        tool.expected_input_schema_fingerprint_sha256,
    );
    assert.equal(tool.output_receipt_profile, "external_action_receipt_v2");
    assert.equal(tool.declared_replay_safe, false);
    assert.equal(tool.replay_semantics, "at_most_once_dispatch");
    assert.equal(tool.side_effect_class, "write");
    assert.equal(tool.risk, "high");
    assert.equal(tool.coverage_status, "covered_contract_only");
    assert.equal(tool.policy_binding.scope,
        "connector.github.pull_request.draft");
    assert.equal(tool.policy_binding.approval_policy, "allow_once");
    assert.equal(tool.enforce_eligible, false);
    assert.equal(tool.authority_status, "inventory_only_no_authority");
    assert.equal(snapshot.live_enforce_allowed, false);
    assert.equal(snapshot.safety.grants_authority, false);
    assert.equal(snapshot.safety.invokes_connectors, false);
    assert.equal(snapshot.safety.performs_external_write, false);
});

test("OpenClaw tools.catalog schema gap is explicit and fails closed", () => {
    const catalog = descriptorsFromOpenClawCatalog(catalogFixture);
    const snapshot = buildRuntimeToolInventoryV1(inventoryInput({
        source: {
            platform: "openclaw",
            catalog_kind: "tools_catalog",
            agent_id: catalog.agent_id,
        },
        tools: catalog.tools,
        registry: structuredClone(REFERENCE_CONNECTOR_REGISTRY_V1),
    }));
    const tool = snapshot.tools[0];
    assert.equal(tool.owner.kind, "plugin");
    assert.equal(tool.owner.owner_id, "github");
    assert.equal(tool.owner.resolution, "exact");
    assert.equal(tool.actual_input_schema_fingerprint_sha256, null);
    assert.equal(tool.coverage_status, "schema_unavailable");
    assert.equal(tool.potential_side_effect, true);
    assert.equal(tool.enforce_eligible, false);
    assert.equal(snapshot.metrics.side_effecting_unclassified_tool_count, 1);
    assert.equal(snapshot.metrics.enforce_profile_ready, false);
});

test("schema and policy drift remain visible and non-authoritative", () => {
    const schemaDrift = inventoryInput();
    schemaDrift.tools[0].input_schema.properties.draft = { type: "boolean" };
    const schemaSnapshot = buildRuntimeToolInventoryV1(schemaDrift);
    assert.equal(schemaSnapshot.tools[0].coverage_status, "schema_drift");
    assert.equal(schemaSnapshot.tools[0].enforce_eligible, false);
    assert.equal(schemaSnapshot.metrics.drifted_tool_count, 1);

    const policyDrift = inventoryInput();
    policyDrift.tools[0].declared_side_effect_class = "admin";
    const policySnapshot = buildRuntimeToolInventoryV1(policyDrift);
    assert.equal(policySnapshot.tools[0].coverage_status, "policy_drift");
    assert.equal(policySnapshot.tools[0].enforce_eligible, false);
    assert.equal(policySnapshot.metrics.drifted_tool_count, 1);
});

test("unresolved MCP owner and unprofiled writes cannot enter coverage", () => {
    const unresolved = inventoryInput();
    unresolved.tools[0].owner.resolution = "unresolved";
    const unresolvedSnapshot = buildRuntimeToolInventoryV1(unresolved);
    assert.equal(
        unresolvedSnapshot.tools[0].coverage_status,
        "owner_unresolved",
    );
    assert.equal(unresolvedSnapshot.tools[0].enforce_eligible, false);

    const unprofiled = inventoryInput();
    unprofiled.tools[0].tool_name = "unknown_external_write";
    const unprofiledSnapshot = buildRuntimeToolInventoryV1(unprofiled);
    assert.equal(
        unprofiledSnapshot.tools[0].coverage_status,
        "unclassified",
    );
    assert.equal(
        unprofiledSnapshot.metrics.side_effecting_unclassified_tool_count,
        1,
    );
});

test("duplicate tools and tampered registry schema are rejected", () => {
    const duplicate = inventoryInput();
    duplicate.tools.push(structuredClone(duplicate.tools[0]));
    expectCode(
        "INVENTORY_TOOL_DUPLICATE",
        () => buildRuntimeToolInventoryV1(duplicate),
    );

    const tamperedRegistry = inventoryInput();
    tamperedRegistry.registry.profiles[0].tool_input_schema.properties.draft =
        { type: "boolean" };
    expectCode(
        "INVENTORY_REGISTRY_SCHEMA_DRIFT",
        () => buildRuntimeToolInventoryV1(tamperedRegistry),
    );
});

test("snapshot fingerprint detects inventory result drift", () => {
    const snapshot = buildRuntimeToolInventoryV1(inventoryInput());
    assert.equal(
        snapshot.snapshot_fingerprint_sha256,
        runtimeToolInventoryFingerprint(snapshot),
    );
    const tampered = structuredClone(snapshot);
    tampered.tools[0].risk = "critical";
    expectCode(
        "INVENTORY_SNAPSHOT_DRIFT",
        () => validateRuntimeToolInventoryV1(tampered),
    );
});

test("Gateway refresh calls only read-only tools.catalog and grants no authority", async () => {
    const calls = [];
    const controller = new UniversalConnectorInventoryController({
        gateway: {
            async request(method, params, options) {
                calls.push({ method, params, options });
                return structuredClone(catalogFixture);
            },
        },
        registry: structuredClone(referenceRegistry),
        now: () => new Date("2026-07-24T20:48:00Z"),
    });
    const snapshot = await controller.refresh({
        reason: "gateway_start",
        agentId: "agent-example-openclaw",
    });
    assert.deepEqual(calls, [{
        method: "tools.catalog",
        params: {
            agentId: "agent-example-openclaw",
            includePlugins: true,
        },
        options: { timeoutMs: 4_000 },
    }]);
    assert.equal(snapshot.refresh_reason, "gateway_start");
    assert.equal(snapshot.live_enforce_allowed, false);
    assert.equal(controller.status().safety.invokes_connectors, false);
    assert.equal(controller.connectors().connectors[0].discovered, true);
    assert.equal(
        controller.connectors().connectors[0].authority_status,
        "inventory_only_no_authority",
    );
});

test("unknown observed tool records only its bounded name and requests refresh", async () => {
    const controller = new UniversalConnectorInventoryController({
        gateway: {
            async request() {
                return structuredClone(catalogFixture);
            },
        },
        now: () => new Date("2026-07-24T20:49:00Z"),
    });
    await controller.refresh({ reason: "gateway_start" });
    controller.observeBeforeToolCall({
        toolName: "mcp_new_write_tool",
        params: {
            secret: "must-not-be-recorded",
            body: "raw-content",
        },
    });
    const status = controller.status();
    assert.equal(status.refresh_required, true);
    assert.deepEqual(status.observed_unlisted_tools, ["mcp_new_write_tool"]);
    assert.doesNotMatch(JSON.stringify(status), /must-not-be-recorded/);
    assert.doesNotMatch(JSON.stringify(status), /raw-content/);
});

test("catalog failure is reported fail-closed without blocking Gateway startup", async () => {
    const controller = new UniversalConnectorInventoryController({
        gateway: {
            async request() {
                throw new Error("catalog unavailable");
            },
        },
    });
    assert.equal(
        await controller.refresh({ reason: "gateway_start" }),
        null,
    );
    const status = controller.status();
    assert.equal(status.snapshot, null);
    assert.equal(status.refresh_required, true);
    assert.equal(status.last_error.failed_closed, true);
    assert.equal(status.live_enforce_allowed, false);
});

test("PHASE4A_RUNTIME_TOOL_INVENTORY=PASS", async () => {
    const proof = await buildUniversalConnectorInventoryProof();
    assert.equal(
        proof.exact_inventory.inventory_completeness_percent,
        100,
    );
    assert.equal(proof.exact_inventory.schema_matches_policy, true);
    assert.equal(
        proof.exact_inventory.coverage_status,
        "covered_contract_only",
    );
    assert.equal(proof.host_catalog_gap.coverage_status, "schema_unavailable");
    assert.equal(proof.host_catalog_gap.failed_closed, true);
    assert.deepEqual(proof.safety, {
        live_enforce_allowed: false,
        authority_granted: false,
        tool_execution_attempted: false,
        connector_call_attempted: false,
        external_network_attempted: false,
        external_write_attempted: false,
        owner_decision_automated: false,
        publish_attempted: false,
        live_install_attempted: false,
        gateway_restart_attempted: false,
        production_modified: false,
    });
    assert.equal(proof.closure.phase4a_acceptance, "pass");
    assert.equal(
        proof.closure.phase4b_policy_sync_authority_granted,
        false,
    );
    assert.equal(
        proof.closure.phase4c_github_write_authority_granted,
        false,
    );
    console.log("NR_OC_CONNECTOR_004A=PASS");
});
