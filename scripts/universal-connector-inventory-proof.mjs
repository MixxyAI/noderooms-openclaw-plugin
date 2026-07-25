import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import {
    buildRuntimeToolInventoryV1,
    descriptorsFromOpenClawCatalog,
    REFERENCE_CONNECTOR_REGISTRY_V1,
    validateRuntimeToolInventoryV1,
} from "../src/universal-connector-engine.js";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

export async function buildUniversalConnectorInventoryProof() {
    const [descriptorFixture, catalogFixture, referenceRegistry] =
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
        ]);

    const exactSnapshot = validateRuntimeToolInventoryV1(
        buildRuntimeToolInventoryV1({
            captured_at: descriptorFixture.captured_at,
            refresh_reason: descriptorFixture.refresh_reason,
            inventory_generation: descriptorFixture.inventory_generation,
            source: descriptorFixture.source,
            tools: descriptorFixture.tools,
            registry: referenceRegistry,
        }),
    );

    const catalog = descriptorsFromOpenClawCatalog(catalogFixture);
    const schemaUnavailableSnapshot = validateRuntimeToolInventoryV1(
        buildRuntimeToolInventoryV1({
            captured_at: "2026-07-24T20:46:00Z",
            refresh_reason: "contract_test",
            inventory_generation: 1,
            source: {
                platform: "openclaw",
                catalog_kind: "tools_catalog",
                agent_id: catalog.agent_id,
            },
            tools: catalog.tools,
            registry: REFERENCE_CONNECTOR_REGISTRY_V1,
        }),
    );

    const githubTool = exactSnapshot.tools[0];
    const unavailableTool = schemaUnavailableSnapshot.tools[0];

    return Object.freeze({
        contract_version:
            "noderooms-phase4a-runtime-tool-inventory-proof-v1",
        proof_time: "2026-07-24T20:47:00Z",
        exact_inventory: Object.freeze({
            tool_count: exactSnapshot.metrics.inventory_tool_count,
            inventory_completeness_percent:
                exactSnapshot.metrics.inventory_completeness_percent,
            classification_coverage_percent:
                exactSnapshot.metrics.classification_coverage_percent,
            tool_name: githubTool.tool_name,
            owner_kind: githubTool.owner.kind,
            owner_id: githubTool.owner.owner_id,
            schema_fingerprint_sha256:
                githubTool.actual_input_schema_fingerprint_sha256,
            schema_matches_policy:
                githubTool.actual_input_schema_fingerprint_sha256
                === githubTool.expected_input_schema_fingerprint_sha256,
            output_receipt_profile: githubTool.output_receipt_profile,
            replay_semantics: githubTool.replay_semantics,
            side_effect_class: githubTool.side_effect_class,
            risk: githubTool.risk,
            coverage_status: githubTool.coverage_status,
            scope: githubTool.policy_binding.scope,
            approval_policy: githubTool.policy_binding.approval_policy,
            snapshot_fingerprint_sha256:
                exactSnapshot.snapshot_fingerprint_sha256,
        }),
        host_catalog_gap: Object.freeze({
            tool_name: unavailableTool.tool_name,
            coverage_status: unavailableTool.coverage_status,
            side_effecting_unclassified_tool_count:
                schemaUnavailableSnapshot.metrics
                    .side_effecting_unclassified_tool_count,
            enforce_eligible: unavailableTool.enforce_eligible,
            failed_closed: unavailableTool.coverage_status
                === "schema_unavailable"
                && unavailableTool.enforce_eligible === false,
        }),
        safety: Object.freeze({
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
        }),
        closure: Object.freeze({
            phase4a_acceptance: "pass",
            phase4b_policy_sync_authority_granted: false,
            phase4c_github_write_authority_granted: false,
        }),
    });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    process.stdout.write(
        `${JSON.stringify(await buildUniversalConnectorInventoryProof(), null, 2)}\n`,
    );
}
