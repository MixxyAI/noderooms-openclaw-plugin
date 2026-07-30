import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import {
    buildConnectorBetaFoundationV1,
    validateConnectorBetaFoundationV1,
} from "../src/connector-beta-foundation.js";
import { canonicalJson } from "../src/passport-runtime-binding.js";
import {
    buildRuntimeToolInventoryV1,
} from "../src/universal-connector-engine.js";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

export async function buildConnectorBetaFoundationProof() {
    const [descriptorFixture, referenceRegistry, expectedFoundation] =
        await Promise.all([
            readJson(
                "contracts/fixtures/"
                + "github-draft-pr.runtime-tool-descriptor-v1.json",
            ),
            readJson("contracts/reference/github-draft-pr.v1.json"),
            readJson(
                "contracts/fixtures/"
                + "connector-beta.github-reference-foundation-v1.json",
            ),
        ]);

    const inventory = buildRuntimeToolInventoryV1({
        captured_at: descriptorFixture.captured_at,
        refresh_reason: descriptorFixture.refresh_reason,
        inventory_generation: descriptorFixture.inventory_generation,
        source: descriptorFixture.source,
        tools: descriptorFixture.tools,
        registry: referenceRegistry,
    });
    const foundation = validateConnectorBetaFoundationV1(
        buildConnectorBetaFoundationV1({
            foundation_id: "nrcbf_2026-07-30.001",
            capture_kind: "contract_fixture",
            captured_at: "2026-07-30T10:30:00Z",
            openclaw_version: "2026.7.1-2",
            plugin_api_version: "2026.7.1-2",
            inventory_snapshot: inventory,
            connector_candidates: [{
                connector_key:
                    "nrcbc_github_draft_pr_reference_v1",
                family: "reference",
                owner_version: "0.0.0-reference.1",
                version_source: "contract_fixture",
                tool_names: ["github_create_pull_request"],
            }],
        }),
    );
    const fixtureMatches =
        canonicalJson(foundation) === canonicalJson(expectedFoundation);
    const connector = foundation.connectors[0];
    const tool = connector.tools[0];

    return Object.freeze({
        contract_version:
            "noderooms-connector-beta-foundation-proof-v1",
        proof_time: "2026-07-30T10:31:00Z",
        development_identity: foundation.development_identity,
        reference_fixture: Object.freeze({
            fixture_matches: fixtureMatches,
            connector_count: foundation.metrics.connector_count,
            tool_binding_count: foundation.metrics.tool_binding_count,
            family: connector.family,
            owner_kind: connector.owner.kind,
            owner_id: connector.owner.owner_id,
            owner_version: connector.owner.owner_version,
            tool_name: tool.tool_name,
            schema_fingerprint_sha256:
                tool.input_schema_fingerprint_sha256,
            schema_verified:
                tool.input_schema_fingerprint_sha256
                === inventory.tools[0]
                    .actual_input_schema_fingerprint_sha256,
            coverage_status: tool.coverage_status,
            approval_policy: tool.approval_policy,
            authority_status: tool.authority_status,
            foundation_fingerprint_sha256:
                foundation.foundation_fingerprint_sha256,
        }),
        future_connector_families: Object.freeze([
            "email",
            "discord",
            "whatsapp",
            "sms",
        ]),
        safety: Object.freeze({
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
        }),
        closure: Object.freeze({
            c001_acceptance: fixtureMatches ? "pass" : "fail",
            c002_email_runtime_enabled: false,
            c003_messaging_runtime_enabled: false,
            c004_provider_write_enabled: false,
        }),
    });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    process.stdout.write(
        `${JSON.stringify(await buildConnectorBetaFoundationProof(), null, 2)}\n`,
    );
}
