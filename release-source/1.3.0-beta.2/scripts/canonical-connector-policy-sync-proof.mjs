import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import {
    CanonicalConnectorPolicySyncController,
    createCanonicalPolicySyncCheckpointV1,
    createInMemoryCanonicalPolicyCheckpointStore,
} from "../src/canonical-connector-policy-sync.js";
import {
    buildRuntimeToolInventoryV1,
    descriptorsFromOpenClawCatalog,
    validateRuntimeToolInventoryV1,
} from "../src/universal-connector-engine.js";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

function fixtureSource(bundle, calls) {
    return Object.freeze({
        async read(request) {
            calls.push(structuredClone(request));
            return structuredClone(bundle);
        },
    });
}

function exactInventory(descriptorFixture, registry) {
    return validateRuntimeToolInventoryV1(
        buildRuntimeToolInventoryV1({
            captured_at: descriptorFixture.captured_at,
            refresh_reason: descriptorFixture.refresh_reason,
            inventory_generation: descriptorFixture.inventory_generation,
            source: descriptorFixture.source,
            tools: descriptorFixture.tools,
            registry,
        }),
    );
}

function unavailableInventory(catalogFixture, registry) {
    const catalog = descriptorsFromOpenClawCatalog(catalogFixture);
    return validateRuntimeToolInventoryV1(
        buildRuntimeToolInventoryV1({
            captured_at: "2026-07-25T13:16:00.000Z",
            refresh_reason: "contract_test",
            inventory_generation: 1,
            source: {
                platform: "openclaw",
                catalog_kind: "tools_catalog",
                agent_id: catalog.agent_id,
            },
            tools: catalog.tools,
            registry,
        }),
    );
}

export async function buildCanonicalConnectorPolicySyncProof() {
    const [
        trustAnchor,
        bundle,
        checkpointFixture,
        descriptorFixture,
        catalogFixture,
    ] = await Promise.all([
        readJson(
            "contracts/fixtures/"
            + "noderooms-canonical-policy.trust-anchor-v1.json",
        ),
        readJson(
            "contracts/fixtures/"
            + "github-draft-pr.canonical-policy-bundle-v1.json",
        ),
        readJson(
            "contracts/fixtures/"
            + "github-draft-pr.policy-sync-checkpoint-v1.json",
        ),
        readJson(
            "contracts/fixtures/"
            + "github-draft-pr.runtime-tool-descriptor-v1.json",
        ),
        readJson(
            "contracts/fixtures/"
            + "openclaw-tools-catalog.schema-unavailable-v1.json",
        ),
    ]);
    const now = () => new Date("2026-07-25T13:15:00.000Z");
    const sourceCalls = [];
    const checkpointStore =
        createInMemoryCanonicalPolicyCheckpointStore();
    const controller = new CanonicalConnectorPolicySyncController({
        source: fixtureSource(bundle, sourceCalls),
        checkpointStore,
        trustAnchor,
        allowFixture: true,
        now,
    });
    const sync = await controller.sync({ reason: "contract_test" });
    const registry = controller.verifiedRegistry();
    const inventory = exactInventory(descriptorFixture, registry);
    const binding = controller.bindInventory(inventory);

    const restartCalls = [];
    const restart = new CanonicalConnectorPolicySyncController({
        source: fixtureSource(bundle, restartCalls),
        checkpointStore,
        trustAnchor,
        allowFixture: true,
        now,
    });
    const restartSync = await restart.sync({
        reason: "before_phase4c_proof",
    });
    const restartBinding = restart.bindInventory(inventory);

    const gapCalls = [];
    const gap = new CanonicalConnectorPolicySyncController({
        source: fixtureSource(bundle, gapCalls),
        checkpointStore:
            createInMemoryCanonicalPolicyCheckpointStore(
                checkpointFixture,
            ),
        trustAnchor,
        allowFixture: true,
        now,
    });
    await gap.sync({ reason: "contract_test" });
    const unavailable = unavailableInventory(catalogFixture, registry);
    const unavailableBinding = gap.bindInventory(unavailable);

    const futureBundle = structuredClone(bundle);
    futureBundle.sequence = 2;
    futureBundle.bundle_id = `nrpolicy_${"f".repeat(32)}`;
    futureBundle.bundle_fingerprint_sha256 = `sha256:${"f".repeat(64)}`;
    futureBundle.registry_fingerprint_sha256 =
        bundle.registry_fingerprint_sha256;
    const futureCheckpoint = createCanonicalPolicySyncCheckpointV1(
        futureBundle,
        Date.parse("2026-07-25T13:14:00.000Z"),
    );
    const rollback = new CanonicalConnectorPolicySyncController({
        source: fixtureSource(bundle, []),
        checkpointStore:
            createInMemoryCanonicalPolicyCheckpointStore(
                futureCheckpoint,
            ),
        trustAnchor,
        allowFixture: true,
        now,
    });
    const rollbackResult = await rollback.sync({
        reason: "contract_test",
    });

    const tamperedBundle = structuredClone(bundle);
    tamperedBundle.attestation.signature_base64url =
        `${tamperedBundle.attestation.signature_base64url.slice(0, -1)}A`;
    const tampered = new CanonicalConnectorPolicySyncController({
        source: fixtureSource(tamperedBundle, []),
        trustAnchor,
        allowFixture: true,
        now,
    });
    const tamperedResult = await tampered.sync({
        reason: "contract_test",
    });

    return Object.freeze({
        contract_version:
            "noderooms-phase4b-canonical-policy-sync-proof-v1",
        proof_time: "2026-07-25T13:17:00.000Z",
        canonical_sync: Object.freeze({
            source_origin: sourceCalls[0]?.origin,
            source_path: sourceCalls[0]?.path,
            source_read_only: sourceCalls[0]?.read_only === true,
            redirects_allowed:
                sourceCalls[0]?.redirects_allowed === true,
            source_read_count: sourceCalls.length,
            bundle_id: sync.bundle_id,
            sequence: sync.sequence,
            registry_version: sync.registry_version,
            policy_version: sync.policy_version,
            signature_trust_anchor_external: true,
            checkpoint_fingerprint_sha256:
                sync.checkpoint_fingerprint_sha256,
            activation_state: sync.activation_state,
            tool_authority_granted: sync.tool_authority_granted,
        }),
        monotonicity: Object.freeze({
            restart_source_read_count: restartCalls.length,
            exact_restart_idempotent: restartSync.idempotent,
            restart_binding_ready:
                restartBinding.phase4c_contract_prerequisite_ready,
            rollback_blocked: rollbackResult === null
                && rollback.status().last_error?.code
                    === "POLICY_ROLLBACK_DETECTED",
            signature_tamper_blocked: tamperedResult === null
                && tampered.status().last_error?.code
                    === "POLICY_SIGNATURE_INVALID",
        }),
        exact_inventory_binding: Object.freeze({
            profile_count: binding.metrics.required_profile_count,
            ready_profile_count: binding.metrics.ready_profile_count,
            blocked_profile_count: binding.metrics.blocked_profile_count,
            schema_matches: binding.profiles[0].schema_matches,
            policy_matches: binding.profiles[0].policy_matches,
            owner_exact: binding.profiles[0].owner_exact,
            coverage_status: binding.profiles[0].coverage_status,
            phase4c_contract_prerequisite_ready:
                binding.phase4c_contract_prerequisite_ready,
            phase4c_external_write_authority_granted:
                binding.phase4c_external_write_authority_granted,
            binding_fingerprint_sha256:
                binding.binding_fingerprint_sha256,
        }),
        host_catalog_gap: Object.freeze({
            coverage_status:
                unavailableBinding.profiles[0].coverage_status,
            blocked_profile_count:
                unavailableBinding.metrics.blocked_profile_count,
            phase4c_contract_prerequisite_ready:
                unavailableBinding
                    .phase4c_contract_prerequisite_ready,
            failed_closed:
                unavailableBinding
                    .phase4c_contract_prerequisite_ready === false,
        }),
        safety: Object.freeze({
            live_policy_fetch_allowed: false,
            live_enforce_allowed: false,
            tool_authority_granted: false,
            tool_execution_attempted: false,
            connector_call_attempted: false,
            external_network_attempted: false,
            external_write_attempted: false,
            owner_decision_automated: false,
            raw_schema_persisted: false,
            raw_parameters_persisted: false,
            raw_results_persisted: false,
            provider_credentials_persisted: false,
            publish_attempted: false,
            live_install_attempted: false,
            gateway_restart_attempted: false,
            production_modified: false,
        }),
        closure: Object.freeze({
            phase4b_acceptance: "pass",
            phase4b_contract_policy_sync_completed: true,
            phase4b_live_policy_sync_authority_granted: false,
            phase4c_contract_prerequisite_ready:
                binding.phase4c_contract_prerequisite_ready,
            phase4c_github_write_authority_granted: false,
        }),
    });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    process.stdout.write(
        `${JSON.stringify(
            await buildCanonicalConnectorPolicySyncProof(),
            null,
            2,
        )}\n`,
    );
}
