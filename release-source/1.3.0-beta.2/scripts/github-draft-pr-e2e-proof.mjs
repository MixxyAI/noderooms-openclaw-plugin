import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import {
    CanonicalConnectorPolicySyncController,
    createInMemoryCanonicalPolicyCheckpointStore,
} from "../src/canonical-connector-policy-sync.js";
import {
    createGitHubDraftPrE2EPlan,
    createGitHubDraftPrE2EReceiptSigner,
    GitHubDraftPrE2EController,
    GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID,
    GITHUB_DRAFT_PR_E2E_MCP_RAW_SCHEMA_FINGERPRINT,
    GITHUB_DRAFT_PR_E2E_MCP_RAW_TOOL_NAME,
    GITHUB_DRAFT_PR_E2E_MCP_SERVER_NAME,
    GITHUB_DRAFT_PR_E2E_TOOL_NAME,
    GITHUB_DRAFT_PR_E2E_TRANSPORT_ADAPTER,
} from "../src/github-draft-pr-e2e.js";
import {
    sha256Fingerprint,
} from "../src/passport-runtime-binding.js";
import {
    buildRuntimeToolInventoryV1,
} from "../src/universal-connector-engine.js";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const NOW = new Date("2026-07-25T14:01:00.000Z");
const BASE_SHA = "1".repeat(40);
const HEAD_SHA = "2".repeat(40);
const PROOF_REPOSITORY = "MixxyAI/noderooms-docs";
const PROOF_HEAD = "noderooms/phase4c-contract-fixture";
const PROOF_PATH = "proofs/noderooms-phase4c-draft-pr-proof.md";

function clone(value) {
    return structuredClone(value);
}

function providerObject() {
    return {
        type: "pull_request",
        repository_full_name: PROOF_REPOSITORY,
        number: 4,
        url: `https://github.com/${PROOF_REPOSITORY}/pull/4`,
        state: "open",
        draft: true,
        base_ref: "main",
        base_sha: BASE_SHA,
        head_ref: PROOF_HEAD,
        head_sha: HEAD_SHA,
    };
}

function proofInput({
    binding,
    bundle,
    checkpoint,
    inventory,
    nonce,
    receiptSigner,
}) {
    const runtimeCatalogFingerprint =
        inventory.snapshot_fingerprint_sha256;
    const payload = {
        repository_full_name: PROOF_REPOSITORY,
        head_ref: PROOF_HEAD,
        base_ref: "main",
        title: "Phase 4C isolated Draft PR contract proof",
        body: "This payload is never sent by the contract proof.",
        draft: true,
    };
    return {
        nonce,
        agent_binding: {
            noderooms_agent_id: 42,
            passport_id: "NRP-000042-AGENT",
            agent_slug: "agent-contract-fixture",
        },
        owner_binding: {
            binding_kind: "noderooms_provider_binding",
            active_binding_id: 77,
            provider: "github",
            provider_login: "FixtureOwner",
            connection_id: "nrgh_inst_0123456789abcdef",
            github_installation_id: 123456789,
            verified_human_owner: true,
        },
        runtime_binding: {
            platform: "openclaw",
            openclaw_version: "2026.7.1-2",
            openclaw_agent_id: "agent-contract-fixture",
            session_key_fingerprint_sha256:
                sha256Fingerprint("fixture-session"),
            gateway_instance_fingerprint_sha256:
                sha256Fingerprint("fixture-gateway"),
            runtime_catalog_fingerprint_sha256:
                runtimeCatalogFingerprint,
        },
        connector_binding: {
            provider: "github",
            owner_kind: binding.profiles[0].owner_kind ?? "mcp",
            owner_id: binding.profiles[0].owner_id ?? "github",
            owner_resolution: "exact",
            tool_name: binding.profiles[0].tool_name,
            tool_schema_fingerprint:
                bundle.registry.profiles[0].tool_schema_fingerprint,
            effective_catalog_fingerprint_sha256:
                runtimeCatalogFingerprint,
        },
        transport_binding: {
            platform: "openclaw",
            transport: "mcp_stdio",
            server_name: GITHUB_DRAFT_PR_E2E_MCP_SERVER_NAME,
            exact_tool_id: GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID,
            raw_tool_name: GITHUB_DRAFT_PR_E2E_MCP_RAW_TOOL_NAME,
            raw_input_schema_fingerprint:
                GITHUB_DRAFT_PR_E2E_MCP_RAW_SCHEMA_FINGERPRINT,
            adapter_contract: GITHUB_DRAFT_PR_E2E_TRANSPORT_ADAPTER,
            reviewers_allowed: false,
            maintainer_can_modify: false,
        },
        phase4b_prerequisite: {
            bundle_id: bundle.bundle_id,
            bundle_fingerprint_sha256:
                bundle.bundle_fingerprint_sha256,
            checkpoint_fingerprint_sha256:
                checkpoint.checkpoint_fingerprint_sha256,
            registry_version:
                binding.policy_bundle_binding.registry_version,
            policy_version:
                binding.policy_bundle_binding.policy_version,
            registry_fingerprint_sha256:
                binding.policy_bundle_binding
                    .registry_fingerprint_sha256,
            inventory_snapshot_fingerprint_sha256:
                binding.inventory_binding
                    .snapshot_fingerprint_sha256,
            inventory_binding_fingerprint_sha256:
                binding.binding_fingerprint_sha256,
            profile_id: binding.profiles[0].profile_id,
            scope: binding.profiles[0].scope,
            tool_name: binding.profiles[0].tool_name,
            owner_kind: "mcp",
            owner_id: "github",
            tool_schema_fingerprint:
                bundle.registry.profiles[0].tool_schema_fingerprint,
            owner_exact: binding.profiles[0].owner_exact,
            schema_matches: binding.profiles[0].schema_matches,
            policy_matches: binding.profiles[0].policy_matches,
            phase4c_contract_prerequisite_ready:
                binding.phase4c_contract_prerequisite_ready,
            phase4c_external_write_authority_granted:
                binding.phase4c_external_write_authority_granted,
        },
        receipt_trust_anchor: clone(receiptSigner.trust_anchor),
        target: {
            repository_full_name: PROOF_REPOSITORY,
            base_ref: "main",
            base_sha: BASE_SHA,
            head_ref: PROOF_HEAD,
            head_sha: HEAD_SHA,
            changed_paths: [PROOF_PATH],
        },
        payload,
        owner_approval: {
            kind: "verified_human_owner",
            decision: "approved_once",
            decision_automated: false,
            evidence_source: "interactive_user_message",
            evidence_fingerprint_sha256:
                sha256Fingerprint("fixture-owner-approved-once"),
            approved_at: "2026-07-25T14:00:00.000Z",
            expires_at: "2026-07-25T14:10:00.000Z",
        },
        created_at: "2026-07-25T14:00:30.000Z",
        expires_at: "2026-07-25T14:09:00.000Z",
    };
}

async function controllerFor(prerequisite, nonce) {
    const receiptSigner = createGitHubDraftPrE2EReceiptSigner();
    const input = proofInput({
        ...prerequisite,
        nonce,
        receiptSigner,
    });
    const plan = createGitHubDraftPrE2EPlan(input, { now: NOW });
    const controller = new GitHubDraftPrE2EController({
        plan,
        receiptSigner,
        now: () => NOW,
    });
    await controller.arm();
    return {
        controller,
        input,
        plan,
        receiptSigner,
    };
}

async function exactPhase4BPrerequisite() {
    const [trustAnchor, bundle, descriptor] = await Promise.all([
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
            + "github-draft-pr.runtime-tool-descriptor-v1.json",
        ),
    ]);
    const policy = new CanonicalConnectorPolicySyncController({
        source: {
            async read() {
                return clone(bundle);
            },
        },
        checkpointStore:
            createInMemoryCanonicalPolicyCheckpointStore(),
        trustAnchor,
        allowFixture: true,
        now: () => new Date("2026-07-25T13:15:00.000Z"),
    });
    const checkpoint = await policy.sync({
        reason: "before_phase4c_contract_proof",
    });
    const inventory = buildRuntimeToolInventoryV1({
        captured_at: descriptor.captured_at,
        refresh_reason: descriptor.refresh_reason,
        inventory_generation: descriptor.inventory_generation,
        source: descriptor.source,
        tools: descriptor.tools,
        registry: policy.verifiedRegistry(),
    });
    const binding = policy.bindInventory(inventory);
    return {
        binding,
        bundle,
        checkpoint,
        inventory,
    };
}

export async function buildGitHubDraftPrE2EContractProof() {
    const prerequisite = await exactPhase4BPrerequisite();

    const success = await controllerFor(
        prerequisite,
        "1".repeat(64),
    );
    const successGate = await success.controller.beforeToolCall({
        tool_name: GITHUB_DRAFT_PR_E2E_TOOL_NAME,
        tool_call_id: "tool-call-contract-success",
        params: clone(success.input.payload),
    }, clone(success.input.runtime_binding));
    const successReceipt = await success.controller.afterToolCall({
        tool_name: GITHUB_DRAFT_PR_E2E_TOOL_NAME,
        provider_tool_id: GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID,
        tool_call_id: "tool-call-contract-success",
        outcome: {
            ok: true,
            certainty: "known",
            provider_object: providerObject(),
            reason_code: null,
        },
    });
    const replay = await success.controller.evaluateBeforeToolCall({
        tool_name: GITHUB_DRAFT_PR_E2E_TOOL_NAME,
        tool_call_id: "tool-call-contract-replay",
        params: clone(success.input.payload),
    }, clone(success.input.runtime_binding));

    const unknown = await controllerFor(
        prerequisite,
        "2".repeat(64),
    );
    await unknown.controller.beforeToolCall({
        tool_name: GITHUB_DRAFT_PR_E2E_TOOL_NAME,
        tool_call_id: "tool-call-contract-unknown",
        params: clone(unknown.input.payload),
    }, clone(unknown.input.runtime_binding));
    const unknownReceipt = await unknown.controller.afterToolCall({
        tool_name: GITHUB_DRAFT_PR_E2E_TOOL_NAME,
        provider_tool_id: GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID,
        tool_call_id: "tool-call-contract-unknown",
        outcome: {
            ok: false,
            certainty: "unknown",
            provider_object: null,
            reason_code: "TRANSPORT_AMBIGUOUS",
        },
    });
    const reconciledReceipt =
        await unknown.controller.reconcileReadOnly({
            provider_write_attempted: false,
            matching_pull_requests: [providerObject()],
        });

    const revoked = await controllerFor(
        prerequisite,
        "3".repeat(64),
    );
    await revoked.controller.revoke("OWNER_REVOKED");
    const revokedGate = await revoked.controller.evaluateBeforeToolCall({
        tool_name: GITHUB_DRAFT_PR_E2E_TOOL_NAME,
        tool_call_id: "tool-call-contract-revoked",
        params: clone(revoked.input.payload),
    }, clone(revoked.input.runtime_binding));

    const concurrent = await controllerFor(
        prerequisite,
        "4".repeat(64),
    );
    const concurrentResults = await Promise.allSettled([
        concurrent.controller.beforeToolCall({
            tool_name: GITHUB_DRAFT_PR_E2E_TOOL_NAME,
            tool_call_id: "tool-call-contract-concurrent-a",
            params: clone(concurrent.input.payload),
        }, clone(concurrent.input.runtime_binding)),
        concurrent.controller.beforeToolCall({
            tool_name: GITHUB_DRAFT_PR_E2E_TOOL_NAME,
            tool_call_id: "tool-call-contract-concurrent-b",
            params: clone(concurrent.input.payload),
        }, clone(concurrent.input.runtime_binding)),
    ]);

    return Object.freeze({
        contract_version:
            "noderooms-phase4c-github-draft-pr-e2e-contract-proof-v1",
        proof_time: "2026-07-25T14:01:00.000Z",
        proof_mode: "isolated_contract_simulation_no_provider",
        phase4b_prerequisite: Object.freeze({
            bundle_id: prerequisite.bundle.bundle_id,
            inventory_binding_fingerprint_sha256:
                prerequisite.binding.binding_fingerprint_sha256,
            owner_exact:
                prerequisite.binding.profiles[0].owner_exact,
            schema_matches:
                prerequisite.binding.profiles[0].schema_matches,
            policy_matches:
                prerequisite.binding.profiles[0].policy_matches,
            contract_prerequisite_ready:
                prerequisite.binding
                    .phase4c_contract_prerequisite_ready,
            preexisting_external_write_authority:
                prerequisite.binding
                    .phase4c_external_write_authority_granted,
        }),
        success_path: Object.freeze({
            allow_once: successGate.allow_once,
            approval_consumed: successGate.approval_consumed,
            provider_tool_id: successGate.provider_tool_id,
            provider_raw_tool_name:
                successGate.provider_raw_tool_name,
            raw_input_schema_fingerprint:
                success.plan.transport_binding
                    .raw_input_schema_fingerprint,
            transport_adapter:
                success.plan.transport_binding.adapter_contract,
            provider_attempt_count:
                successReceipt.dispatch.provider_attempt_count,
            outcome: successReceipt.outcome.status,
            exact_draft_pr_observed:
                successReceipt.outcome.provider_object.draft === true,
            trusted_receipt_verified: true,
            receipt_fingerprint_sha256:
                successReceipt.receipt_fingerprint_sha256,
        }),
        replay: Object.freeze({
            blocked: replay.block === true,
            reason_code: replay.reason_code,
            provider_attempt_count:
                (await success.controller.status())
                    .provider_attempt_count,
        }),
        concurrency: Object.freeze({
            allowed_count: concurrentResults.filter(
                (result) => result.status === "fulfilled",
            ).length,
            blocked_count: concurrentResults.filter(
                (result) => result.status === "rejected",
            ).length,
            provider_attempt_count:
                (await concurrent.controller.status())
                    .provider_attempt_count,
        }),
        unknown_outcome: Object.freeze({
            initial_status: unknownReceipt.outcome.status,
            retry_allowed: false,
            reconciliation_mode:
                reconciledReceipt.reconciliation.mode,
            reconciliation_provider_write_attempted:
                reconciledReceipt.reconciliation
                    .provider_write_attempted,
            reconciled_status: reconciledReceipt.outcome.status,
            total_provider_attempt_count:
                reconciledReceipt.dispatch.provider_attempt_count,
        }),
        revocation: Object.freeze({
            blocked: revokedGate.block === true,
            reason_code: revokedGate.reason_code,
            provider_attempt_count:
                (await revoked.controller.status())
                    .provider_attempt_count,
        }),
        safety: Object.freeze({
            live_plugin_armed: false,
            openclaw_tool_invoked: false,
            connector_call_attempted: false,
            provider_network_attempted: false,
            external_write_attempted: false,
            raw_payload_persisted: false,
            provider_credentials_persisted: false,
            automatic_owner_decision: false,
            automatic_write_retry_attempted: false,
            direct_main_push_attempted: false,
            non_draft_pull_request_attempted: false,
            workflow_edit_attempted: false,
            merge_attempted: false,
            publish_attempted: false,
            live_install_attempted: false,
            gateway_restart_attempted: false,
            production_modified: false,
        }),
        closure: Object.freeze({
            contract_controller_ready: true,
            live_host_preflight_required: true,
            phase4c_external_write_proof_completed: false,
        }),
    });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    process.stdout.write(
        `${JSON.stringify(
            await buildGitHubDraftPrE2EContractProof(),
            null,
            2,
        )}\n`,
    );
}
