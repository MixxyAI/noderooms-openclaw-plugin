import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
    createFileGitHubDraftPrProofStore,
    createGitHubDraftPrE2EPlan,
    createGitHubDraftPrE2EReceiptSigner,
    createInMemoryGitHubDraftPrProofStore,
    GITHUB_DRAFT_PR_E2E_CANONICAL_SCHEMA_FINGERPRINT,
    GITHUB_DRAFT_PR_E2E_DISPATCH_RESERVATION_CONTRACT_VERSION,
    GITHUB_DRAFT_PR_E2E_LIVE_PLUGIN_ARMED,
    GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID,
    GITHUB_DRAFT_PR_E2E_MCP_RAW_SCHEMA_FINGERPRINT,
    GITHUB_DRAFT_PR_E2E_MCP_RAW_TOOL_NAME,
    GITHUB_DRAFT_PR_E2E_MCP_SERVER_NAME,
    GITHUB_DRAFT_PR_E2E_OWNER_ID,
    GITHUB_DRAFT_PR_E2E_PROFILE_ID,
    GITHUB_DRAFT_PR_E2E_SCOPE,
    GITHUB_DRAFT_PR_E2E_TOOL_NAME,
    GITHUB_DRAFT_PR_E2E_TRANSPORT_ADAPTER,
    GitHubDraftPrE2EController,
    GitHubDraftPrE2EError,
    githubMcpCreatePullRequestParams,
    githubMcpCreatePullRequestParamsFingerprint,
    githubDraftPrPayloadFingerprint,
    githubDraftPrPayloadProjection,
    validateGitHubDraftPrE2EPlan,
    validateGitHubDraftPrE2EReceipt,
} from "../src/github-draft-pr-e2e.js";
import {
    buildGitHubDraftPrE2EContractProof,
} from "../scripts/github-draft-pr-e2e-proof.mjs";

const NOW = new Date("2026-07-25T14:01:00.000Z");
const BASE_SHA = "1".repeat(40);
const HEAD_SHA = "2".repeat(40);
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const HASH_D = `sha256:${"d".repeat(64)}`;
const HASH_E = `sha256:${"e".repeat(64)}`;
const HASH_F = `sha256:${"f".repeat(64)}`;
const TOOL_SCHEMA_FINGERPRINT =
    "sha256:c12e12e4f6a0d03d85c46dbe4e17cfe814f7a988f56ecc4c2b40089d621f8c37";

function clone(value) {
    return structuredClone(value);
}

function planInput(receiptSigner) {
    return {
        nonce: "9".repeat(64),
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
            session_key_fingerprint_sha256: HASH_A,
            gateway_instance_fingerprint_sha256: HASH_B,
            runtime_catalog_fingerprint_sha256: HASH_C,
        },
        connector_binding: {
            provider: "github",
            owner_kind: "mcp",
            owner_id: "github",
            owner_resolution: "exact",
            tool_name: GITHUB_DRAFT_PR_E2E_TOOL_NAME,
            tool_schema_fingerprint: TOOL_SCHEMA_FINGERPRINT,
            effective_catalog_fingerprint_sha256: HASH_C,
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
            bundle_id: "nrpolicy_d79e47a0fc8b4cd8a7d3014348f2afbf",
            bundle_fingerprint_sha256: HASH_D,
            checkpoint_fingerprint_sha256: HASH_E,
            registry_version: "nrcr_2026-07-23.001",
            policy_version: "nrp_2026-07-23.001",
            registry_fingerprint_sha256: HASH_F,
            inventory_snapshot_fingerprint_sha256: HASH_C,
            inventory_binding_fingerprint_sha256: HASH_B,
            profile_id: GITHUB_DRAFT_PR_E2E_PROFILE_ID,
            scope: GITHUB_DRAFT_PR_E2E_SCOPE,
            tool_name: GITHUB_DRAFT_PR_E2E_TOOL_NAME,
            owner_kind: "mcp",
            owner_id: "github",
            tool_schema_fingerprint: TOOL_SCHEMA_FINGERPRINT,
            owner_exact: true,
            schema_matches: true,
            policy_matches: true,
            phase4c_contract_prerequisite_ready: true,
            phase4c_external_write_authority_granted: false,
        },
        receipt_trust_anchor: clone(receiptSigner.trust_anchor),
        target: {
            repository_full_name: "MixxyAI/noderooms-docs",
            base_ref: "main",
            base_sha: BASE_SHA,
            head_ref: "noderooms/phase4c-contract-fixture",
            head_sha: HEAD_SHA,
            changed_paths: [
                "proofs/noderooms-phase4c-draft-pr-proof.md",
            ],
        },
        payload: {
            repository_full_name: "MixxyAI/noderooms-docs",
            head_ref: "noderooms/phase4c-contract-fixture",
            base_ref: "main",
            title: "Phase 4C isolated Draft PR proof",
            body: "Contract fixture only.",
            draft: true,
        },
        owner_approval: {
            kind: "verified_human_owner",
            decision: "approved_once",
            decision_automated: false,
            evidence_source: "interactive_user_message",
            evidence_fingerprint_sha256: HASH_D,
            approved_at: "2026-07-25T14:00:00.000Z",
            expires_at: "2026-07-25T14:10:00.000Z",
        },
        created_at: "2026-07-25T14:00:30.000Z",
        expires_at: "2026-07-25T14:09:00.000Z",
    };
}

function fixture(options = {}) {
    const receiptSigner =
        options.receiptSigner ?? createGitHubDraftPrE2EReceiptSigner();
    const input = planInput(receiptSigner);
    options.mutate?.(input);
    const plan = createGitHubDraftPrE2EPlan(input, { now: NOW });
    const store = options.store
        ?? createInMemoryGitHubDraftPrProofStore();
    const now = options.now ?? (() => NOW);
    const controller = new GitHubDraftPrE2EController({
        plan,
        receiptSigner,
        store,
        now,
    });
    return {
        controller,
        input,
        now,
        payload: clone(input.payload),
        plan,
        receiptSigner,
        runtime: clone(input.runtime_binding),
        store,
    };
}

function beforeEvent(payload, toolCallId = "tool-call-004c") {
    return {
        tool_name: GITHUB_DRAFT_PR_E2E_TOOL_NAME,
        tool_call_id: toolCallId,
        params: clone(payload),
    };
}

function afterEvent(outcome, toolCallId = "tool-call-004c") {
    return {
        tool_name: GITHUB_DRAFT_PR_E2E_TOOL_NAME,
        provider_tool_id: GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID,
        tool_call_id: toolCallId,
        outcome,
    };
}

function providerObject() {
    return {
        type: "pull_request",
        repository_full_name: "MixxyAI/noderooms-docs",
        number: 4,
        url: "https://github.com/MixxyAI/noderooms-docs/pull/4",
        state: "open",
        draft: true,
        base_ref: "main",
        base_sha: BASE_SHA,
        head_ref: "noderooms/phase4c-contract-fixture",
        head_sha: HEAD_SHA,
    };
}

function successOutcome() {
    return {
        ok: true,
        certainty: "known",
        provider_object: providerObject(),
        reason_code: null,
    };
}

async function expectReject(code, operation) {
    await assert.rejects(
        operation,
        (error) =>
            error instanceof GitHubDraftPrE2EError
            && error.code === code,
    );
}

test("004C stays isolated and binds one exact GitHub Draft PR profile", () => {
    const { plan } = fixture();
    assert.equal(GITHUB_DRAFT_PR_E2E_LIVE_PLUGIN_ARMED, false);
    assert.equal(plan.live_plugin_armed, false);
    assert.equal(plan.proof_mode, "isolated_owner_approved_once");
    assert.equal(plan.connector_binding.owner_kind, "mcp");
    assert.equal(plan.connector_binding.owner_id, "github");
    assert.equal(plan.connector_binding.owner_resolution, "exact");
    assert.equal(
        plan.transport_binding.exact_tool_id,
        GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID,
    );
    assert.equal(
        plan.transport_binding.raw_input_schema_fingerprint,
        GITHUB_DRAFT_PR_E2E_MCP_RAW_SCHEMA_FINGERPRINT,
    );
    assert.equal(plan.lease.approval_policy, "allow_once");
    assert.equal(plan.lease.max_actions, 1);
    assert.equal(plan.intent.max_provider_attempts, 1);
    assert.equal(plan.intent.exactly_once_effect_claimed, false);
});

test("004C schemas freeze exact trust and one-use boundaries", async () => {
    const [planSchema, receiptSchema, reservationSchema] = await Promise.all([
        readFile(
            new URL(
                "../contracts/github-draft-pr-e2e-v1.schema.json",
                import.meta.url,
            ),
            "utf8",
        ).then(JSON.parse),
        readFile(
            new URL(
                "../contracts/github-draft-pr-e2e-receipt-v1.schema.json",
                import.meta.url,
            ),
            "utf8",
        ).then(JSON.parse),
        readFile(
            new URL(
                "../contracts/"
                + "github-draft-pr-dispatch-reservation-v1.schema.json",
                import.meta.url,
            ),
            "utf8",
        ).then(JSON.parse),
    ]);
    assert.equal(
        planSchema.properties.live_plugin_armed.const,
        false,
    );
    assert.equal(
        planSchema.properties.lease.properties.approval_policy.const,
        "allow_once",
    );
    assert.equal(
        planSchema.properties.lease.properties.max_actions.const,
        1,
    );
    assert.equal(
        planSchema.properties.payload_binding.properties
            .payload_projection.properties.draft.const,
        true,
    );
    assert.equal(
        planSchema.properties.boundaries.properties
            .automatic_write_retry_allowed.const,
        false,
    );
    assert.equal(
        receiptSchema.properties.dispatch.properties
            .provider_attempt_count.const,
        1,
    );
    assert.equal(
        receiptSchema.properties.dispatch.properties
            .exactly_once_effect_claimed.const,
        false,
    );
    assert.equal(
        planSchema.properties.transport_binding.properties
            .exact_tool_id.const,
        GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID,
    );
    assert.equal(
        receiptSchema.properties.dispatch.properties
            .raw_input_schema_fingerprint.const,
        GITHUB_DRAFT_PR_E2E_MCP_RAW_SCHEMA_FINGERPRINT,
    );
    assert.equal(
        planSchema.properties.connector_binding.properties.owner_id.const,
        GITHUB_DRAFT_PR_E2E_OWNER_ID,
    );
    assert.equal(
        planSchema.properties.connector_binding.properties
            .tool_schema_fingerprint.const,
        GITHUB_DRAFT_PR_E2E_CANONICAL_SCHEMA_FINGERPRINT,
    );
    assert.equal(
        reservationSchema.properties.contract_version.const,
        GITHUB_DRAFT_PR_E2E_DISPATCH_RESERVATION_CONTRACT_VERSION,
    );
    assert.equal(
        reservationSchema.properties.provider_attempt_count.const,
        1,
    );
    assert.equal(
        reservationSchema.properties.approval_consumed.const,
        true,
    );
});

test("canonical payload maps to one exact GitHub MCP transport payload", () => {
    const { payload } = fixture();
    const params = githubMcpCreatePullRequestParams(payload);
    assert.deepEqual(params, {
        owner: "MixxyAI",
        repo: "noderooms-docs",
        title: payload.title,
        head: payload.head_ref,
        base: payload.base_ref,
        body: payload.body,
        draft: true,
        maintainer_can_modify: false,
    });
    assert.equal("reviewers" in params, false);
    assert.match(
        githubMcpCreatePullRequestParamsFingerprint(payload),
        /^sha256:[a-f0-9]{64}$/,
    );
});

test("raw MCP transport drift fails before the plan can arm", () => {
    const signer = createGitHubDraftPrE2EReceiptSigner();
    const input = planInput(signer);
    input.transport_binding.raw_input_schema_fingerprint = HASH_F;
    assert.throws(
        () => createGitHubDraftPrE2EPlan(input, { now: NOW }),
        (error) =>
            error instanceof GitHubDraftPrE2EError
            && error.code === "TRANSPORT_BINDING_MISMATCH",
    );
});

test("payload projection stores fingerprints instead of title and body", () => {
    const { payload } = fixture();
    const projection = githubDraftPrPayloadProjection(payload);
    assert.equal(projection.repository_full_name, payload.repository_full_name);
    assert.equal(projection.draft, true);
    assert.equal("title" in projection, false);
    assert.equal("body" in projection, false);
    assert.match(projection.title_sha256, /^sha256:[a-f0-9]{64}$/);
    assert.match(projection.body_sha256, /^sha256:[a-f0-9]{64}$/);
    const changed = clone(payload);
    changed.title = `${changed.title} changed`;
    assert.notEqual(
        githubDraftPrPayloadFingerprint(changed),
        githubDraftPrPayloadFingerprint(payload),
    );
});

test("non-draft, main-head, and extra tool parameters fail closed", () => {
    const signer = createGitHubDraftPrE2EReceiptSigner();
    for (const mutate of [
        (input) => {
            input.payload.draft = false;
        },
        (input) => {
            input.target.head_ref = "main";
            input.payload.head_ref = "main";
        },
        (input) => {
            input.payload.unknown = true;
        },
    ]) {
        const input = planInput(signer);
        mutate(input);
        assert.throws(
            () => createGitHubDraftPrE2EPlan(input, { now: NOW }),
            GitHubDraftPrE2EError,
        );
    }
});

test("workflow, credential, traversal, and wildcard-like paths are prohibited", () => {
    const signer = createGitHubDraftPrE2EReceiptSigner();
    for (const changedPath of [
        ".github/workflows/proof.yml",
        "config/credentials.json",
        "../outside.md",
        "keys/provider.pem",
    ]) {
        const input = planInput(signer);
        input.target.changed_paths = [changedPath];
        assert.throws(
            () => createGitHubDraftPrE2EPlan(input, { now: NOW }),
            (error) =>
                error instanceof GitHubDraftPrE2EError
                && error.code === "CHANGED_PATH_FORBIDDEN",
        );
    }
});

test("Owner approval must be human, explicit, narrow, current, and one-use", () => {
    const signer = createGitHubDraftPrE2EReceiptSigner();
    const automated = planInput(signer);
    automated.owner_approval.decision_automated = true;
    assert.throws(
        () => createGitHubDraftPrE2EPlan(automated, { now: NOW }),
        (error) =>
            error instanceof GitHubDraftPrE2EError
            && error.code === "BOOLEAN_INVALID",
    );
    const broad = planInput(signer);
    broad.owner_approval.expires_at = "2026-07-25T14:30:00.000Z";
    assert.throws(
        () => createGitHubDraftPrE2EPlan(broad, { now: NOW }),
        (error) =>
            error instanceof GitHubDraftPrE2EError
            && error.code === "OWNER_APPROVAL_EXPIRED",
    );
    const expired = planInput(signer);
    expired.owner_approval.expires_at = "2026-07-25T14:00:30.000Z";
    assert.throws(
        () => createGitHubDraftPrE2EPlan(expired, { now: NOW }),
        GitHubDraftPrE2EError,
    );
});

test("004B must be ready while still granting zero external-write authority", () => {
    const signer = createGitHubDraftPrE2EReceiptSigner();
    const notReady = planInput(signer);
    notReady.phase4b_prerequisite.phase4c_contract_prerequisite_ready = false;
    assert.throws(
        () => createGitHubDraftPrE2EPlan(notReady, { now: NOW }),
        GitHubDraftPrE2EError,
    );
    const preGranted = planInput(signer);
    preGranted.phase4b_prerequisite
        .phase4c_external_write_authority_granted = true;
    assert.throws(
        () => createGitHubDraftPrE2EPlan(preGranted, { now: NOW }),
        GitHubDraftPrE2EError,
    );
});

test("owner, schema, profile, and policy drift fail closed", () => {
    const signer = createGitHubDraftPrE2EReceiptSigner();
    for (const mutate of [
        (input) => {
            input.phase4b_prerequisite.owner_id = "another-github";
        },
        (input) => {
            input.phase4b_prerequisite.tool_schema_fingerprint = HASH_E;
        },
        (input) => {
            input.phase4b_prerequisite.profile_id = "nrscp_other_v1";
        },
        (input) => {
            input.phase4b_prerequisite.policy_matches = false;
        },
    ]) {
        const input = planInput(signer);
        mutate(input);
        assert.throws(
            () => createGitHubDraftPrE2EPlan(input, { now: NOW }),
            GitHubDraftPrE2EError,
        );
    }
});

test("coordinated owner and canonical-schema drift fail closed", () => {
    const signer = createGitHubDraftPrE2EReceiptSigner();
    for (const [expectedCode, mutate] of [
        [
            "CONNECTOR_OWNER_INVALID",
            (input) => {
                input.connector_binding.owner_id = "another-github";
                input.phase4b_prerequisite.owner_id = "another-github";
            },
        ],
        [
            "TOOL_SCHEMA_MISMATCH",
            (input) => {
                input.connector_binding.tool_schema_fingerprint = HASH_E;
                input.phase4b_prerequisite.tool_schema_fingerprint = HASH_E;
            },
        ],
    ]) {
        const input = planInput(signer);
        mutate(input);
        assert.throws(
            () => createGitHubDraftPrE2EPlan(input, { now: NOW }),
            (error) =>
                error instanceof GitHubDraftPrE2EError
                && error.code === expectedCode,
        );
    }
});

test("runtime, connector, and 004B inventory catalogs form one chain", () => {
    const signer = createGitHubDraftPrE2EReceiptSigner();
    for (const mutate of [
        (input) => {
            input.runtime_binding.runtime_catalog_fingerprint_sha256 =
                HASH_D;
        },
        (input) => {
            input.connector_binding
                .effective_catalog_fingerprint_sha256 = HASH_D;
        },
        (input) => {
            input.phase4b_prerequisite
                .inventory_snapshot_fingerprint_sha256 = HASH_D;
        },
    ]) {
        const input = planInput(signer);
        mutate(input);
        assert.throws(
            () => createGitHubDraftPrE2EPlan(input, { now: NOW }),
            (error) =>
                error instanceof GitHubDraftPrE2EError
                && error.code === "CATALOG_BINDING_MISMATCH",
        );
    }
});

test("receipt signer is mandatory and bound into the approved plan", () => {
    const first = createGitHubDraftPrE2EReceiptSigner();
    const second = createGitHubDraftPrE2EReceiptSigner();
    const plan = createGitHubDraftPrE2EPlan(planInput(first), { now: NOW });
    assert.throws(
        () => new GitHubDraftPrE2EController({
            plan,
            now: () => NOW,
        }),
        (error) =>
            error instanceof GitHubDraftPrE2EError
            && error.code === "RECEIPT_SIGNER_REQUIRED",
    );
    assert.throws(
        () => new GitHubDraftPrE2EController({
            plan,
            receiptSigner: second,
            now: () => NOW,
        }),
        (error) =>
            error instanceof GitHubDraftPrE2EError
            && error.code === "RECEIPT_TRUST_ANCHOR_MISMATCH",
    );
});

test("arming is idempotent only before dispatch", async () => {
    const { controller } = fixture();
    const first = await controller.arm();
    const second = await controller.arm();
    assert.equal(first.idempotent, false);
    assert.equal(second.idempotent, true);
    assert.equal(first.proof_id, second.proof_id);
});

test("one exact successful provider attempt creates one trusted receipt", async () => {
    const {
        controller,
        payload,
        plan,
        receiptSigner,
        runtime,
    } = fixture();
    await controller.arm();
    const gate = await controller.beforeToolCall(
        beforeEvent(payload),
        runtime,
    );
    assert.equal(gate.allow_once, true);
    assert.equal(gate.provider_attempt_count, 1);
    assert.equal(
        gate.provider_tool_id,
        GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID,
    );
    assert.equal(
        gate.provider_raw_tool_name,
        GITHUB_DRAFT_PR_E2E_MCP_RAW_TOOL_NAME,
    );
    assert.deepEqual(
        gate.provider_params,
        githubMcpCreatePullRequestParams(payload),
    );
    const receipt = await controller.afterToolCall(
        afterEvent(successOutcome()),
    );
    assert.equal(receipt.outcome.status, "committed");
    assert.equal(receipt.outcome.provider_object.number, 4);
    assert.equal(receipt.dispatch.provider_attempt_count, 1);
    assert.equal(
        receipt.dispatch.provider_tool_id,
        GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID,
    );
    assert.equal(receipt.dispatch.automatic_write_retry_attempted, false);
    assert.equal(receipt.approval_consumption.consumed, true);
    assert.equal(receipt.plan_fingerprint_sha256, plan.plan_fingerprint_sha256);
    assert.equal(
        receipt.attestation.key_thumbprint_sha256,
        receiptSigner.trust_anchor.key_thumbprint_sha256,
    );
    validateGitHubDraftPrE2EReceipt(receipt, {
        expectedTrustAnchor: receiptSigner.trust_anchor,
    });
});

test("replay after success is blocked without a second provider attempt", async () => {
    const { controller, payload, runtime } = fixture();
    await controller.arm();
    await controller.beforeToolCall(beforeEvent(payload), runtime);
    await controller.afterToolCall(afterEvent(successOutcome()));
    await expectReject(
        "REPLAY_BLOCKED",
        () => controller.beforeToolCall(
            beforeEvent(payload, "tool-call-replay"),
            runtime,
        ),
    );
    const status = await controller.status();
    assert.equal(status.provider_attempt_count, 1);
    assert.equal(status.lease_actions_remaining, 0);
});

test("concurrent dispatch permits exactly one winner", async () => {
    const { controller, payload, runtime } = fixture();
    await controller.arm();
    const results = await Promise.allSettled([
        controller.beforeToolCall(
            beforeEvent(payload, "tool-call-a"),
            runtime,
        ),
        controller.beforeToolCall(
            beforeEvent(payload, "tool-call-b"),
            runtime,
        ),
    ]);
    assert.equal(
        results.filter((result) => result.status === "fulfilled").length,
        1,
    );
    assert.equal(
        results.filter((result) => result.status === "rejected").length,
        1,
    );
    assert.equal((await controller.status()).provider_attempt_count, 1);
});

test("payload drift is blocked before approval consumption", async () => {
    const { controller, payload, runtime } = fixture();
    await controller.arm();
    payload.body = "Unreviewed body drift.";
    await expectReject(
        "PAYLOAD_FINGERPRINT_MISMATCH",
        () => controller.beforeToolCall(beforeEvent(payload), runtime),
    );
    const status = await controller.status();
    assert.equal(status.state, "armed");
    assert.equal(status.provider_attempt_count, 0);
    assert.equal(status.approval_consumed, false);
});

test("runtime drift is blocked before approval consumption", async () => {
    const { controller, payload, runtime } = fixture();
    await controller.arm();
    runtime.session_key_fingerprint_sha256 = HASH_F;
    await expectReject(
        "RUNTIME_BINDING_MISMATCH",
        () => controller.beforeToolCall(beforeEvent(payload), runtime),
    );
    assert.equal((await controller.status()).provider_attempt_count, 0);
});

test("Owner revocation is sticky, idempotent, and blocks dispatch", async () => {
    const { controller, payload, runtime } = fixture();
    await controller.arm();
    const first = await controller.revoke("OWNER_REVOKED");
    const second = await controller.revoke("OWNER_REVOKED");
    assert.equal(first.idempotent, false);
    assert.equal(second.idempotent, true);
    await expectReject(
        "LEASE_REVOKED",
        () => controller.beforeToolCall(beforeEvent(payload), runtime),
    );
    const status = await controller.status();
    assert.equal(status.revoked, true);
    assert.equal(status.provider_attempt_count, 0);
});

test("unknown provider outcome seals the write path and forbids retry", async () => {
    const { controller, payload, runtime } = fixture();
    await controller.arm();
    await controller.beforeToolCall(beforeEvent(payload), runtime);
    const receipt = await controller.afterToolCall(afterEvent({
            ok: false,
            certainty: "unknown",
            provider_object: null,
            reason_code: "PROVIDER_RESPONSE_LOST",
        }));
    assert.equal(receipt.outcome.status, "unknown");
    await expectReject(
        "REPLAY_BLOCKED",
        () => controller.beforeToolCall(
            beforeEvent(payload, "tool-call-retry"),
            runtime,
        ),
    );
});

test("unknown outcome may reconcile one exact Draft PR read-only", async () => {
    const { controller, payload, runtime } = fixture();
    await controller.arm();
    await controller.beforeToolCall(beforeEvent(payload), runtime);
    await controller.afterToolCall(afterEvent({
            ok: false,
            certainty: "unknown",
            provider_object: null,
            reason_code: "TRANSPORT_AMBIGUOUS",
        }));
    const receipt = await controller.reconcileReadOnly({
        provider_write_attempted: false,
        matching_pull_requests: [providerObject()],
    });
    assert.equal(receipt.outcome.status, "committed");
    assert.equal(receipt.reconciliation.attempted, true);
    assert.equal(receipt.reconciliation.provider_write_attempted, false);
    assert.equal(receipt.dispatch.provider_attempt_count, 1);
});

test("unknown outcome may reconcile to known no-effect without retry", async () => {
    const { controller, payload, runtime } = fixture();
    await controller.arm();
    await controller.beforeToolCall(beforeEvent(payload), runtime);
    await controller.afterToolCall(afterEvent({
            ok: false,
            certainty: "unknown",
            provider_object: null,
            reason_code: "TRANSPORT_AMBIGUOUS",
        }));
    const receipt = await controller.reconcileReadOnly({
        provider_write_attempted: false,
        matching_pull_requests: [],
    });
    assert.equal(receipt.outcome.status, "no_effect");
    assert.equal(
        receipt.outcome.reason_code,
        "READ_ONLY_RECONCILE_NO_EFFECT",
    );
    assert.equal(receipt.dispatch.provider_attempt_count, 1);
});

test("ambiguous or write-capable reconciliation is prohibited", async () => {
    const unknownFixture = async () => {
        const value = fixture();
        await value.controller.arm();
        await value.controller.beforeToolCall(
            beforeEvent(value.payload),
            value.runtime,
        );
        await value.controller.afterToolCall(afterEvent({
                ok: false,
                certainty: "unknown",
                provider_object: null,
                reason_code: "TRANSPORT_AMBIGUOUS",
            }));
        return value.controller;
    };
    const ambiguous = await unknownFixture();
    await expectReject(
        "RECONCILIATION_AMBIGUOUS",
        () => ambiguous.reconcileReadOnly({
            provider_write_attempted: false,
            matching_pull_requests: [providerObject(), providerObject()],
        }),
    );
    const writing = await unknownFixture();
    await expectReject(
        "BOOLEAN_INVALID",
        () => writing.reconcileReadOnly({
            provider_write_attempted: true,
            matching_pull_requests: [],
        }),
    );
});

test("provider response must match exact repository, draft, base, and head", async () => {
    const { controller, payload, runtime } = fixture();
    await controller.arm();
    await controller.beforeToolCall(beforeEvent(payload), runtime);
    const wrong = successOutcome();
    wrong.provider_object.draft = false;
    await expectReject(
        "PROVIDER_OBJECT_MISMATCH",
        () => controller.afterToolCall(afterEvent(wrong)),
    );
    const status = await controller.status();
    assert.equal(status.state, "dispatching");
    assert.equal(status.provider_attempt_count, 1);
});

test("file store survives restart and still blocks replay", async () => {
    const temporary = await mkdtemp(
        path.join(os.tmpdir(), "nr-004c-store-"),
    );
    try {
        const filePath = path.join(temporary, "nested", "proof.json");
        const receiptSigner = createGitHubDraftPrE2EReceiptSigner();
        const first = fixture({
            receiptSigner,
            store: createFileGitHubDraftPrProofStore(filePath),
        });
        await first.controller.arm();
        await first.controller.beforeToolCall(
            beforeEvent(first.payload),
            first.runtime,
        );
        await first.controller.afterToolCall(afterEvent(successOutcome()));
        const restarted = new GitHubDraftPrE2EController({
            plan: first.plan,
            receiptSigner,
            store: createFileGitHubDraftPrProofStore(filePath),
            now: () => NOW,
        });
        assert.equal((await restarted.status()).state, "committed");
        await expectReject(
            "REPLAY_BLOCKED",
            () => restarted.beforeToolCall(
                beforeEvent(first.payload, "tool-call-after-restart"),
                first.runtime,
            ),
        );
        const raw = await readFile(filePath, "utf8");
        assert.doesNotMatch(raw, /Phase 4C isolated Draft PR proof/);
        assert.doesNotMatch(raw, /Contract fixture only/);
    }
    finally {
        await rm(temporary, { recursive: true, force: true });
    }
});

test("durable reservation detects rollback to an older armed record", async () => {
    const temporary = await mkdtemp(
        path.join(os.tmpdir(), "nr-004c-rollback-"),
    );
    try {
        const filePath = path.join(temporary, "proof.json");
        const receiptSigner = createGitHubDraftPrE2EReceiptSigner();
        const first = fixture({
            receiptSigner,
            store: createFileGitHubDraftPrProofStore(filePath),
        });
        await first.controller.arm();
        const armedDocument = await readFile(filePath, "utf8");
        await first.controller.beforeToolCall(
            beforeEvent(first.payload),
            first.runtime,
        );
        const reservationDocument = JSON.parse(await readFile(
            `${filePath}.dispatch-reservation`,
            "utf8",
        ));
        assert.equal(
            reservationDocument.reservation.contract_version,
            GITHUB_DRAFT_PR_E2E_DISPATCH_RESERVATION_CONTRACT_VERSION,
        );
        assert.equal(
            reservationDocument.reservation.reservation_id,
            first.plan.intent.reservation_id,
        );

        await writeFile(filePath, armedDocument, "utf8");
        const restarted = new GitHubDraftPrE2EController({
            plan: first.plan,
            receiptSigner,
            store: createFileGitHubDraftPrProofStore(filePath),
            now: () => NOW,
        });
        await expectReject(
            "STORE_ROLLBACK_DETECTED",
            () => restarted.status(),
        );
        await expectReject(
            "STORE_ROLLBACK_DETECTED",
            () => restarted.beforeToolCall(
                beforeEvent(
                    first.payload,
                    "tool-call-after-record-rollback",
                ),
                first.runtime,
            ),
        );
    }
    finally {
        await rm(temporary, { recursive: true, force: true });
    }
});

test("consumed file state without its reservation marker fails closed", async () => {
    const temporary = await mkdtemp(
        path.join(os.tmpdir(), "nr-004c-missing-reservation-"),
    );
    try {
        const filePath = path.join(temporary, "proof.json");
        const value = fixture({
            store: createFileGitHubDraftPrProofStore(filePath),
        });
        await value.controller.arm();
        await value.controller.beforeToolCall(
            beforeEvent(value.payload),
            value.runtime,
        );
        await rm(`${filePath}.dispatch-reservation`);
        await expectReject(
            "STORE_RESERVATION_MISSING",
            () => value.controller.status(),
        );
    }
    finally {
        await rm(temporary, { recursive: true, force: true });
    }
});

test("receipt signature and approved trust anchor reject tampering", async () => {
    const { controller, payload, receiptSigner, runtime } = fixture();
    await controller.arm();
    await controller.beforeToolCall(beforeEvent(payload), runtime);
    const receipt = await controller.afterToolCall(
        afterEvent(successOutcome()),
    );
    const tampered = clone(receipt);
    tampered.attestation.signature_base64url =
        `${tampered.attestation.signature_base64url[0] === "A" ? "B" : "A"}`
        + tampered.attestation.signature_base64url.slice(1);
    assert.throws(
        () => validateGitHubDraftPrE2EReceipt(tampered, {
            expectedTrustAnchor: receiptSigner.trust_anchor,
        }),
        GitHubDraftPrE2EError,
    );
    const anotherSigner = createGitHubDraftPrE2EReceiptSigner();
    assert.throws(
        () => validateGitHubDraftPrE2EReceipt(receipt, {
            expectedTrustAnchor: anotherSigner.trust_anchor,
        }),
        (error) =>
            error instanceof GitHubDraftPrE2EError
            && error.code === "RECEIPT_TRUST_ANCHOR_MISMATCH",
    );
});

test("tampered persistent plan binding fails closed", async () => {
    const temporary = await mkdtemp(
        path.join(os.tmpdir(), "nr-004c-tamper-"),
    );
    try {
        const filePath = path.join(temporary, "proof.json");
        const value = fixture({
            store: createFileGitHubDraftPrProofStore(filePath),
        });
        await value.controller.arm();
        const document = JSON.parse(await readFile(filePath, "utf8"));
        document.record.plan_fingerprint_sha256 = HASH_F;
        await writeFile(filePath, JSON.stringify(document), "utf8");
        await expectReject(
            "STORE_PLAN_CONFLICT",
            () => value.controller.status(),
        );
    }
    finally {
        await rm(temporary, { recursive: true, force: true });
    }
});

test("status and receipts exclude raw payloads and provider credentials", async () => {
    const { controller, payload, runtime } = fixture();
    await controller.arm();
    await controller.beforeToolCall(beforeEvent(payload), runtime);
    await controller.afterToolCall(afterEvent(successOutcome()));
    const serialized = JSON.stringify(await controller.status());
    assert.doesNotMatch(serialized, /Phase 4C isolated Draft PR proof/);
    assert.doesNotMatch(serialized, /Contract fixture only/);
    assert.doesNotMatch(serialized, /private_key/i);
    assert.equal((await controller.status()).provider_credentials_persisted, false);
});

test("evaluation API returns a fail-closed block without unsafe error data", async () => {
    const { controller, payload, runtime } = fixture();
    await controller.arm();
    payload.title = "Unreviewed mutation";
    const result = await controller.evaluateBeforeToolCall(
        beforeEvent(payload),
        runtime,
    );
    assert.equal(result.block, true);
    assert.equal(result.allow_once, false);
    assert.equal(result.reason_code, "PAYLOAD_FINGERPRINT_MISMATCH");
    assert.equal(result.automatic_write_retry_allowed, false);
});

test("004C payload exactly matches the signed 004B reference schema", async () => {
    const bundle = JSON.parse(await readFile(
        new URL(
            "../contracts/fixtures/"
            + "github-draft-pr.canonical-policy-bundle-v1.json",
            import.meta.url,
        ),
        "utf8",
    ));
    const schema = bundle.registry.profiles[0].tool_input_schema;
    const { payload, plan } = fixture();
    assert.deepEqual(
        Object.keys(payload).sort(),
        schema.required.toSorted(),
    );
    assert.equal(schema.additionalProperties, false);
    assert.equal(schema.properties.draft.const, true);
    assert.equal(
        plan.connector_binding.tool_schema_fingerprint,
        bundle.registry.profiles[0].tool_schema_fingerprint,
    );
});

test("004C source has no network, provider, Gateway, task, or process path", async () => {
    const [source, index] = await Promise.all([
        readFile(
            new URL("../src/github-draft-pr-e2e.js", import.meta.url),
            "utf8",
        ),
        readFile(new URL("../src/index.js", import.meta.url), "utf8"),
    ]);
    assert.doesNotMatch(index, /GitHubDraftPrE2EController/);
    assert.doesNotMatch(source, /\bfetch\(/);
    assert.doesNotMatch(source, /"tools\.invoke"/);
    assert.doesNotMatch(source, /"tools\.catalog"/);
    assert.doesNotMatch(source, /\.runTask\(/);
    assert.doesNotMatch(source, /\.resume\(/);
    assert.doesNotMatch(source, /child_process/);
    assert.doesNotMatch(source, /\bexec(?:File)?\(/);
});

test("validated plan is frozen and fingerprint-protected", () => {
    const { plan } = fixture();
    const validated = validateGitHubDraftPrE2EPlan(plan, { now: NOW });
    assert.equal(Object.isFrozen(validated), true);
    assert.equal(Object.isFrozen(validated.target), true);
    const tampered = clone(plan);
    tampered.target.base_sha = "3".repeat(40);
    assert.throws(
        () => validateGitHubDraftPrE2EPlan(tampered, { now: NOW }),
        (error) =>
            error instanceof GitHubDraftPrE2EError
            && error.code === "PLAN_FINGERPRINT_MISMATCH",
    );
});

test("004C proof closes success, replay, concurrency, unknown, and revoke", async () => {
    const proof = await buildGitHubDraftPrE2EContractProof();
    assert.equal(
        proof.phase4b_prerequisite.contract_prerequisite_ready,
        true,
    );
    assert.equal(
        proof.phase4b_prerequisite.preexisting_external_write_authority,
        false,
    );
    assert.equal(proof.success_path.allow_once, true);
    assert.equal(proof.success_path.provider_attempt_count, 1);
    assert.equal(proof.replay.blocked, true);
    assert.equal(proof.replay.provider_attempt_count, 1);
    assert.equal(proof.concurrency.allowed_count, 1);
    assert.equal(proof.concurrency.blocked_count, 1);
    assert.equal(proof.unknown_outcome.initial_status, "unknown");
    assert.equal(
        proof.unknown_outcome
            .reconciliation_provider_write_attempted,
        false,
    );
    assert.equal(
        proof.unknown_outcome.total_provider_attempt_count,
        1,
    );
    assert.equal(proof.revocation.blocked, true);
    assert.equal(proof.revocation.provider_attempt_count, 0);
    assert.equal(proof.safety.external_write_attempted, false);
    assert.equal(
        proof.closure.phase4c_external_write_proof_completed,
        false,
    );
});
