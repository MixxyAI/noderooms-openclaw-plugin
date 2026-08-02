import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
    mkdir,
    mkdtemp,
    readFile,
    rm,
    writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Value } from "typebox/value";

import {
    buildGmailTrustBridgeReceipt,
    createGmailTrustBridgeReceiptSigner,
    GmailTrustBridgeReceiptError,
    gmailTrustBridgeReceiptFingerprint,
    validateGmailTrustBridgeReceipt,
} from "../src/gmail-trustbridge-receipt.js";
import {
    GmailTrustBridgePilotController,
    GmailTrustBridgePilotStore,
    gmailAddressFingerprint,
    normalizeGmailTrustBridgeConfig,
} from "../src/gmail-trustbridge-pilot.js";
import {
    sha256Fingerprint,
} from "../src/passport-runtime-binding.js";

const schema = JSON.parse(await readFile(
    new URL(
        "../contracts/gmail-trustbridge-receipt-v1.schema.json",
        import.meta.url,
    ),
    "utf8",
));
const pluginManifest = JSON.parse(await readFile(
    new URL("../openclaw.plugin.json", import.meta.url),
    "utf8",
));
const pluginIndex = await readFile(
    new URL("../src/index.js", import.meta.url),
    "utf8",
);
const verifierPath = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    "../src/bin/verify-gmail-trustbridge-receipt.js",
);

const ACCOUNT = "owner@example.invalid";
const TARGET = "accounts@example.invalid";
const BASE_TIME = Date.parse("2026-07-31T00:30:00.000Z");

function pluginConfig(mode = "pilot") {
    return {
        gmailTrustBridge: {
            mode,
            passportAgentId: "passport-agent",
            accountBindingFingerprintSha256:
                gmailAddressFingerprint(ACCOUNT),
            allowedRecipientFingerprintsSha256: [
                gmailAddressFingerprint(ACCOUNT),
                gmailAddressFingerprint(TARGET),
            ],
            gog: {
                account: ACCOUNT,
                homePath: path.resolve("/opt/noderooms/gog-home"),
                client: "noderooms-alpha5",
                executablePath: path.resolve("/opt/noderooms/gog"),
                executableSha256: `sha256:${"a".repeat(64)}`,
            },
            receiptLedgerMaxEntries: 64,
        },
    };
}

async function harness(t, options = {}) {
    const root = await mkdtemp(path.join(os.tmpdir(), "nr-gmail-alpha5-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const config = normalizeGmailTrustBridgeConfig(
        options.pluginConfig ?? pluginConfig(),
    );
    const signer = createGmailTrustBridgeReceiptSigner();
    let now = options.now ?? BASE_TIME;
    const store = new GmailTrustBridgePilotStore({
        filePath: path.join(root, "state", "gmail-pilot.json"),
        maxEntries: config.receiptLedgerMaxEntries,
    });
    const controller = new GmailTrustBridgePilotController({
        config,
        receiptSigner: signer,
        store,
        now: () => now,
    });
    return {
        advance(milliseconds = 1_000) {
            now += milliseconds;
        },
        config,
        controller,
        root,
        signer,
        store,
    };
}

function event(toolName, params, suffix = "a") {
    return {
        toolName,
        params,
        runId: `run-alpha5-${suffix}`,
        toolCallId: `tool-call-alpha5-${suffix}`,
    };
}

function context(agentId) {
    return {
        agentId,
        runId: "run-alpha5-context",
        sessionKey: `agent:${agentId}:main`,
    };
}

function textPayload(content = "Alpha5 fixture content") {
    return {
        mime_type: "text/plain",
        charset: "UTF-8",
        body: { content },
    };
}

function sendParams(overrides = {}) {
    return {
        message: {
            to: TARGET,
            subject: "Alpha5 fixture",
            payload: textPayload(),
            ...overrides,
        },
        response_fields: ["id", "thread_id"],
    };
}

function draftParams() {
    return {
        body: {
            message: {
                to: TARGET,
                subject: "Alpha5 unsent fixture",
                payload: textPayload("Unsent fixture"),
            },
        },
        response_fields: ["id", "message"],
    };
}

async function approveAndComplete(
    fixture,
    beforeEvent,
    actor,
    result = { id: "provider-message-fixture" },
) {
    const gate = await fixture.controller.beforeToolCall(
        beforeEvent,
        context(actor),
    );
    assert.ok(gate?.requireApproval);
    assert.deepEqual(
        gate.requireApproval.allowedDecisions,
        ["allow-once", "deny"],
    );
    await gate.requireApproval.onResolution("allow-once");
    fixture.advance();
    await fixture.controller.afterToolCall({
        ...beforeEvent,
        result,
        durationMs: 25,
    }, context(actor));
    const summary = await fixture.store.summary();
    return summary.receipts.at(-1);
}

test("Alpha5 config stays default-off and binds one Passport Agent", () => {
    const off = normalizeGmailTrustBridgeConfig({});
    assert.equal(off.mode, "off");
    assert.equal(off.defaultOff, true);
    assert.equal(off.activationBlocked, false);
    assert.equal(off.deleteAllowed, false);
    assert.equal(off.passportAgentId, "noderooms-passport-agent");

    const incomplete = normalizeGmailTrustBridgeConfig({
        gmailTrustBridge: { mode: "pilot" },
    });
    assert.equal(incomplete.mode, "pilot");
    assert.equal(incomplete.activationBlocked, true);

    assert.equal(
        normalizeGmailTrustBridgeConfig(pluginConfig()).passportAgentId,
        "passport-agent",
    );
});

test("recipient fingerprints normalize case without persisting raw addresses", () => {
    assert.equal(
        gmailAddressFingerprint(`  ${TARGET.toUpperCase()} `),
        gmailAddressFingerprint(TARGET),
    );
    assert.match(
        gmailAddressFingerprint(TARGET),
        /^sha256:[a-f0-9]{64}$/,
    );
});

test("Gmail delete is hard-denied even when the pilot is off", async (t) => {
    const fixture = await harness(t, {
        pluginConfig: pluginConfig("off"),
    });
    const denied = await fixture.controller.beforeToolCall(
        event("gmail_delete_emails", {
            message_ids: ["message-delete-fixture"],
        }, "delete"),
        context("passport-agent"),
    );
    assert.equal(denied.block, true);
    assert.match(denied.blockReason, /permanently prohibits Gmail delete/i);

    const ungoverned = await fixture.controller.beforeToolCall(
        event("gmail_send_email", sendParams(), "off-send"),
        context("passport-agent"),
    );
    assert.equal(ungoverned, undefined);
});

test("Passport Agent is isolated and produces a signed read receipt", async (t) => {
    const fixture = await harness(t);
    const readEvent = event("gmail_search_emails", {
        query: "from:accounts@example.invalid",
        max_results: 5,
    }, "reader");
    const gate = await fixture.controller.beforeToolCall(
        readEvent,
        context("passport-agent"),
    );
    assert.equal(gate, undefined);
    fixture.advance();
    await fixture.controller.afterToolCall({
        ...readEvent,
        result: {
            emails: [{
                id: "message-id-that-must-not-enter-receipt",
                snippet: "raw mailbox content that must be fingerprinted only",
            }],
            durationMs: 12,
        },
    }, context("passport-agent"));
    const receipt = (await fixture.store.summary()).receipts.at(-1);
    assert.equal(receipt.operation, "search");
    assert.equal(receipt.approval.policy, "none");
    assert.equal(receipt.approval.consumed, false);
    assert.equal(receipt.actor.role, "passport_bound_gmail_agent");
    assert.doesNotMatch(
        JSON.stringify(receipt),
        /message-id-that-must-not-enter-receipt|raw mailbox content/,
    );
    assert.equal(Value.Check(schema, receipt), true);
    validateGmailTrustBridgeReceipt(receipt, {
        trustedReceiptAnchor: fixture.signer.trust_anchor,
    });

    const wrongAgent = await fixture.controller.beforeToolCall(
        event("gmail_read_email_thread", {
            id: "thread-fixture",
            id_type: "thread",
            max_messages: 5,
        }, "wrong-reader"),
        context("another-agent"),
    );
    assert.equal(wrongAgent.block, true);
    assert.match(wrongAgent.blockReason, /AGENT_MISMATCH/);
});

test("one unsent draft is created without granting send authority", async (t) => {
    const fixture = await harness(t);
    const draftEvent = event("gmail_create_draft", draftParams(), "draft");
    const gate = await fixture.controller.beforeToolCall(
        draftEvent,
        context("passport-agent"),
    );
    assert.equal(gate, undefined);
    fixture.advance();
    await fixture.controller.afterToolCall({
        ...draftEvent,
        result: {
            draft_id: "draft-id-that-must-not-enter-receipt",
            message: { id: "draft-message-id" },
        },
        durationMs: 25,
    }, context("passport-agent"));
    const receipt = (await fixture.store.summary()).receipts.at(-1);
    assert.equal(receipt.operation, "draft");
    assert.equal(receipt.approval.policy, "none");
    assert.equal(receipt.approval.consumed, false);
    assert.equal(receipt.actor.role, "passport_bound_gmail_agent");
    assert.equal(receipt.dispatch.provider_attempt_count, 1);
    assert.equal(receipt.dispatch.automatic_retry_allowed, false);
    assert.doesNotMatch(
        JSON.stringify(receipt),
        /draft-id-that-must-not-enter-receipt|draft-message-id/,
    );
});

test("send and reply are separate allow-once operations", async (t) => {
    const fixture = await harness(t);
    const sendReceipt = await approveAndComplete(
        fixture,
        event("gmail_send_email", sendParams(), "send"),
        "passport-agent",
    );
    assert.equal(sendReceipt.operation, "send");
    assert.equal(
        sendReceipt.scope,
        "connector.gmail.message.send",
    );

    const replyReceipt = await approveAndComplete(
        fixture,
        event("gmail_send_email", sendParams({
            reply_message_id: "source-message-fixture",
        }), "reply"),
        "passport-agent",
    );
    assert.equal(replyReceipt.operation, "reply");
    assert.equal(
        replyReceipt.scope,
        "connector.gmail.message.reply",
    );
    assert.notEqual(
        sendReceipt.receipt_fingerprint_sha256,
        replyReceipt.receipt_fingerprint_sha256,
    );
});

test("forward, archive, label, and delete stay hard denied", async (t) => {
    const fixture = await harness(t);
    for (const toolName of [
        "gmail_forward_emails",
        "gmail_archive_emails",
        "gmail_apply_labels_to_emails",
        "gmail_delete_emails",
    ]) {
        const denied = await fixture.controller.beforeToolCall(
            event(toolName, {}, toolName),
            context("passport-agent"),
        );
        assert.equal(denied.block, true);
    }
});

test("recipient expansion, Trash mutation, and unknown Gmail tools fail closed", async (t) => {
    const fixture = await harness(t);
    const expanded = await fixture.controller.beforeToolCall(
        event("gmail_send_email", sendParams({
            cc: ACCOUNT,
        }), "expanded"),
        context("passport-agent"),
    );
    assert.equal(expanded.block, true);
    assert.match(expanded.blockReason, /RECIPIENT_SET_INVALID/);

    const outside = await fixture.controller.beforeToolCall(
        event("gmail_send_email", sendParams({
            to: "outside@example.invalid",
        }), "outside"),
        context("passport-agent"),
    );
    assert.equal(outside.block, true);
    assert.match(outside.blockReason, /RECIPIENT_NOT_ALLOWED/);

    const trash = await fixture.controller.beforeToolCall(
        event("gmail_apply_labels_to_emails", {
            message_ids: ["message-alpha5-proof"],
            add_label_names: ["TRASH"],
            create_missing_labels: false,
        }, "trash-label"),
        context("passport-agent"),
    );
    assert.equal(trash.block, true);
    assert.match(trash.blockReason, /prohibits Gmail delete/i);

    const unknown = await fixture.controller.beforeToolCall(
        event("gmail_batch_modify_email", {
            message_ids: ["message-alpha5-proof"],
            add_label_ids: ["TRASH"],
        }, "unknown"),
        context("passport-agent"),
    );
    assert.equal(unknown.block, true);
    assert.match(unknown.blockReason, /outside the exact Alpha5 pilot/);
});

test("exact replay is blocked before a second provider attempt", async (t) => {
    const fixture = await harness(t);
    const sendEvent = event(
        "mcp__codex_apps__gmail_send_email",
        sendParams(),
        "replay",
    );
    const first = await fixture.controller.beforeToolCall(
        sendEvent,
        context("passport-agent"),
    );
    assert.ok(first.requireApproval);
    const second = await fixture.controller.beforeToolCall(
        sendEvent,
        context("passport-agent"),
    );
    assert.equal(second.block, true);
    assert.match(second.blockReason, /REPLAY_BLOCKED/);
    await first.requireApproval.onResolution("allow-once");
    const reservation = (await fixture.store.summary())
        .state_counts;
    assert.equal(reservation.dispatching, 1);
});

test("denied send approval never records a provider attempt", async (t) => {
    const fixture = await harness(t);
    const draftEvent = event(
        "gmail_send_email",
        sendParams(),
        "deny",
    );
    const gate = await fixture.controller.beforeToolCall(
        draftEvent,
        context("passport-agent"),
    );
    await gate.requireApproval.onResolution("deny");
    const summary = await fixture.store.summary();
    assert.equal(summary.state_counts.denied, 1);
    assert.equal(summary.receipts.length, 0);
});

test("write errors are sealed as unknown and never become retry signals", async (t) => {
    const fixture = await harness(t);
    const sendEvent = event(
        "gmail_send_email",
        sendParams(),
        "unknown",
    );
    const gate = await fixture.controller.beforeToolCall(
        sendEvent,
        context("passport-agent"),
    );
    await gate.requireApproval.onResolution("allow-once");
    fixture.advance();
    await fixture.controller.afterToolCall({
        ...sendEvent,
        error: "provider transport closed after dispatch",
        durationMs: 500,
    }, context("passport-agent"));
    const receipt = (await fixture.store.summary()).receipts.at(-1);
    assert.equal(receipt.outcome.status, "unknown");
    assert.equal(receipt.dispatch.provider_attempt_count, 1);
    assert.equal(receipt.dispatch.automatic_retry_attempted, false);
    assert.equal(receipt.dispatch.exactly_once_effect_claimed, false);
});

test("signed receipt rejects content, fingerprint, signature, and trust-anchor drift", async (t) => {
    const fixture = await harness(t);
    const receipt = await approveAndComplete(
        fixture,
        event("gmail_send_email", sendParams(), "tamper"),
        "passport-agent",
    );
    assert.equal(
        receipt.receipt_fingerprint_sha256,
        gmailTrustBridgeReceiptFingerprint(receipt),
    );

    const fingerprintDrift = structuredClone(receipt);
    fingerprintDrift.operation = "forward";
    assert.throws(
        () => validateGmailTrustBridgeReceipt(fingerprintDrift, {
            trustedReceiptAnchor: fixture.signer.trust_anchor,
        }),
        (error) =>
            error instanceof GmailTrustBridgeReceiptError
            && error.code === "GMAIL_RECEIPT_FINGERPRINT_MISMATCH",
    );

    const signatureDrift = structuredClone(receipt);
    signatureDrift.attestation.signature_base64url = "A".repeat(86);
    assert.throws(
        () => validateGmailTrustBridgeReceipt(signatureDrift, {
            trustedReceiptAnchor: fixture.signer.trust_anchor,
        }),
        (error) =>
            error instanceof GmailTrustBridgeReceiptError
            && error.code === "GMAIL_RECEIPT_SIGNATURE_INVALID",
    );

    const anotherSigner = createGmailTrustBridgeReceiptSigner();
    assert.throws(
        () => validateGmailTrustBridgeReceipt(receipt, {
            trustedReceiptAnchor: anotherSigner.trust_anchor,
        }),
        (error) =>
            error instanceof GmailTrustBridgeReceiptError
            && error.code === "GMAIL_RECEIPT_TRUST_ANCHOR_MISMATCH",
    );

    assert.throws(
        () => buildGmailTrustBridgeReceipt({
            reservation_id: "nrgmailres_11111111111111111111111111111111",
            operation: "send",
            scope: "connector.gmail.message.send",
            tool_name: "gmail_send_email",
            actor_role: "passport_bound_gmail_agent",
            agent_id_fingerprint_sha256:
                sha256Fingerprint({ agent: "fixture" }),
            account_binding_fingerprint_sha256:
                sha256Fingerprint({ account: "fixture" }),
            target_fingerprint_sha256:
                sha256Fingerprint({ target: "fixture" }),
            payload_fingerprint_sha256:
                sha256Fingerprint({ payload: "fixture" }),
            approval_policy: "allow_once",
            approval_consumed: true,
            provider_attempt_count: 1,
            provider_observation_fingerprint_sha256:
                sha256Fingerprint({ provider: "fixture" }),
            outcome_status: "committed",
            started_at: "2026-07-31T00:00:00.000Z",
            completed_at: "2026-07-31T00:00:01.000Z",
        }, {
            receiptSigner: null,
        }),
        (error) =>
            error instanceof GmailTrustBridgeReceiptError
            && error.code === "GMAIL_RECEIPT_SIGNER_REQUIRED",
    );
});

test("independent verifier CLI validates receipt plus separate trust anchor", async (t) => {
    const fixture = await harness(t);
    const receipt = await approveAndComplete(
        fixture,
        event("gmail_send_email", sendParams(), "cli"),
        "passport-agent",
    );
    const receiptPath = path.join(fixture.root, "receipt.json");
    const anchorPath = path.join(fixture.root, "trust-anchor.json");
    await mkdir(fixture.root, { recursive: true });
    await Promise.all([
        writeFile(receiptPath, JSON.stringify(receipt, null, 2)),
        writeFile(
            anchorPath,
            JSON.stringify(fixture.signer.trust_anchor, null, 2),
        ),
    ]);
    const result = spawnSync(
        process.execPath,
        [verifierPath, receiptPath, anchorPath],
        { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(
        result.stdout,
        /NR_GMAIL_TRUSTBRIDGE_RECEIPT_VERIFY=PASS/,
    );
    assert.doesNotMatch(result.stdout, /@example\.invalid/);
});

test("persisted receipts retain and revalidate their public trust anchor", async (t) => {
    const fixture = await harness(t);
    const receipt = await approveAndComplete(
        fixture,
        event("gmail_send_email", sendParams(), "restart-anchor"),
        "passport-agent",
    );
    const statePath = path.join(
        fixture.root,
        "state",
        "gmail-pilot.json",
    );
    const restartedStore = new GmailTrustBridgePilotStore({
        filePath: statePath,
        maxEntries: 64,
    });
    const restartedSummary = await restartedStore.summary();
    assert.equal(restartedSummary.receipt_records.length, 1);
    const record = restartedSummary.receipt_records[0];
    assert.deepEqual(record.receipt, receipt);
    validateGmailTrustBridgeReceipt(record.receipt, {
        trustedReceiptAnchor: record.trust_anchor,
    });

    const tampered = JSON.parse(await readFile(statePath, "utf8"));
    tampered.reservations[0].receipt.operation = "forward";
    await writeFile(statePath, JSON.stringify(tampered, null, 2));
    const tamperedStore = new GmailTrustBridgePilotStore({
        filePath: statePath,
        maxEntries: 64,
    });
    await assert.rejects(
        () => tamperedStore.summary(),
        (error) =>
            error?.code === "GMAIL_PILOT_STORE_INVALID",
    );
});

test("legacy Alpha5 pilot stays disconnected while R6 registers only background infrastructure", () => {
    const gmailConfig =
        pluginManifest.configSchema.properties.gmailTrustBridge;
    assert.deepEqual(gmailConfig.properties.mode.enum, ["off", "worker"]);
    assert.equal(gmailConfig.properties.mode.default, "off");
    assert.equal(gmailConfig.properties.openclawAgentId.default, "main");
    assert.equal(gmailConfig.properties.localPairingPort.default, 45832);
    assert.equal(pluginManifest.contracts.tools.length, 14);
    assert.equal(new Set(pluginManifest.contracts.tools).size, 14);
    assert.equal(
        pluginManifest.contracts.tools
            .filter((name) => name.startsWith("noderooms_"))
            .length,
        14,
    );
    assert.equal(
        pluginManifest.contracts.tools.some((name) =>
            name.startsWith("gmail_")),
        false,
    );
    assert.match(pluginIndex, /registerGmailTrustBridgeWorkerService/);
    assert.doesNotMatch(pluginIndex, /GmailTrustBridgePilotController/);
    assert.doesNotMatch(pluginIndex, /registerGmailGogTools/);
    assert.doesNotMatch(
        JSON.stringify(pluginManifest),
        /owner@example\.invalid|accounts@example\.invalid/,
    );
});
