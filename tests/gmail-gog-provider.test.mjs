import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
    buildGogInvocation,
    GmailGogProviderError,
    GMAIL_GOG_TOOL_NAMES,
    verifyGogExecutableBinding,
} from "../src/gmail-gog-provider.js";
import {
    gmailAddressFingerprint,
    normalizeGmailTrustBridgeConfig,
} from "../src/gmail-trustbridge-pilot.js";

const ACCOUNT = "abraham.zsolt30@gmail.com";
const TARGET = "accounts@noderooms.com";
const EXECUTABLE_SHA = `sha256:${"a".repeat(64)}`;

function pluginConfig(overrides = {}) {
    return normalizeGmailTrustBridgeConfig({
        gmailTrustBridge: {
            mode: "pilot",
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
                executableSha256: EXECUTABLE_SHA,
            },
            ...overrides,
        },
    });
}

function assertExactPolicy(invocation, expectedPolicy) {
    const policyIndex = invocation.args.indexOf(
        "--enable-commands-exact",
    );
    assert.ok(policyIndex >= 0);
    assert.equal(invocation.args[policyIndex + 1], expectedPolicy);
    assert.equal(invocation.args.includes("--enable-commands"), false);
}

test("Alpha5 activation requires an exact gog account and binary binding", () => {
    const ready = pluginConfig();
    assert.equal(ready.activationBlocked, false);
    assert.equal(ready.gog.ready, true);
    assert.equal(ready.gog.accountMatchesBinding, true);

    const missing = normalizeGmailTrustBridgeConfig({
        gmailTrustBridge: {
            mode: "pilot",
            passportAgentId: "passport-agent",
            accountBindingFingerprintSha256:
                gmailAddressFingerprint(ACCOUNT),
            allowedRecipientFingerprintsSha256: [
                gmailAddressFingerprint(ACCOUNT),
                gmailAddressFingerprint(TARGET),
            ],
        },
    });
    assert.equal(missing.activationBlocked, true);
    assert.equal(missing.gog.ready, false);

    const mismatch = pluginConfig({
        gog: {
            account: "another@example.com",
            executablePath: path.resolve("/opt/noderooms/gog"),
            executableSha256: EXECUTABLE_SHA,
        },
    });
    assert.equal(mismatch.activationBlocked, true);
    assert.equal(mismatch.gog.accountMatchesBinding, false);
});

test("read commands are exact, read-only, no-send, bounded gog invocations", () => {
    const config = pluginConfig();
    const search = buildGogInvocation(
        GMAIL_GOG_TOOL_NAMES.search,
        {
            query: "newer_than:7d from:accounts@noderooms.com",
            max_results: 5,
        },
        config,
    );
    assertExactPolicy(search, "gmail.messages.search");
    assert.equal(search.readOnly, true);
    assert.equal(search.args.includes("--readonly"), true);
    assert.equal(search.args.includes("--gmail-no-send"), true);
    assert.equal(
        search.args[search.args.indexOf("--client") + 1],
        "noderooms-alpha5",
    );
    assert.equal(
        search.args[search.args.indexOf("--home") + 1],
        path.resolve("/opt/noderooms/gog-home"),
    );
    assert.deepEqual(
        search.args.slice(-6),
        [
            "gmail",
            "messages",
            "search",
            "newer_than:7d from:accounts@noderooms.com",
            "--max",
            "5",
        ],
    );

    const read = buildGogInvocation(
        GMAIL_GOG_TOOL_NAMES.readThread,
        { thread_id: "thread_ABC-123" },
        config,
    );
    assertExactPolicy(read, "gmail.thread.get");
    assert.deepEqual(
        read.args.slice(-5),
        ["gmail", "thread", "get", "thread_ABC-123", "--sanitize-content"],
    );
});

test("the low-level adapter exports read operations only", async () => {
    assert.deepEqual(GMAIL_GOG_TOOL_NAMES, {
        search: "gmail_search_emails",
        readThread: "gmail_read_email_thread",
    });
    const module = await import("../src/gmail-gog-provider.js");
    assert.equal("GmailGogProvider" in module, false);
    assert.equal("registerGmailGogTools" in module, false);
    assert.equal("spawnGogOnce" in module, false);
});

test("all direct and destructive mailbox mutations expose no adapter path", () => {
    const config = pluginConfig();
    for (const toolName of [
        "gmail_create_draft",
        "gmail_send_email",
        "gmail_draft_create",
        "gmail_send_approved_draft",
        "gmail_forward_emails",
        "gmail_archive_emails",
        "gmail_apply_labels_to_emails",
        "gmail_delete_emails",
    ]) {
        assert.throws(
            () => buildGogInvocation(toolName, {}, config),
            (error) =>
                error instanceof GmailGogProviderError
                && error.code === "GMAIL_GOG_TOOL_UNSUPPORTED",
        );
    }
});

test("binary binding rejects tamper before gog can start", async (t) => {
    const root = await mkdtemp(path.join(os.tmpdir(), "nr-gog-binding-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const executablePath = path.join(root, "gog.exe");
    const bytes = Buffer.alloc(1_000_000, 0x41);
    await writeFile(executablePath, bytes);
    const digest = createHash("sha256").update(bytes).digest("hex");
    const config = pluginConfig({
        gog: {
            account: ACCOUNT,
            homePath: path.resolve("/opt/noderooms/gog-home"),
            client: "noderooms-alpha5",
            executablePath,
            executableSha256: `sha256:${digest}`,
        },
    });
    const binding = await verifyGogExecutableBinding(config);
    assert.equal(binding.executableSha256, `sha256:${digest}`);

    const tampered = structuredClone(config);
    tampered.gog.executableSha256 = EXECUTABLE_SHA;
    await assert.rejects(
        () => verifyGogExecutableBinding(tampered),
        (error) =>
            error instanceof GmailGogProviderError
            && error.code === "GMAIL_GOG_BINARY_HASH_MISMATCH",
    );
});
