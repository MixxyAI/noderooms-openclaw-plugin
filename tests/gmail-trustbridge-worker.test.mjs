import assert from "node:assert/strict";
import {
    createHash,
    createPublicKey,
    verify,
} from "node:crypto";
import {
    mkdtemp,
    readFile,
    rm,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    GMAIL_TRUSTBRIDGE_JOB_CONTRACT_VERSION,
    GMAIL_TRUSTBRIDGE_PAIR_CONTRACT_VERSION,
    GMAIL_TRUSTBRIDGE_SUPPORTED_JOB_TYPES,
    GMAIL_TRUSTBRIDGE_WORKER_CONTRACT_VERSION,
    GMAIL_TRUSTBRIDGE_WORKER_VERSION,
    GmailTrustBridgeWorkerError,
    GmailTrustBridgeWorkerService,
    buildGmailTrustBridgeGogInvocation,
    gmailTrustBridgeJobTargetFingerprint,
    gmailTrustBridgePairCanonical,
    gmailTrustBridgeRequestCanonical,
    normalizeGmailTrustBridgeJobResult,
    normalizeGmailTrustBridgeWorkerConfig,
    registerGmailTrustBridgeWorkerService,
} from "../src/gmail-trustbridge-worker.js";
import {
    NODEROOMS_CONNECTOR_AUTHORITY_CONTRACT_VERSION,
    NODEROOMS_CONNECTOR_JOB_SCOPES,
    noderoomsConnectorActionFingerprint,
} from "../src/noderooms-connector-authority.js";

const account = "owner@example.com";
const executableHash = `sha256:${"a".repeat(64)}`;
const ownerBindingId = "nrownbind_passport_agent_2026";

function sha256(value) {
    return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function workerConfig(overrides = {}) {
    return normalizeGmailTrustBridgeWorkerConfig({
        gmailTrustBridge: {
            mode: "worker",
            baseUrl: "https://noderooms.com",
            openclawAgentId: "main",
            localPairingPort: 45_832,
            pollIntervalMs: 60_000,
            gog: {
                account,
                homePath: path.resolve("/tmp/nr-gog-home"),
                client: "noderooms-r6",
                executablePath: path.resolve("/tmp/gog.exe"),
                executableSha256: executableHash,
            },
            ...overrides,
        },
    });
}

function oauthPayload(extra = {}) {
    return {
        account_email: account,
        callback_uri:
            "https://noderooms.com/wp-json/agent-guild-os/v1/trustbridge/gmail/oauth/callback",
        oauth_scopes: [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.compose",
        ],
        ...extra,
    };
}

function pairingPayload(extra = {}) {
    return {
        contract_version: GMAIL_TRUSTBRIDGE_PAIR_CONTRACT_VERSION,
        challenge_id: `nrtbp_${"1".repeat(32)}`,
        challenge: Buffer.alloc(32, 7).toString("base64url"),
        callback_url:
            "https://noderooms.com/wp-json/agent-guild-os/v1/trustbridge/worker/pairing/complete",
        site_origin: "https://noderooms.com",
        return_to: "https://noderooms.com/owner-dashboard/",
        agent_slug: "passport-agent",
        passport_public_id: "nrpass_example_123",
        expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
        ...extra,
    };
}

function encodedPairingPayload(extra = {}) {
    return Buffer.from(JSON.stringify(pairingPayload(extra))).toString(
        "base64url",
    );
}

function activePrivateBinding() {
    return {
        record: {
            status: "ACTIVE",
            worker_id: `nrtbw_${"7".repeat(32)}`,
            worker_binding_id: `nrtbwb_${"8".repeat(32)}`,
            agent_slug: "passport-agent",
            owner_binding_id: ownerBindingId,
            owner_binding_status: "verified",
            passport_public_id: "nrpass_example_123",
            passport_status: "active",
        },
        privateKey: null,
    };
}

function claimedJob(jobType, payload, idCharacter = "9") {
    const config = workerConfig();
    const jobId = `nrtbj_${idCharacter.repeat(32)}`;
    const payloadJson = JSON.stringify(payload);
    const payloadSha256 = sha256(payloadJson);
    const accountBindingSha256 = sha256(account);
    const targetFingerprintSha256 =
        gmailTrustBridgeJobTargetFingerprint(jobType, payload, config);
    const purposeId = "nrpurpose_mail_automation_2026";
    const purposeSha256 = sha256("NodeRooms owner mail automation");
    const capabilityId = "nrcap_mail_automation_2026";
    const runLeaseId = "nrlease_mail_automation_2026";
    const scope = NODEROOMS_CONNECTOR_JOB_SCOPES[jobType];
    const issuedAt = new Date(Date.now() - 60_000).toISOString();
    const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
    const capability = {
        capability_id: capabilityId,
        status: "active",
        decision: "allow",
        decision_source: "verified_human_owner",
        automated: false,
        agent_slug: "passport-agent",
        owner_binding_id: ownerBindingId,
        passport_public_id: "nrpass_example_123",
        provider: "gmail",
        account_binding_sha256: accountBindingSha256,
        target_fingerprint_sha256: targetFingerprintSha256,
        scope,
        purpose_id: purposeId,
        purpose_sha256: purposeSha256,
        issued_at: issuedAt,
        expires_at: expiresAt,
    };
    const runLease = {
        run_lease_id: runLeaseId,
        status: "active",
        capability_id: capabilityId,
        agent_slug: "passport-agent",
        owner_binding_id: ownerBindingId,
        passport_public_id: "nrpass_example_123",
        provider: "gmail",
        account_binding_sha256: accountBindingSha256,
        target_fingerprint_sha256: targetFingerprintSha256,
        scope,
        purpose_id: purposeId,
        purpose_sha256: purposeSha256,
        remaining_actions: 1,
        issued_at: issuedAt,
        expires_at: expiresAt,
    };
    const draftIdSha256 = jobType === "gmail_send_approved_draft"
        ? sha256(payload.draft_id)
        : null;
    const actionApproval = jobType === "gmail_send_approved_draft"
        ? {
            policy: "allow_once",
            status: "approved",
            decision_source: "verified_human_owner",
            automated: false,
            owner_binding_id: ownerBindingId,
            approval_receipt_id: "nrapproval_gmail_send_2026",
            dispatch_reservation_id: "nrdispatch_gmail_send_2026",
            draft_id_sha256: draftIdSha256,
            action_fingerprint_sha256:
                noderoomsConnectorActionFingerprint({
                    jobId,
                    jobType,
                    payloadSha256,
                    agentSlug: "passport-agent",
                    passportPublicId: "nrpass_example_123",
                    ownerBindingId,
                    capabilityId,
                    runLeaseId,
                    provider: "gmail",
                    accountBindingSha256,
                    targetFingerprintSha256,
                    scope,
                    purposeId,
                    purposeSha256,
                    draftIdSha256,
                }),
            provider_attempt_max: 1,
            automatic_retry_allowed: false,
            expires_at: new Date(Date.now() + 5 * 60_000).toISOString(),
        }
        : null;
    return {
        contract_version: GMAIL_TRUSTBRIDGE_JOB_CONTRACT_VERSION,
        job_id: jobId,
        job_type: jobType,
        agent: {
            slug: "passport-agent",
            passport_public_id: "nrpass_example_123",
        },
        payload_json: payloadJson,
        payload_sha256: payloadSha256,
        lease_token: "lease-token-".padEnd(64, "x"),
        expires_at: new Date(Date.now() + 5 * 60_000).toISOString(),
        authority: {
            contract_version:
                NODEROOMS_CONNECTOR_AUTHORITY_CONTRACT_VERSION,
            surfaces: {
                registration: "noderooms",
                work: "noderooms",
                connector_setup: "noderooms",
                operations: "noderooms",
                automations: "noderooms",
                approvals: "noderooms",
                results: "noderooms",
            },
            runtime: {
                role: "background_infrastructure",
                user_visible: false,
                user_cli_allowed: false,
                user_install_allowed: false,
                user_plugin_allowed: false,
                user_branding_allowed: false,
            },
            agent: {
                slug: "passport-agent",
                owner_binding_id: ownerBindingId,
                owner_binding_status: "verified",
                passport_public_id: "nrpass_example_123",
                passport_status: "active",
            },
            capability,
            run_lease: runLease,
            action_approval: actionApproval,
            job_binding: {
                job_id: jobId,
                job_type: jobType,
                payload_sha256: payloadSha256,
            },
        },
    };
}

test("Gmail infrastructure is default-off and worker mode requires an exact gog binding", () => {
    const off = normalizeGmailTrustBridgeWorkerConfig({});
    assert.equal(off.mode, "off");
    assert.equal(off.gog, null);
    assert.throws(
        () => normalizeGmailTrustBridgeWorkerConfig({
            gmailTrustBridge: { mode: "worker" },
        }),
        (error) => error instanceof GmailTrustBridgeWorkerError
            && error.code === "GMAIL_TRUSTBRIDGE_CONFIG_INVALID",
    );
    const active = workerConfig();
    assert.equal(active.mode, "worker");
    assert.equal(active.gog.account, account);
});

test("OAuth uses exact read plus compose scopes through the NodeRooms PKCE callback", () => {
    const config = workerConfig();
    const start = buildGmailTrustBridgeGogInvocation(
        "gmail_oauth_start",
        oauthPayload(),
        config,
    );
    assert.ok(start.args.includes("--gmail-scope"));
    assert.equal(
        start.args[start.args.indexOf("--gmail-scope") + 1],
        "readonly",
    );
    assert.equal(
        start.args[start.args.indexOf("--extra-scopes") + 1],
        "https://www.googleapis.com/auth/gmail.compose",
    );
    assert.equal(start.args.includes("--readonly"), false);
    assert.ok(start.args.includes("--gmail-no-send"));
    assert.ok(start.args.includes("auth.add"));

    const callbackUrl =
        "https://noderooms.com/wp-json/agent-guild-os/v1/trustbridge/gmail/oauth/callback?state=state-value-123456&code=one-use-code";
    const complete = buildGmailTrustBridgeGogInvocation(
        "gmail_oauth_complete",
        oauthPayload({ callback_url: callbackUrl }),
        config,
    );
    assert.equal(complete.args.includes("--readonly"), false);
    assert.ok(complete.args.includes("--gmail-no-send"));
    assert.deepEqual(
        complete.args.slice(-2),
        ["--auth-url", callbackUrl],
    );
});

test("search and thread reads keep the exact gog readonly/no-send command allowlist", () => {
    const config = workerConfig();
    const search = buildGmailTrustBridgeGogInvocation(
        "gmail_search",
        { account_email: account, query: "newer_than:7d", max_results: 10 },
        config,
    );
    assert.ok(search.args.includes("gmail.messages.search"));
    assert.ok(search.args.includes("--readonly"));
    assert.ok(search.args.includes("--gmail-no-send"));
    assert.equal(search.readOnly, true);

    const thread = buildGmailTrustBridgeGogInvocation(
        "gmail_thread_read",
        { account_email: account, thread_id: "thread_123" },
        config,
    );
    assert.ok(thread.args.includes("gmail.thread.get"));
    assert.ok(thread.args.includes("--sanitize-content"));
    assert.ok(thread.args.includes("--readonly"));
    assert.ok(thread.args.includes("--gmail-no-send"));
});

test("draft uses no-send while approved send can dispatch only one exact draft id", () => {
    const config = workerConfig();
    const draft = buildGmailTrustBridgeGogInvocation(
        "gmail_draft_create",
        {
            account_email: account,
            to: "recipient@example.com",
            subject: "Owner review",
            body: "Unsent body",
        },
        config,
    );
    assert.ok(draft.args.includes("gmail.drafts.create"));
    assert.ok(draft.args.includes("--gmail-no-send"));
    assert.deepEqual(draft.args.slice(-9), [
        "gmail", "drafts", "create",
        "--to", "recipient@example.com",
        "--subject", "Owner review",
        "--body-file", "-",
    ]);
    assert.equal(draft.stdin, "Unsent body");
    assert.equal(draft.writeKind, "draft");
    assert.equal(draft.automaticRetryAllowed, false);

    const send = buildGmailTrustBridgeGogInvocation(
        "gmail_send_approved_draft",
        {
            account_email: account,
            draft_id: "draft_owner_approved_1",
        },
        config,
    );
    assert.ok(send.args.includes("gmail.drafts.send"));
    assert.equal(send.args.includes("--gmail-no-send"), false);
    assert.deepEqual(
        send.args.slice(-4),
        ["gmail", "drafts", "send", "draft_owner_approved_1"],
    );
    assert.equal(send.stdin, null);
    assert.equal(send.writeKind, "send");
    assert.equal(send.providerAttemptMax, 1);
    assert.equal(send.automaticRetryAllowed, false);
    assert.equal(send.args.some((entry) => /recipient|subject|body/i.test(entry)), false);
});

test("draft and approved-send results expose only public-safe NodeRooms outcomes", () => {
    const config = workerConfig();
    const draft = normalizeGmailTrustBridgeJobResult(
        "gmail_draft_create",
        {
            account_email: account,
            to: "recipient@example.com",
            subject: "Owner review",
            body: "Private draft body",
        },
        { draft: { id: "draft_owner_approved_1" } },
        config,
    );
    assert.equal(draft.status, "draft_created");
    assert.equal(draft.sent, false);
    assert.equal(draft.draft_id, "draft_owner_approved_1");
    assert.equal(draft.provider_response_exposed, false);
    assert.equal(JSON.stringify(draft).includes("Private draft body"), false);

    const sent = normalizeGmailTrustBridgeJobResult(
        "gmail_send_approved_draft",
        {
            account_email: account,
            draft_id: "draft_owner_approved_1",
        },
        { message: { id: "message_sent_1" } },
        config,
    );
    assert.equal(sent.status, "sent");
    assert.equal(sent.owner_approval_consumed, true);
    assert.equal(sent.provider_attempt_count, 1);
    assert.equal(sent.automatic_retry_attempted, false);
    assert.equal(sent.exactly_once_effect_claimed, false);
    assert.equal(sent.mailbox_delete_enabled, false);
});

test("read results are explicitly untrusted, execute nothing, and reject provider secrets", () => {
    const config = workerConfig();
    const result = normalizeGmailTrustBridgeJobResult(
        "gmail_search",
        { account_email: account },
        { messages: [{ id: "m1", snippet: "external text" }] },
        config,
    );
    assert.equal(result.remote_content_untrusted, true);
    assert.equal(result.remote_content_executed, false);
    assert.equal(result.write_enabled, false);
    assert.throws(
        () => normalizeGmailTrustBridgeJobResult(
            "gmail_search",
            { account_email: account },
            { access_token: "forbidden" },
            config,
        ),
        (error) => error instanceof GmailTrustBridgeWorkerError
            && error.code === "GMAIL_TRUSTBRIDGE_RESULT_SECRET_REJECTED",
    );
});

test("OAuth start accepts only a Google URL bound to S256 PKCE and the exact callback", () => {
    const config = workerConfig();
    const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    authUrl.searchParams.set("redirect_uri", oauthPayload().callback_uri);
    authUrl.searchParams.set("state", "state-value-long-enough");
    authUrl.searchParams.set("code_challenge_method", "S256");
    authUrl.searchParams.set("code_challenge", "A".repeat(43));
    const normalized = normalizeGmailTrustBridgeJobResult(
        "gmail_oauth_start",
        oauthPayload(),
        { authorization: { url: authUrl.href } },
        config,
    );
    assert.equal(normalized.auth_url, authUrl.href);
    assert.equal(normalized.provider_token_exposed, false);
    assert.equal(normalized.write_enabled, false);
});

test("pairing canonical binds challenge, worker key, OpenClaw Agent, version, and exact job set", () => {
    const input = {
        challenge_id: `nrtbp_${"2".repeat(32)}`,
        challenge: Buffer.alloc(32, 2).toString("base64url"),
        worker_id: `nrtbw_${"3".repeat(32)}`,
        public_key_b64url: Buffer.alloc(32, 3).toString("base64url"),
        openclaw_agent_id: "main",
        worker_version: GMAIL_TRUSTBRIDGE_WORKER_VERSION,
        supported_job_types: [...GMAIL_TRUSTBRIDGE_SUPPORTED_JOB_TYPES].reverse(),
        issued_at: 1_786_000_000,
    };
    const canonical = gmailTrustBridgePairCanonical(input);
    assert.match(canonical, /^noderooms-gmail-worker-pair\.v1\n/);
    assert.ok(canonical.includes(`\nmain\n${GMAIL_TRUSTBRIDGE_WORKER_VERSION}\n`));
    assert.match(
        canonical,
        /gmail_disconnect,gmail_draft_create,gmail_oauth_complete,gmail_oauth_start,gmail_search,gmail_send_approved_draft,gmail_thread_read/,
    );
});

test("request canonical binds method, exact REST path, timestamp, nonce, and exact body bytes", () => {
    const first = gmailTrustBridgeRequestCanonical(
        "post",
        "/wp-json/example",
        1_786_000_000,
        "abc123",
        "{\"a\":1}",
    );
    const second = gmailTrustBridgeRequestCanonical(
        "POST",
        "/wp-json/example",
        1_786_000_000,
        "abc123",
        "{\"a\":2}",
    );
    assert.notEqual(first, second);
    assert.match(first, /^POST\n\/wp-json\/example\n1786000000\nabc123\n[a-f0-9]{64}$/);
});

test("pairing stores the private key only in the exact Agent directory and sends only the public key", async () => {
    const agentDir = await mkdtemp(path.join(os.tmpdir(), "nr-gmail-worker-"));
    let requestBody;
    const fetchMock = async (_url, options) => {
        requestBody = JSON.parse(options.body);
        const publicKey = createPublicKey({
            key: {
                kty: "OKP",
                crv: "Ed25519",
                x: requestBody.public_key_b64url,
            },
            format: "jwk",
        });
        assert.equal(
            verify(
                null,
                Buffer.from(gmailTrustBridgePairCanonical(requestBody)),
                publicKey,
                Buffer.from(requestBody.signature_b64url, "base64url"),
            ),
            true,
        );
        return new Response(JSON.stringify({
            ok: true,
            worker_id: requestBody.worker_id,
            worker_binding_id: `nrtbwb_${"4".repeat(32)}`,
            agent: {
                slug: "passport-agent",
                owner_binding_id: ownerBindingId,
                owner_binding_status: "verified",
                passport_public_id: "nrpass_example_123",
                passport_status: "active",
            },
        }), {
            status: 200,
            headers: { "content-type": "application/json" },
        });
    };
    const service = new GmailTrustBridgeWorkerService({
        config: workerConfig(),
        agentDir,
        fetch: fetchMock,
        verifyExecutable: async () => ({
            executablePath: "/tmp/gog.exe",
            executableSha256: executableHash,
            sizeBytes: 2_000_000,
        }),
    });
    try {
        const paired = await service.pair(encodedPairingPayload());
        assert.equal(paired.worker_binding_id, `nrtbwb_${"4".repeat(32)}`);
        assert.equal(Object.hasOwn(requestBody, "private_key_pkcs8_pem"), false);
        assert.equal(Object.hasOwn(requestBody, "challenge_sha256"), false);
        const privatePath = path.join(
            agentDir,
            "noderooms",
            "gmail-trustbridge-worker-v2",
            "worker-private.json",
        );
        const privateRecord = JSON.parse(await readFile(privatePath, "utf8"));
        assert.match(privateRecord.private_key_pkcs8_pem, /BEGIN PRIVATE KEY/);
        assert.equal(privateRecord.status, "ACTIVE");
        assert.equal(privateRecord.agent_slug, "passport-agent");
        assert.equal(privateRecord.owner_binding_id, ownerBindingId);
        assert.equal(privateRecord.owner_binding_status, "verified");
        assert.equal(privateRecord.passport_public_id, "nrpass_example_123");
        assert.equal(privateRecord.passport_status, "active");
    }
    finally {
        await service.stop();
        await rm(agentDir, { recursive: true, force: true });
    }
});

test("a paired worker rejects another NodeRooms Agent or Passport without key rotation", async () => {
    const agentDir = await mkdtemp(path.join(os.tmpdir(), "nr-gmail-worker-"));
    const fetchMock = async (_url, options) => {
        const body = JSON.parse(options.body);
        return new Response(JSON.stringify({
            ok: true,
            worker_id: body.worker_id,
            worker_binding_id: `nrtbwb_${"5".repeat(32)}`,
            agent: {
                slug: "passport-agent",
                owner_binding_id: ownerBindingId,
                owner_binding_status: "verified",
                passport_public_id: "nrpass_example_123",
                passport_status: "active",
            },
        }), { status: 200 });
    };
    const service = new GmailTrustBridgeWorkerService({
        config: workerConfig(),
        agentDir,
        fetch: fetchMock,
        verifyExecutable: async () => ({ executablePath: "/tmp/gog.exe" }),
    });
    try {
        await service.pair(encodedPairingPayload());
        await assert.rejects(
            service.pair(encodedPairingPayload({
                challenge_id: `nrtbp_${"6".repeat(32)}`,
                agent_slug: "another-agent",
            })),
            (error) => error instanceof GmailTrustBridgeWorkerError
                && error.code === "GMAIL_TRUSTBRIDGE_ALREADY_BOUND",
        );
    }
    finally {
        await service.stop();
        await rm(agentDir, { recursive: true, force: true });
    }
});

test("worker service registers only in full runtime mode and never registers a Gmail tool", () => {
    let services = 0;
    let tools = 0;
    const api = {
        registrationMode: "discovery",
        registerService() { services += 1; },
        registerTool() { tools += 1; },
        logger: {},
    };
    assert.equal(registerGmailTrustBridgeWorkerService(api, {
        config: workerConfig(),
        agentDir: "/tmp/agent",
        service: {},
    }), null);
    assert.equal(services, 0);
    assert.equal(tools, 0);

    api.registrationMode = "full";
    const service = { start() {}, stop() {} };
    assert.equal(registerGmailTrustBridgeWorkerService(api, {
        config: workerConfig(),
        agentDir: "/tmp/agent",
        service,
    }), service);
    assert.equal(services, 1);
    assert.equal(tools, 0);
});

test("claimed jobs hard-deny before provider use without every NodeRooms authority link", () => {
    const service = new GmailTrustBridgeWorkerService({
        config: workerConfig(),
        agentDir: path.resolve("/tmp/nr-authority-test"),
        verifyExecutable: async () => ({ executablePath: "/tmp/gog.exe" }),
    });
    service.privateBinding = activePrivateBinding();
    const base = claimedJob(
        "gmail_search",
        { account_email: account, query: "newer_than:1d" },
    );
    const valid = service.validateClaimedJob(base);
    assert.equal(valid.authority.ownerBindingId, ownerBindingId);

    for (const [field, code] of [
        ["capability", "NODEROOMS_CAPABILITY_REQUIRED"],
        ["run_lease", "NODEROOMS_RUN_LEASE_REQUIRED"],
    ]) {
        const invalid = structuredClone(base);
        delete invalid.authority[field];
        assert.throws(
            () => service.validateClaimedJob(invalid),
            (error) => error?.code === code,
        );
    }

    const noOwner = structuredClone(base);
    noOwner.authority.agent.owner_binding_status = "revoked";
    assert.throws(
        () => service.validateClaimedJob(noOwner),
        (error) => error?.code === "NODEROOMS_OWNER_BINDING_REQUIRED",
    );

    const noPassport = structuredClone(base);
    noPassport.authority.agent.passport_status = "revoked";
    assert.throws(
        () => service.validateClaimedJob(noPassport),
        (error) => error?.code === "NODEROOMS_PASSPORT_REQUIRED",
    );

    const wrongSurface = structuredClone(base);
    wrongSurface.authority.surfaces.results = "openclaw";
    assert.throws(
        () => service.validateClaimedJob(wrongSurface),
        (error) => error?.code === "NODEROOMS_PRODUCT_SURFACE_REQUIRED",
    );
});

test("an uncertain approved send is sealed unknown and replay never reaches provider twice", async () => {
    let providerAttempts = 0;
    const completions = [];
    const service = new GmailTrustBridgeWorkerService({
        config: workerConfig(),
        agentDir: path.resolve("/tmp/nr-send-test"),
        verifyExecutable: async () => ({ executablePath: "/tmp/gog.exe" }),
        runCommand: async () => {
            providerAttempts += 1;
            throw new Error("transport closed after dispatch");
        },
    });
    service.privateBinding = activePrivateBinding();
    service.completeJob = async (_job, completion) => {
        completions.push(completion);
        return { ok: true };
    };
    const job = claimedJob(
        "gmail_send_approved_draft",
        {
            account_email: account,
            draft_id: "draft_owner_approved_1",
        },
    );
    await service.processClaimedJob(job);
    assert.equal(providerAttempts, 1);
    assert.equal(completions.at(-1).outcome, "unknown");
    assert.equal(completions.at(-1).provider_attempt_count, 1);
    assert.equal(completions.at(-1).automatic_retry_attempted, false);

    await service.processClaimedJob(job);
    assert.equal(providerAttempts, 1);
    assert.equal(
        completions.at(-1).error_code,
        "GMAIL_TRUSTBRIDGE_JOB_REPLAY_BLOCKED",
    );
    assert.equal(completions.at(-1).provider_attempt_count, 0);
});

test("the R6 job set exposes draft and approved-draft send but no delete surface", () => {
    assert.equal(
        GMAIL_TRUSTBRIDGE_WORKER_CONTRACT_VERSION,
        "noderooms-trustbridge-worker.v2",
    );
    assert.equal(
        GMAIL_TRUSTBRIDGE_JOB_CONTRACT_VERSION,
        "noderooms-trustbridge-job.v2",
    );
    assert.deepEqual(GMAIL_TRUSTBRIDGE_SUPPORTED_JOB_TYPES, [
        "gmail_oauth_start",
        "gmail_oauth_complete",
        "gmail_search",
        "gmail_thread_read",
        "gmail_draft_create",
        "gmail_send_approved_draft",
        "gmail_disconnect",
    ]);
    assert.equal(
        GMAIL_TRUSTBRIDGE_SUPPORTED_JOB_TYPES.some(
            (name) => /forward|archive|label|delete|trash/.test(name),
        ),
        false,
    );
});
