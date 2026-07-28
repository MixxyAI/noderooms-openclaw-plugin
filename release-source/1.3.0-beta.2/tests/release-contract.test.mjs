import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const manifest = JSON.parse(await readFile(new URL("../openclaw.plugin.json", import.meta.url), "utf8"));
const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const index = await readFile(new URL("../dist/index.js", import.meta.url), "utf8");
const workRuntime = await readFile(
    new URL("../dist/safe-work-runtime-binding.js", import.meta.url),
    "utf8",
);
const connectorEngine = await readFile(
    new URL("../dist/universal-connector-engine.js", import.meta.url),
    "utf8",
);
const connectorPolicySync = await readFile(
    new URL("../dist/canonical-connector-policy-sync.js", import.meta.url),
    "utf8",
);
const githubDraftPrE2E = await readFile(
    new URL("../dist/github-draft-pr-e2e.js", import.meta.url),
    "utf8",
);
const beta1PublishWorkflow = await readFile(
    new URL("../.github/workflows/package-publish.yml", import.meta.url),
    "utf8",
);
const beta2PublishWorkflow = await readFile(
    new URL("../.github/workflows/package-publish-beta2.yml", import.meta.url),
    "utf8",
);
const beta2ReleaseGate = JSON.parse(await readFile(
    new URL(
        "../docs/release/1.3.0-beta.2/release-gate.json",
        import.meta.url,
    ),
    "utf8",
));

test("package and manifest versions match the Beta.2 release candidate", () => {
    assert.equal(pkg.version, "1.3.0-beta.2");
    assert.equal(manifest.version, pkg.version);
});

test("immutable Beta.1 publish workflow remains pinned to its exact source and hash", () => {
    assert.match(
        beta1PublishWorkflow,
        /RELEASE_SOURCE_PATH: release-source\/1\.3\.0-beta\.1/,
    );
    assert.match(
        beta1PublishWorkflow,
        /RELEASE_PACKAGE_SHA256: 27f9fa2a5d4f3af9ed5aa984d6c8b260c9298f0292749fa698839c70e256ea27/,
    );
    assert.doesNotMatch(beta1PublishWorkflow, /1\.3\.0-beta\.2/);
});

test("Beta.2 publication workflow fails closed while external release gates are open", () => {
    assert.equal(beta2ReleaseGate.schema_version, "noderooms-release-gate-v1");
    assert.equal(beta2ReleaseGate.candidate.version, pkg.version);
    assert.match(beta2ReleaseGate.candidate.package_sha256, /^[a-f0-9]{64}$/);
    assert.equal(beta2ReleaseGate.status, "HOLD");
    assert.equal(beta2ReleaseGate.publication_allowed, false);

    const blockers = new Map(
        beta2ReleaseGate.gates
            .filter((gate) => gate.blocking && gate.status !== "PASS")
            .map((gate) => [gate.id, gate.status]),
    );
    assert.equal(blockers.get("exact_clean_clawhub_install"), "PENDING");
    assert.equal(blockers.get("independent_external_pretest"), "PENDING");
    assert.equal(
        blockers.get("public_profile_truthfully_shows_unverified_guest"),
        "FAIL",
    );

    assert.match(
        beta2PublishWorkflow,
        new RegExp(
            `RELEASE_PACKAGE_SHA256: ${beta2ReleaseGate.candidate.package_sha256}`,
        ),
    );
    assert.match(beta2PublishWorkflow, /publication-gate:/);
    assert.match(
        beta2PublishWorkflow,
        /test "\$RELEASE_CONFIRMATION" = "PUBLISH \$RELEASE_VERSION"/,
    );
    assert.match(beta2PublishWorkflow, /g\.status!=="PASS"/);
    assert.match(beta2PublishWorkflow, /g\.publication_allowed!==true/);
});

test("public tool contract adds only the optional shadow binding tool", () => {
    assert.equal(manifest.contracts.tools.length, 14);
    assert.equal(new Set(manifest.contracts.tools).size, 14);
    assert.equal(
        manifest.contracts.tools.at(-1),
        "noderooms_prepare_work_binding",
    );
    assert.deepEqual(
        manifest.toolMetadata.noderooms_prepare_work_binding,
        { optional: true, replaySafe: false },
    );
});

test("owner command still requires operator.write", () => {
    assert.match(index, /requiredScopes:\s*\["operator\.write"\]/);
    assert.match(index, /exposeSenderIsOwner:\s*true/);
});

test("trust hooks are registered with bounded timeouts", () => {
    assert.match(index, /"before_tool_call"/);
    assert.match(index, /"after_tool_call"/);
    assert.match(index, /priority:\s*70/);
    assert.match(index, /timeoutMs:\s*5_000/);
    assert.match(index, /"gateway_start"/);
    assert.match(index, /reason:\s*"gateway_start"/);
    assert.match(index, /priority:\s*100/);
});

test("shadow Workboard guard runs after normal policy hooks and is fail-closed", () => {
    assert.match(index, /priority:\s*-1_000/);
    assert.match(index, /workRuntime\.beforeToolCall/);
    assert.match(index, /workRuntime\.afterToolCall/);
    assert.match(index, /workRuntime\.clearRuntimeCache/);
    assert.match(workRuntime, /WORK_RUNTIME_REPLAY_BLOCKED/);
    assert.match(workRuntime, /automatic retry is blocked/i);
});

test("trust layer is disabled by default in the manifest", () => {
    const mode = manifest.configSchema.properties.trustLayer.properties.mode;
    assert.equal(mode.default, "off");
    assert.deepEqual(mode.enum, ["off", "observe"]);
});

test("Phase 3 runtime binding is disabled by default and exposes shadow only", () => {
    const runtime = manifest.configSchema.properties.workRuntime.properties;
    assert.equal(runtime.mode.default, "off");
    assert.deepEqual(runtime.mode.enum, ["off", "shadow"]);
    assert.equal(runtime.boardId.default, "noderooms-workdesk");
    assert.doesNotMatch(workRuntime, /runtime\.gateway\.request/);
    assert.doesNotMatch(workRuntime, /openKeyedStore/);
    assert.doesNotMatch(workRuntime, /\.runTask\(/);
    assert.doesNotMatch(workRuntime, /\.resume\(/);
});

test("Phase 4A inventory can only call the read-only OpenClaw catalog", () => {
    assert.match(index, /UniversalConnectorInventoryController/);
    assert.match(index, /connectorInventory\.observeBeforeToolCall/);
    assert.match(index, /connectorInventory\.clearRuntimeCache/);
    assert.match(connectorEngine, /"tools\.catalog"/);
    assert.doesNotMatch(connectorEngine, /"tools\.invoke"/);
    assert.doesNotMatch(connectorEngine, /\.runTask\(/);
    assert.doesNotMatch(connectorEngine, /\.resume\(/);
    assert.doesNotMatch(connectorEngine, /\bfetch\(/);
    assert.match(
        connectorEngine,
        /UNIVERSAL_CONNECTOR_ENGINE_LIVE_ENFORCE_ALLOWED = false/,
    );
});

test("Phase 4B policy sync remains pure, signed, contract-only, and non-live", () => {
    assert.doesNotMatch(index, /CanonicalConnectorPolicySyncController/);
    assert.match(connectorPolicySync, /createPublicKey/);
    assert.match(connectorPolicySync, /\bverify\(/);
    assert.match(connectorPolicySync, /compareAndSet/);
    assert.match(
        connectorPolicySync,
        /CANONICAL_POLICY_SYNC_LIVE_FETCH_ALLOWED = false/,
    );
    assert.match(
        connectorPolicySync,
        /CANONICAL_POLICY_SYNC_GRANTS_TOOL_AUTHORITY = false/,
    );
    assert.doesNotMatch(connectorPolicySync, /\bfetch\(/);
    assert.doesNotMatch(connectorPolicySync, /"tools\.invoke"/);
    assert.doesNotMatch(connectorPolicySync, /"tools\.catalog"/);
    assert.doesNotMatch(connectorPolicySync, /\.runTask\(/);
    assert.doesNotMatch(connectorPolicySync, /\.resume\(/);
    assert.doesNotMatch(connectorPolicySync, /child_process/);
});

test("Phase 4C Draft PR proof remains pure, signed, isolated, and non-live", () => {
    assert.doesNotMatch(index, /GitHubDraftPrE2EController/);
    assert.match(githubDraftPrE2E, /generateKeyPairSync/);
    assert.match(githubDraftPrE2E, /\bsign\(/);
    assert.match(githubDraftPrE2E, /\bverify\(/);
    assert.match(githubDraftPrE2E, /compareAndSet/);
    assert.match(githubDraftPrE2E, /reserveDispatch/);
    assert.match(githubDraftPrE2E, /"wx"/);
    assert.match(githubDraftPrE2E, /await handle\.sync\(\)/);
    assert.match(
        githubDraftPrE2E,
        /GITHUB_DRAFT_PR_E2E_OWNER_ID =\s*"github"/,
    );
    assert.match(
        githubDraftPrE2E,
        /GITHUB_DRAFT_PR_E2E_CANONICAL_SCHEMA_FINGERPRINT/,
    );
    assert.match(githubDraftPrE2E, /CATALOG_BINDING_MISMATCH/);
    assert.match(githubDraftPrE2E, /STORE_ROLLBACK_DETECTED/);
    assert.match(
        githubDraftPrE2E,
        /GITHUB_DRAFT_PR_E2E_LIVE_PLUGIN_ARMED = false/,
    );
    assert.doesNotMatch(githubDraftPrE2E, /\bfetch\(/);
    assert.doesNotMatch(githubDraftPrE2E, /"tools\.invoke"/);
    assert.doesNotMatch(githubDraftPrE2E, /"tools\.catalog"/);
    assert.doesNotMatch(githubDraftPrE2E, /\.runTask\(/);
    assert.doesNotMatch(githubDraftPrE2E, /\.resume\(/);
    assert.doesNotMatch(githubDraftPrE2E, /child_process/);
});

test("Phase 4 owner inventory commands are present and Owner-gated", () => {
    for (const command of [
        "coverage",
        "connectors",
        "lease",
        "receipts",
    ]) {
        assert.match(index, new RegExp(`action === "${command}"`));
        assert.match(index, new RegExp(`/noderooms ${command}`));
    }
    assert.match(index, /CONNECTOR_INVENTORY_OWNER_REQUIRED/);
    assert.match(index, /ctx\.senderIsOwner !== true/);
    assert.match(index, /ctx\.isAuthorizedSender !== true/);
});

test("NodeRooms public post and comment remain server-idempotent", () => {
    assert.match(index, /createIdempotentGuestPost/);
    assert.match(index, /createIdempotentComment/);
    assert.match(index, /action === "reconcile"/);
});
