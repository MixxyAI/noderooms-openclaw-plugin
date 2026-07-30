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
const connectorBetaFoundation = await readFile(
    new URL("../dist/connector-beta-foundation.js", import.meta.url),
    "utf8",
);
const emailReadDraftProfile = await readFile(
    new URL("../dist/email-read-draft-profile.js", import.meta.url),
    "utf8",
);
const stableSourcePackage = JSON.parse(await readFile(
    new URL("../release-source/1.3.0/package.json", import.meta.url),
    "utf8",
));
const stableSourceManifest = JSON.parse(await readFile(
    new URL("../release-source/1.3.0/openclaw.plugin.json", import.meta.url),
    "utf8",
));
const beta1PublishWorkflow = await readFile(
    new URL("../.github/workflows/package-publish.yml", import.meta.url),
    "utf8",
);
const beta2PublishWorkflow = await readFile(
    new URL("../.github/workflows/package-publish-beta2.yml", import.meta.url),
    "utf8",
);
const stablePublishWorkflow = await readFile(
    new URL("../.github/workflows/package-publish-stable.yml", import.meta.url),
    "utf8",
);
const pluginCiWorkflow = await readFile(
    new URL("../.github/workflows/plugin-ci.yml", import.meta.url),
    "utf8",
);
const beta2ReleaseGate = JSON.parse(await readFile(
    new URL(
        "../docs/release/1.3.0-beta.2/release-gate.json",
        import.meta.url,
    ),
    "utf8",
));
const beta2ReleaseClosure = JSON.parse(await readFile(
    new URL(
        "../docs/release/1.3.0-beta.2/release-closure.json",
        import.meta.url,
    ),
    "utf8",
));
const stableReleaseGate = JSON.parse(await readFile(
    new URL("../docs/release/1.3.0/release-gate.json", import.meta.url),
    "utf8",
));
const stableReleaseClosure = JSON.parse(await readFile(
    new URL("../docs/release/1.3.0/release-closure.json", import.meta.url),
    "utf8",
));

test("Connector Beta uses a distinct development identity and preserves stable 1.3.0", () => {
    assert.equal(pkg.version, "1.4.0-alpha.2-dev.1");
    assert.equal(manifest.version, pkg.version);
    assert.equal(stableSourcePackage.version, "1.3.0");
    assert.equal(stableSourceManifest.version, stableSourcePackage.version);
});

test("feature CI validates the exact branch identity without a stable-version hardcode", () => {
    assert.match(pluginCiWorkflow, /const sourcePackage = JSON\.parse/);
    assert.match(pluginCiWorkflow, /const pluginManifest = JSON\.parse/);
    assert.match(
        pluginCiWorkflow,
        /result\[0\]\.name !== sourcePackage\.name/,
    );
    assert.match(
        pluginCiWorkflow,
        /result\[0\]\.version !== sourcePackage\.version/,
    );
    assert.match(
        pluginCiWorkflow,
        /pluginManifest\.version !== sourcePackage\.version/,
    );
    assert.doesNotMatch(
        pluginCiWorkflow,
        /result\[0\]\.version !== "1\.3\.0"/,
    );
});

test("immutable Beta.1 workflow remains pinned and validation-only", () => {
    assert.match(
        beta1PublishWorkflow,
        /RELEASE_SOURCE_PATH: release-source\/1\.3\.0-beta\.1/,
    );
    assert.match(
        beta1PublishWorkflow,
        /RELEASE_PACKAGE_SHA256: 27f9fa2a5d4f3af9ed5aa984d6c8b260c9298f0292749fa698839c70e256ea27/,
    );
    assert.doesNotMatch(beta1PublishWorkflow, /1\.3\.0-beta\.2/);
    assert.match(
        beta1PublishWorkflow,
        /name: NodeRooms Beta1 immutable validation \(publish disabled\)/,
    );
    assert.doesNotMatch(beta1PublishWorkflow, /^\s{2}publish:\s*$/m);
    assert.doesNotMatch(beta1PublishWorkflow, /dry_run:\s*false/);
});

test("Beta.2 publication and post-publication evidence are closed without changing its channel", () => {
    assert.equal(beta2ReleaseGate.schema_version, "noderooms-release-gate-v1");
    assert.equal(beta2ReleaseGate.candidate.version, "1.3.0-beta.2");
    assert.equal(
        beta2ReleaseGate.candidate.package_sha256,
        "909016696cbcc9931c535b05f77b644bc55e792432a8a611a5b3f810024d17a2",
    );
    assert.equal(beta2ReleaseGate.status, "PASS");
    assert.equal(beta2ReleaseGate.publication_allowed, true);

    const blockers = beta2ReleaseGate.gates
        .filter((gate) => gate.blocking && gate.status !== "PASS");
    assert.deepEqual(blockers, []);

    const blockingGates = new Map(
        beta2ReleaseGate.gates
            .filter((gate) => gate.blocking)
            .map((gate) => [gate.id, gate.status]),
    );
    for (const id of [
        "clean_local_clawpack_archive_install",
        "clawhub_remote_dry_run_validation",
        "independent_external_pretest",
        "public_profile_truthfully_shows_unverified_guest",
        "candidate_readme_exact_version_and_owner_commit_flow",
        "public_exact_version_and_owner_commit_flow_documented",
        "public_activity_copy_truthful_for_unverified_guest",
        "agent_local_guest_entry_serialization",
    ]) {
        assert.equal(blockingGates.get(id), "PASS");
    }
    for (const id of [
        "openclaw_host_dependency_audit",
        "locked_dependency_tree_integrity",
    ]) {
        const advisory = beta2ReleaseGate.gates.find((gate) => gate.id === id);
        assert.equal(advisory?.blocking, false);
        assert.equal(advisory?.status, "UPSTREAM_WARN");
    }
    for (const id of [
        "exact_clean_clawhub_install_post_publish",
        "clawhub_listing_truth_check_post_publish",
    ]) {
        const postPublish = beta2ReleaseGate.gates.find(
            (gate) => gate.id === id,
        );
        assert.equal(postPublish?.blocking, false);
        assert.equal(postPublish?.status, "PASS");
    }

    assert.equal(
        beta2ReleaseClosure.schema_version,
        "noderooms-release-closure-v1",
    );
    assert.equal(
        beta2ReleaseClosure.candidate.package_sha256,
        beta2ReleaseGate.candidate.package_sha256,
    );
    assert.equal(
        beta2ReleaseClosure.github_actions.plugin_ci.conclusion,
        "success",
    );
    assert.equal(
        beta2ReleaseClosure.github_actions.beta2_validation_and_dry_run
            .conclusion,
        "success",
    );
    assert.equal(
        beta2ReleaseClosure.github_actions.beta2_validation_and_dry_run
            .dry_run,
        true,
    );
    assert.deepEqual(
        beta2ReleaseClosure.github_actions.beta2_validation_and_dry_run.tags,
        ["beta"],
    );
    assert.equal(
        beta2ReleaseClosure.independent_external_pretest.two_agent_verdict,
        "PASS",
    );
    assert.equal(
        beta2ReleaseClosure.independent_external_pretest.nine_agent_verdict,
        "PASS",
    );
    assert.equal(
        beta2ReleaseClosure.independent_external_pretest
            .noderooms_production_network_calls,
        0,
    );
    assert.equal(
        beta2ReleaseClosure.independent_external_pretest
            .production_public_writes,
        0,
    );
    assert.equal(
        beta2ReleaseClosure.public_origin_prepublish
            .normal_login_registration_changed,
        false,
    );
    assert.equal(
        beta2ReleaseClosure.public_origin_prepublish
            .separate_external_agent_entry,
        true,
    );
    assert.equal(beta2ReleaseClosure.publication_scope.channel, "beta");
    assert.equal(
        beta2ReleaseClosure.publication_scope.stable_channel_allowed,
        false,
    );
    assert.equal(beta2ReleaseClosure.decision.status, "PASS");
    assert.equal(beta2ReleaseClosure.decision.publication_allowed, true);
    assert.equal(beta2ReleaseClosure.decision.publication_completed, true);
    assert.equal(beta2ReleaseClosure.publication.run_id, 30439110714);
    assert.equal(
        beta2ReleaseClosure.publication.head_sha,
        "85bc9985ab599178913f4ad7bf23b0a4df4ad443",
    );
    assert.equal(
        beta2ReleaseClosure.publication.release_id,
        "rd70zhfkejk4ha0t55f9g2nvqs8bf980",
    );
    assert.equal(beta2ReleaseClosure.post_publish.status, "PASS");
    assert.equal(beta2ReleaseClosure.post_publish.loaded_tools, 14);
    assert.equal(beta2ReleaseClosure.post_publish.plugin_diagnostics, 0);
    assert.equal(beta2ReleaseClosure.post_publish.public_content_modified, false);
    assert.equal(beta2ReleaseClosure.post_publish.legacy_public_url_count, 0);
    assert.equal(beta2ReleaseClosure.post_publish.release_hold_count, 0);

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
    assert.match(beta2PublishWorkflow, /dry_run:\s*true/);
    assert.match(beta2PublishWorkflow, /dry_run:\s*false/);
    assert.match(beta2PublishWorkflow, /version:\s*1\.3\.0-beta\.2/);
    assert.match(beta2PublishWorkflow, /tags:\s*beta/);
});

test("stable promotion records fresh PR CI and latest dry-run evidence before publication", () => {
    assert.equal(
        stableReleaseGate.schema_version,
        "noderooms-stable-release-gate-v1",
    );
    assert.equal(stableReleaseGate.candidate.version, stableSourcePackage.version);
    assert.equal(
        stableReleaseGate.promotion.predecessor_version,
        "1.3.0-beta.2",
    );
    assert.equal(
        stableReleaseGate.promotion.predecessor_package_sha256,
        "909016696cbcc9931c535b05f77b644bc55e792432a8a611a5b3f810024d17a2",
    );
    assert.equal(stableReleaseGate.promotion.runtime_logic_changed, false);
    assert.equal(stableReleaseGate.promotion.target_channel, "latest");
    assert.equal(stableReleaseGate.status, "PASS");
    assert.equal(stableReleaseGate.publication_allowed, true);

    const blockers = stableReleaseGate.gates
        .filter((gate) => gate.blocking && gate.status !== "PASS")
        .map((gate) => [gate.id, gate.status]);
    assert.deepEqual(blockers, []);

    assert.equal(
        stableReleaseClosure.schema_version,
        "noderooms-stable-release-closure-v1",
    );
    assert.equal(stableReleaseClosure.candidate.pull_request, 16);
    assert.equal(
        stableReleaseClosure.candidate.validated_head_sha,
        "c6ad23c411082b4db85b313d923d678332a60538",
    );
    assert.equal(
        stableReleaseClosure.candidate.tested_merge_sha,
        "ee5767be359d3841280d50971ae34cc54d5cd0c9",
    );
    assert.equal(
        stableReleaseClosure.candidate.package_sha256,
        stableReleaseGate.candidate.package_sha256,
    );
    assert.equal(
        stableReleaseClosure.verified_predecessor.package_sha256,
        stableReleaseGate.promotion.predecessor_package_sha256,
    );
    assert.equal(stableReleaseClosure.runtime_delta.logic_changed, false);
    assert.equal(stableReleaseClosure.runtime_delta.tool_count_before, 14);
    assert.equal(stableReleaseClosure.runtime_delta.tool_count_after, 14);
    assert.equal(
        stableReleaseClosure.trusted_pr_validation.plugin_ci.status,
        "PASS",
    );
    assert.equal(
        stableReleaseClosure.trusted_pr_validation.plugin_ci.run_id,
        30497506980,
    );
    assert.equal(
        stableReleaseClosure.trusted_pr_validation.plugin_ci.tests,
        266,
    );
    assert.equal(
        stableReleaseClosure.trusted_pr_validation.plugin_ci.failures,
        0,
    );
    assert.equal(
        stableReleaseClosure.trusted_pr_validation.stable_latest_dry_run.status,
        "PASS",
    );
    assert.equal(
        stableReleaseClosure.trusted_pr_validation.stable_latest_dry_run.run_id,
        30497507384,
    );
    assert.equal(
        stableReleaseClosure.trusted_pr_validation.stable_latest_dry_run
            .dry_run,
        true,
    );
    assert.deepEqual(
        stableReleaseClosure.trusted_pr_validation.stable_latest_dry_run.tags,
        ["latest"],
    );
    assert.equal(
        stableReleaseClosure.trusted_pr_validation.stable_latest_dry_run
            .package_sha256_verified,
        true,
    );
    assert.equal(
        stableReleaseClosure.trusted_pr_validation.stable_latest_dry_run
            .plugin_inspector_breakages,
        0,
    );
    assert.equal(
        stableReleaseClosure.trusted_pr_validation.stable_latest_dry_run
            .plugin_inspector_warnings,
        0,
    );
    assert.equal(
        stableReleaseClosure.trusted_pr_validation.stable_latest_dry_run
            .publication_gate_job,
        "SKIPPED",
    );
    assert.equal(
        stableReleaseClosure.trusted_pr_validation.stable_latest_dry_run
            .publish_job,
        "SKIPPED",
    );
    assert.equal(stableReleaseClosure.publication_scope.channel, "latest");
    assert.equal(
        stableReleaseClosure.publication_scope.exact_confirmation,
        "PUBLISH 1.3.0 STABLE",
    );
    assert.equal(
        stableReleaseClosure.publication_scope.beta2_republication_allowed,
        false,
    );
    assert.equal(
        stableReleaseClosure.publication_scope.noderooms_production_change_in_scope,
        false,
    );
    assert.equal(
        stableReleaseClosure.publication_scope.final_owner_approval_required,
        true,
    );
    assert.equal(
        stableReleaseClosure.publication_scope.merge_attempted,
        false,
    );
    assert.equal(
        stableReleaseClosure.publication_scope.stable_publication_attempted,
        false,
    );
    assert.equal(
        stableReleaseClosure.publication_scope.latest_channel_modified,
        false,
    );
    assert.equal(
        stableReleaseClosure.publication_scope.noderooms_production_modified,
        false,
    );
    assert.equal(stableReleaseClosure.decision.status, "PASS");
    assert.equal(stableReleaseClosure.decision.blocking_gates_open, 0);
    assert.equal(stableReleaseClosure.decision.publication_allowed, true);
    assert.equal(stableReleaseClosure.decision.publication_completed, false);

    assert.match(
        stablePublishWorkflow,
        new RegExp(
            `RELEASE_PACKAGE_SHA256: ${stableReleaseGate.candidate.package_sha256}`,
        ),
    );
    assert.match(
        stablePublishWorkflow,
        /BETA2_PACKAGE_SHA256: 909016696cbcc9931c535b05f77b644bc55e792432a8a611a5b3f810024d17a2/,
    );
    assert.match(stablePublishWorkflow, /publication-gate:/);
    assert.match(
        stablePublishWorkflow,
        /test "\$RELEASE_CONFIRMATION" = "PUBLISH 1\.3\.0 STABLE"/,
    );
    assert.match(stablePublishWorkflow, /g\.status!=="PASS"/);
    assert.match(stablePublishWorkflow, /g\.publication_allowed!==true/);
    assert.match(stablePublishWorkflow, /dry_run:\s*true/);
    assert.match(stablePublishWorkflow, /dry_run:\s*false/);
    assert.match(stablePublishWorkflow, /version:\s*1\.3\.0/);
    assert.match(stablePublishWorkflow, /tags:\s*latest/);
    assert.match(
        stablePublishWorkflow,
        /STABLE_PACKAGED_RUNTIME_DELTA=PASS/,
    );
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

test("C001 Connector Beta foundation is packaged but disconnected and non-live", () => {
    assert.doesNotMatch(index, /connector-beta-foundation/);
    assert.doesNotMatch(index, /buildConnectorBetaFoundationV1/);
    assert.match(
        connectorBetaFoundation,
        /CONNECTOR_BETA_DEVELOPMENT_IDENTITY =\s*"1\.4\.0-alpha\.1-dev\.1"/,
    );
    assert.match(
        connectorBetaFoundation,
        /CONNECTOR_BETA_LIVE_CONNECTOR_USE_ALLOWED = false/,
    );
    assert.doesNotMatch(connectorBetaFoundation, /\bfetch\(/);
    assert.doesNotMatch(connectorBetaFoundation, /"tools\.invoke"/);
    assert.doesNotMatch(connectorBetaFoundation, /"tools\.catalog"/);
    assert.doesNotMatch(connectorBetaFoundation, /\.runTask\(/);
    assert.doesNotMatch(connectorBetaFoundation, /\.resume\(/);
    assert.doesNotMatch(connectorBetaFoundation, /child_process/);
});

test("C002 Email Read + Draft profile is packaged but disconnected and non-live", () => {
    assert.doesNotMatch(index, /email-read-draft-profile/);
    assert.doesNotMatch(index, /buildEmailReadDraftProfileV1/);
    assert.match(
        emailReadDraftProfile,
        /EMAIL_READ_DRAFT_DEVELOPMENT_IDENTITY =\s*"1\.4\.0-alpha\.2-dev\.1"/,
    );
    assert.match(
        emailReadDraftProfile,
        /EMAIL_READ_DRAFT_LIVE_USE_ALLOWED = false/,
    );
    assert.match(
        emailReadDraftProfile,
        /external_validation_pending/,
    );
    assert.doesNotMatch(emailReadDraftProfile, /\bfetch\(/);
    assert.doesNotMatch(emailReadDraftProfile, /"tools\.invoke"/);
    assert.doesNotMatch(emailReadDraftProfile, /"tools\.catalog"/);
    assert.doesNotMatch(emailReadDraftProfile, /\.runTask\(/);
    assert.doesNotMatch(emailReadDraftProfile, /\.resume\(/);
    assert.doesNotMatch(emailReadDraftProfile, /child_process/);
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
