import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
    GMAIL_TRUSTBRIDGE_SUPPORTED_JOB_TYPES,
} from "../src/gmail-trustbridge-worker.js";

const readText = (path) => readFile(new URL(`../${path}`, import.meta.url), "utf8");
const [
    contract,
    manifest,
    pluginIndex,
    workerSource,
    providerSource,
    readme,
    adr,
] =
    await Promise.all([
        readText("contracts/reference/noderooms-product-surface.v1.json")
            .then(JSON.parse),
        readText("openclaw.plugin.json").then(JSON.parse),
        readText("src/index.js"),
        readText("src/gmail-trustbridge-worker.js"),
        readText("src/gmail-gog-provider.js"),
        readText("README.md"),
        readText("docs/adr/C004-noderooms-only-product-surface.md"),
    ]);

test("the canonical contract makes NodeRooms the only user product surface", () => {
    assert.equal(contract.contract_version, "noderooms-product-surface.v1");
    assert.equal(contract.user_product, "noderooms");
    assert.equal(contract.registration_surface, "noderooms");
    assert.equal(contract.work_surface, "noderooms");
    assert.equal(contract.connector_setup.surface, "noderooms");
    assert.deepEqual(
        contract.connector_setup.initial_connector_families,
        ["gmail", "whatsapp", "discord"],
    );
    assert.equal(contract.connector_setup.runtime_setup_exposed_to_user, false);
    assert.deepEqual(contract.noderooms_surfaces, {
        operations: true,
        automations: true,
        approvals: true,
        results: true,
    });
});

test("OpenClaw is recorded only as invisible background infrastructure", () => {
    assert.equal(contract.runtime.internal_provider, "openclaw");
    assert.equal(contract.runtime.role, "background_infrastructure");
    for (const field of [
        "user_visible",
        "user_cli_allowed",
        "user_install_allowed",
        "user_plugin_allowed",
        "user_branding_allowed",
    ]) {
        assert.equal(contract.runtime[field], false, field);
    }
    assert.match(readme, /NodeRooms is the only user product surface/);
    assert.match(adr, /user registers only in NodeRooms/);
});

test("missing Owner binding, Passport, capability, or lease is a machine-readable hard deny", () => {
    assert.equal(contract.hard_deny.missing_owner_binding, true);
    assert.equal(contract.hard_deny.invalid_owner_binding, true);
    assert.equal(contract.hard_deny.missing_passport, true);
    assert.equal(contract.hard_deny.invalid_passport, true);
    assert.equal(contract.hard_deny.missing_capability, true);
    assert.equal(
        contract.hard_deny.expired_or_mismatched_capability,
        true,
    );
    assert.equal(contract.hard_deny.missing_run_lease, true);
    assert.equal(
        contract.hard_deny.expired_exhausted_or_mismatched_run_lease,
        true,
    );
});

test("Gmail is a background service, never a model-visible Gmail tool", () => {
    assert.match(pluginIndex, /registerGmailTrustBridgeWorkerService/);
    assert.doesNotMatch(pluginIndex, /registerGmailGogTools/);
    assert.doesNotMatch(pluginIndex, /GmailTrustBridgePilotController/);
    assert.equal(
        manifest.contracts.tools.some((name) => name.startsWith("gmail_")),
        false,
    );
    assert.equal(
        manifest.contracts.tools.every((name) => name.startsWith("noderooms_")),
        true,
    );
    assert.doesNotMatch(providerSource, /registerGmailGogTools/);
    assert.doesNotMatch(providerSource, /class GmailGogProvider\s*\{/);
    assert.doesNotMatch(providerSource, /gmail_create_draft|gmail_send_email/);
});

test("the exact Gmail surface includes approved-draft send and no delete route", () => {
    assert.deepEqual(
        contract.gmail_initial_job_surface.allowed,
        GMAIL_TRUSTBRIDGE_SUPPORTED_JOB_TYPES,
    );
    assert.equal(
        contract.gmail_initial_job_surface.send_policy,
        "exact_draft_allow_once_verified_owner_approval",
    );
    assert.equal(contract.gmail_initial_job_surface.automatic_provider_retry, false);
    assert.equal(contract.gmail_initial_job_surface.delete, "prohibited");
    assert.equal(contract.gmail_initial_job_surface.trash, "prohibited");
    assert.equal(
        GMAIL_TRUSTBRIDGE_SUPPORTED_JOB_TYPES.some(
            (name) => /delete|trash|archive|label|forward|batch/.test(name),
        ),
        false,
    );
    assert.doesNotMatch(
        workerSource,
        /gmail\.(?:drafts\.delete|trash|batch\.delete|batch\.modify)/,
    );
});
