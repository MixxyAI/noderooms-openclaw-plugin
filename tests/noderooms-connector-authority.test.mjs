import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
    NODEROOMS_CONNECTOR_AUTHORITY_CONTRACT_VERSION,
    NODEROOMS_CONNECTOR_JOB_SCOPES,
    NodeRoomsConnectorAuthorityError,
    noderoomsConnectorActionFingerprint,
    validateNodeRoomsConnectorJobAuthority,
} from "../src/noderooms-connector-authority.js";

const NOW = Date.parse("2026-08-02T03:00:00.000Z");
const ISSUED_AT = "2026-08-02T02:55:00.000Z";
const EXPIRES_AT = "2026-08-02T03:10:00.000Z";
const JOB_ID = `nrtbj_${"1".repeat(32)}`;
const AGENT_SLUG = "agent-zsolt";
const PASSPORT_ID = "nrpass_agent_zsolt_2026";
const OWNER_BINDING_ID = "nrownbind_agent_zsolt_2026";
const CAPABILITY_ID = "nrcap_gmail_exact_job_2026";
const RUN_LEASE_ID = "nrlease_gmail_exact_job_2026";
const PURPOSE_ID = "nrpurpose_owner_mail_automation_2026";

function sha256(value) {
    return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function expectation(jobType = "gmail_search", payload = "{}") {
    return {
        jobId: JOB_ID,
        jobType,
        payloadSha256: sha256(payload),
        agentSlug: AGENT_SLUG,
        passportPublicId: PASSPORT_ID,
        ownerBindingId: OWNER_BINDING_ID,
        provider: "gmail",
        accountBindingSha256: sha256("owner@example.invalid"),
        targetFingerprintSha256: sha256(`${jobType}\n${payload}`),
        scope: NODEROOMS_CONNECTOR_JOB_SCOPES[jobType],
        draftIdSha256: jobType === "gmail_send_approved_draft"
            ? sha256("draft-owner-approved-1")
            : null,
        nowMs: NOW,
    };
}

function authority(expected) {
    const capability = {
        capability_id: CAPABILITY_ID,
        status: "active",
        decision: "allow",
        decision_source: "verified_human_owner",
        automated: false,
        agent_slug: AGENT_SLUG,
        owner_binding_id: OWNER_BINDING_ID,
        passport_public_id: PASSPORT_ID,
        provider: "gmail",
        account_binding_sha256: expected.accountBindingSha256,
        target_fingerprint_sha256: expected.targetFingerprintSha256,
        scope: expected.scope,
        purpose_id: PURPOSE_ID,
        purpose_sha256: sha256("NodeRooms owner mail automation"),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
    };
    const runLease = {
        run_lease_id: RUN_LEASE_ID,
        status: "active",
        capability_id: CAPABILITY_ID,
        agent_slug: AGENT_SLUG,
        owner_binding_id: OWNER_BINDING_ID,
        passport_public_id: PASSPORT_ID,
        provider: "gmail",
        account_binding_sha256: expected.accountBindingSha256,
        target_fingerprint_sha256: expected.targetFingerprintSha256,
        scope: expected.scope,
        purpose_id: PURPOSE_ID,
        purpose_sha256: capability.purpose_sha256,
        remaining_actions: 1,
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
    };
    const actionApproval = expected.jobType
        === "gmail_send_approved_draft"
        ? {
            policy: "allow_once",
            status: "approved",
            decision_source: "verified_human_owner",
            automated: false,
            owner_binding_id: OWNER_BINDING_ID,
            approval_receipt_id: "nrapproval_gmail_draft_send_2026",
            dispatch_reservation_id: "nrdispatch_gmail_draft_send_2026",
            draft_id_sha256: expected.draftIdSha256,
            action_fingerprint_sha256:
                noderoomsConnectorActionFingerprint({
                    jobId: expected.jobId,
                    jobType: expected.jobType,
                    payloadSha256: expected.payloadSha256,
                    agentSlug: AGENT_SLUG,
                    passportPublicId: PASSPORT_ID,
                    ownerBindingId: OWNER_BINDING_ID,
                    capabilityId: CAPABILITY_ID,
                    runLeaseId: RUN_LEASE_ID,
                    provider: "gmail",
                    accountBindingSha256:
                        expected.accountBindingSha256,
                    targetFingerprintSha256:
                        expected.targetFingerprintSha256,
                    scope: expected.scope,
                    purposeId: PURPOSE_ID,
                    purposeSha256: capability.purpose_sha256,
                    draftIdSha256: expected.draftIdSha256,
                }),
            provider_attempt_max: 1,
            automatic_retry_allowed: false,
            expires_at: "2026-08-02T03:05:00.000Z",
        }
        : null;
    return {
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
            slug: AGENT_SLUG,
            owner_binding_id: OWNER_BINDING_ID,
            owner_binding_status: "verified",
            passport_public_id: PASSPORT_ID,
            passport_status: "active",
        },
        capability,
        run_lease: runLease,
        action_approval: actionApproval,
        job_binding: {
            job_id: expected.jobId,
            job_type: expected.jobType,
            payload_sha256: expected.payloadSha256,
        },
    };
}

function expectCode(code) {
    return (error) =>
        error instanceof NodeRoomsConnectorAuthorityError
        && error.code === code;
}

test("the canonical product contract keeps every user surface in NodeRooms", () => {
    const expected = expectation();
    const validated = validateNodeRoomsConnectorJobAuthority(
        authority(expected),
        expected,
    );
    assert.equal(validated.scope, "connector.gmail.message.search");
    assert.equal(validated.ownerBindingId, OWNER_BINDING_ID);
    assert.equal(validated.capabilityId, CAPABILITY_ID);
    assert.equal(validated.runLeaseId, RUN_LEASE_ID);
    assert.equal(validated.actionApproval, null);
});

test("a non-NodeRooms user surface or visible runtime is a hard deny", () => {
    const expected = expectation();
    const wrongSurface = authority(expected);
    wrongSurface.surfaces.connector_setup = "openclaw";
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(
            wrongSurface,
            expected,
        ),
        expectCode("NODEROOMS_PRODUCT_SURFACE_REQUIRED"),
    );

    const visibleRuntime = authority(expected);
    visibleRuntime.runtime.user_visible = true;
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(
            visibleRuntime,
            expected,
        ),
        expectCode("NODEROOMS_RUNTIME_BOUNDARY_REQUIRED"),
    );
});

test("missing or inactive Owner binding and Passport hard-deny immediately", () => {
    const expected = expectation();
    const missingOwner = authority(expected);
    delete missingOwner.agent.owner_binding_id;
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(
            missingOwner,
            expected,
        ),
        expectCode("NODEROOMS_OWNER_BINDING_REQUIRED"),
    );

    const inactiveOwner = authority(expected);
    inactiveOwner.agent.owner_binding_status = "revoked";
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(
            inactiveOwner,
            expected,
        ),
        expectCode("NODEROOMS_OWNER_BINDING_REQUIRED"),
    );

    const inactivePassport = authority(expected);
    inactivePassport.agent.passport_status = "revoked";
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(
            inactivePassport,
            expected,
        ),
        expectCode("NODEROOMS_PASSPORT_REQUIRED"),
    );
});

test("missing, automated, expired, or cross-purpose capability hard-denies", () => {
    const expected = expectation();
    const missing = authority(expected);
    delete missing.capability;
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(missing, expected),
        expectCode("NODEROOMS_CAPABILITY_REQUIRED"),
    );

    const automated = authority(expected);
    automated.capability.automated = true;
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(automated, expected),
        expectCode("NODEROOMS_CAPABILITY_REQUIRED"),
    );

    const expired = authority(expected);
    expired.capability.expires_at = "2026-08-02T02:59:59.000Z";
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(expired, expected),
        expectCode("NODEROOMS_CAPABILITY_REQUIRED"),
    );

    const crossPurpose = authority(expected);
    crossPurpose.run_lease.purpose_id = "nrpurpose_other_2026";
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(
            crossPurpose,
            expected,
        ),
        expectCode("NODEROOMS_CONNECTOR_AUTHORITY_MISMATCH"),
    );
});

test("missing, exhausted, expired, or cross-account scoped lease hard-denies", () => {
    const expected = expectation();
    const missing = authority(expected);
    delete missing.run_lease;
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(missing, expected),
        expectCode("NODEROOMS_RUN_LEASE_REQUIRED"),
    );

    const exhausted = authority(expected);
    exhausted.run_lease.remaining_actions = 0;
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(exhausted, expected),
        expectCode("NODEROOMS_RUN_LEASE_REQUIRED"),
    );

    const expired = authority(expected);
    expired.run_lease.expires_at = "2026-08-02T02:59:59.000Z";
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(expired, expected),
        expectCode("NODEROOMS_RUN_LEASE_REQUIRED"),
    );

    const crossAccount = authority(expected);
    crossAccount.run_lease.account_binding_sha256 = sha256("other@example.invalid");
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(
            crossAccount,
            expected,
        ),
        expectCode("NODEROOMS_CONNECTOR_AUTHORITY_MISMATCH"),
    );
});

test("send accepts only an exact draft-bound one-use Owner approval", () => {
    const payload = JSON.stringify({
        account_email: "owner@example.invalid",
        draft_id: "draft-owner-approved-1",
    });
    const expected = expectation(
        "gmail_send_approved_draft",
        payload,
    );
    const validated = validateNodeRoomsConnectorJobAuthority(
        authority(expected),
        expected,
    );
    assert.equal(validated.actionApproval.policy, "allow_once");
    assert.equal(validated.actionApproval.provider_attempt_max, 1);
    assert.equal(
        validated.actionApproval.automatic_retry_allowed,
        false,
    );

    const missing = authority(expected);
    missing.action_approval = null;
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(missing, expected),
        expectCode("NODEROOMS_SEND_APPROVAL_REQUIRED"),
    );

    const draftDrift = authority(expected);
    draftDrift.action_approval.draft_id_sha256 = sha256("another-draft");
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(
            draftDrift,
            expected,
        ),
        expectCode("NODEROOMS_SEND_APPROVAL_REQUIRED"),
    );

    const retryExpansion = authority(expected);
    retryExpansion.action_approval.provider_attempt_max = 2;
    assert.throws(
        () => validateNodeRoomsConnectorJobAuthority(
            retryExpansion,
            expected,
        ),
        expectCode("NODEROOMS_SEND_APPROVAL_REQUIRED"),
    );
});

test("job, Agent, Passport, scope, and payload cross-binding cannot drift", () => {
    const expected = expectation();
    for (const mutate of [
        (value) => { value.agent.slug = "another-agent"; },
        (value) => { value.capability.passport_public_id = "nrpass_other_2026"; },
        (value) => { value.capability.scope = "connector.gmail.thread.read"; },
        (value) => { value.job_binding.payload_sha256 = sha256("drift"); },
    ]) {
        const value = authority(expected);
        mutate(value);
        assert.throws(
            () => validateNodeRoomsConnectorJobAuthority(value, expected),
            expectCode("NODEROOMS_CONNECTOR_AUTHORITY_MISMATCH"),
        );
    }
});
