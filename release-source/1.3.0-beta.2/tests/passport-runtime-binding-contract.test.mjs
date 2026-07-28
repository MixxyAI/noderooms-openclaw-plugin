import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFile } from "node:fs/promises";

import {
    evaluateRuntimeBinding,
    pairingChallengeFingerprint,
    runtimeKeyThumbprint,
    validateBindingSet,
    validateRecoveryRecord,
    validateRuntimeBindingRecord,
    verifyPairingAssertion,
} from "../src/passport-runtime-binding.js";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const schema = await readJson("contracts/agent-passport-runtime-binding-v1.schema.json");
const challenge = await readJson(
    "contracts/fixtures/openclaw-agent-passport.pairing-challenge-v1.json",
);
const assertion = await readJson(
    "contracts/fixtures/openclaw-agent-passport.pairing-assertion-v1.json",
);
const binding = await readJson(
    "contracts/fixtures/openclaw-agent-passport.runtime-binding-v1.json",
);
const recovery = await readJson(
    "contracts/fixtures/openclaw-agent-passport.runtime-recovery-v1.json",
);
const lease = await readJson("contracts/fixtures/github-draft-pr.run-lease-v2.json");

const PAIRING_NOW = Date.parse("2026-07-24T16:02:00Z");
const BINDING_NOW = Date.parse("2026-07-24T16:10:00Z");
const RECOVERY_NOW = Date.parse("2026-07-24T16:04:00Z");

function clone(value) {
    return structuredClone(value);
}

function runtimeContext(value = binding) {
    return {
        ...clone(value.runtime_binding),
        runtime_key_thumbprint: value.runtime_key.thumbprint_sha256,
    };
}

function activeBinding(value = binding) {
    const active = clone(value);
    active.fixture = false;
    active.activation_state = "active";
    return active;
}

function distinctBindingOnSameGateway() {
    const value = clone(binding);
    const { publicKey } = generateKeyPairSync("ed25519");
    const exported = publicKey.export({ format: "jwk" });
    const publicKeyJwk = { kty: exported.kty, crv: exported.crv, x: exported.x };
    value.binding_id = "nrbind_22222222222222222222222222222222";
    value.agent_binding.noderooms_agent_id = 43;
    value.agent_binding.passport_id = "NRP-000043-AGENT";
    value.agent_binding.owner_binding_id = "NRPB-DDDDDDDDDDDDDDDDDDDDDDDD";
    value.runtime_binding.runtime_instance_id = "ocruntime_22222222222222222222222222222222";
    value.runtime_binding.openclaw_agent_id = "agent-example-openclaw-two";
    value.runtime_key.public_key_jwk = publicKeyJwk;
    value.runtime_key.thumbprint_sha256 = runtimeKeyThumbprint(publicKeyJwk);
    value.proof.binding_request_id = "nrbreq_22222222222222222222222222222222";
    value.proof.challenge_id = "nrbch_22222222222222222222222222222222";
    value.proof.assertion_id = "nrbassert_22222222222222222222222222222222";
    value.proof.challenge_fingerprint_sha256 = `sha256:${"2".repeat(64)}`;
    return value;
}

test("002B schema declares strict challenge, assertion, binding, and recovery contracts", () => {
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.oneOf.length, 4);
    for (const key of ["pairingChallenge", "pairingAssertion", "runtimeBinding", "runtimeRecovery"]) {
        assert.equal(schema.$defs[key].additionalProperties, false);
    }
    assert.equal(
        schema.$defs.runtimeBinding.properties.live_enforce_allowed.const,
        false,
    );
    assert.equal(
        schema.$defs.runtimeBinding.properties.constraints.properties.shared_run_secret_allowed.const,
        false,
    );
    assert.equal(
        schema.$defs.runtimeBinding.properties.constraints.properties.shared_lease_allowed.const,
        false,
    );
});

test("one-use pairing fixture has an exact fingerprint and a valid Ed25519 assertion", () => {
    assert.equal(
        pairingChallengeFingerprint(challenge),
        challenge.challenge_fingerprint_sha256,
    );
    assert.equal(
        runtimeKeyThumbprint(challenge.runtime_public_key_jwk),
        challenge.runtime_key_thumbprint,
    );
    const verified = verifyPairingAssertion({
        challenge,
        assertion,
        now: PAIRING_NOW,
        allowFixture: true,
    });
    assert.equal(verified.verified, true);
    assert.equal(verified.atomic_challenge_consumption_required, true);
    assert.equal(verified.challenge_id, challenge.challenge_id);
});

test("live verification rejects fixtures by default", () => {
    assert.throws(
        () => verifyPairingAssertion({ challenge, assertion, now: PAIRING_NOW }),
        (error) => error.code === "FIXTURE_REJECTED",
    );
    assert.throws(
        () => validateRuntimeBindingRecord(binding, { now: BINDING_NOW }),
        (error) => error.code === "FIXTURE_REJECTED",
    );
});

test("pairing fails closed on replay, expiry, identity drift, fingerprint drift, and signature tampering", () => {
    const cases = [
        (nextChallenge) => {
            nextChallenge.state = "consumed";
            nextChallenge.consumed_at = "2026-07-24T16:01:30Z";
        },
        (nextChallenge, _nextAssertion, options) => {
            options.now = Date.parse("2026-07-24T16:05:00Z");
        },
        (_nextChallenge, nextAssertion) => {
            nextAssertion.runtime_binding.openclaw_agent_id = "agent-other";
        },
        (nextChallenge) => {
            nextChallenge.nonce = "A".repeat(43);
        },
        (_nextChallenge, nextAssertion) => {
            nextAssertion.signature_base64url = `A${nextAssertion.signature_base64url.slice(1)}`;
        },
    ];
    for (const mutate of cases) {
        const nextChallenge = clone(challenge);
        const nextAssertion = clone(assertion);
        const options = { now: PAIRING_NOW };
        mutate(nextChallenge, nextAssertion, options);
        assert.throws(() => verifyPairingAssertion({
            challenge: nextChallenge,
            assertion: nextAssertion,
            now: options.now,
            allowFixture: true,
        }));
    }
});

test("contract-only binding matches exactly but cannot authorize live enforcement", () => {
    const decision = evaluateRuntimeBinding({
        binding,
        expectedAgentBinding: clone(binding.agent_binding),
        runtimeContext: runtimeContext(),
        now: BINDING_NOW,
        allowFixture: true,
        allowContractOnly: true,
    });
    assert.equal(decision.decision, "contract_match_not_authorized");
    assert.equal(decision.reason_code, "LIVE_ENFORCE_PROHIBITED");

    const defaultDecision = evaluateRuntimeBinding({
        binding,
        expectedAgentBinding: clone(binding.agent_binding),
        runtimeContext: runtimeContext(),
        now: BINDING_NOW,
    });
    assert.equal(defaultDecision.decision, "block_invalid_binding");
    assert.equal(defaultDecision.reason_code, "FIXTURE_REJECTED");
});

test("active binding evaluator requires exact Gateway, runtime instance, and OpenClaw Agent", () => {
    const active = activeBinding();
    assert.equal(evaluateRuntimeBinding({
        binding: active,
        expectedAgentBinding: clone(active.agent_binding),
        runtimeContext: runtimeContext(active),
        now: BINDING_NOW,
    }).decision, "binding_match");

    for (const [field, value] of [
        ["gateway_id", "ocgw_11111111111111111111111111111111"],
        ["runtime_instance_id", "ocruntime_11111111111111111111111111111111"],
        ["openclaw_agent_id", "agent-other"],
        ["runtime_key_thumbprint", `sha256:${"1".repeat(64)}`],
    ]) {
        const context = runtimeContext(active);
        context[field] = value;
        const decision = evaluateRuntimeBinding({
            binding: active,
            expectedAgentBinding: clone(active.agent_binding),
            runtimeContext: context,
            now: BINDING_NOW,
        });
        assert.equal(decision.decision, "block_runtime_mismatch");
    }
});

test("binding validation blocks Owner, Passport, key, expiry, and revocation drift", () => {
    const cases = [
        (value) => { value.agent_binding.passport_id = "NRP-000043-AGENT"; },
        (value) => { value.agent_binding.owner_binding_id = "NRPB-DDDDDDDDDDDDDDDDDDDDDDDD"; },
        (value) => { value.runtime_key.thumbprint_sha256 = `sha256:${"0".repeat(64)}`; },
        (value) => { value.lifecycle.expires_at = "2026-07-24T16:09:00Z"; },
        (value) => {
            value.activation_state = "revoked";
            value.lifecycle.status = "revoked";
            value.lifecycle.revoked_at = "2026-07-24T16:09:00Z";
            value.lifecycle.revocation_reason = "owner_revoked";
        },
    ];
    for (const mutate of cases) {
        const value = activeBinding();
        mutate(value);
        const decision = evaluateRuntimeBinding({
            binding: value,
            expectedAgentBinding: clone(binding.agent_binding),
            runtimeContext: runtimeContext(value),
            now: BINDING_NOW,
        });
        assert.notEqual(decision.decision, "binding_match");
    }
});

test("one Gateway may host multiple Agents only with isolated runtime and key authority", () => {
    const second = distinctBindingOnSameGateway();
    const result = validateBindingSet([binding, second], {
        allowFixture: true,
        allowContractOnly: true,
        now: BINDING_NOW,
    });
    assert.equal(result.binding_count, 2);
    assert.equal(result.gateway_count, 1);
    assert.equal(result.multi_agent_gateway_safe, true);
    assert.equal(result.shared_run_secret_allowed, false);
    assert.equal(result.shared_lease_allowed, false);

    const sharedKey = distinctBindingOnSameGateway();
    sharedKey.runtime_key = clone(binding.runtime_key);
    assert.throws(
        () => validateBindingSet([binding, sharedKey], {
            allowFixture: true,
            allowContractOnly: true,
            now: BINDING_NOW,
        }),
        (error) => error.code === "SHARED_RUNTIME_KEY",
    );

    const sharedProof = distinctBindingOnSameGateway();
    sharedProof.proof = clone(binding.proof);
    assert.throws(
        () => validateBindingSet([binding, sharedProof], {
            allowFixture: true,
            allowContractOnly: true,
            now: BINDING_NOW,
        }),
        (error) => error.code === "SHARED_PAIRING_PROOF",
    );
});

test("runtime reinstall recovery preserves Agent and Passport but reuses no binding, key, lease, or run secret", () => {
    validateRecoveryRecord(recovery, {
        allowFixture: true,
        now: RECOVERY_NOW,
    });
    assert.equal(recovery.passport_continuity.noderooms_agent_id_preserved, true);
    assert.equal(recovery.passport_continuity.passport_id_preserved, true);
    assert.equal(recovery.lease_transition.previous_lease_reused, false);
    assert.equal(recovery.lease_transition.previous_run_secret_reused, false);
    assert.equal(recovery.lease_transition.new_lease_required, true);

    for (const mutate of [
        (value) => { value.owner_revalidation.decision = "denied"; },
        (value) => {
            value.replacement_binding.runtime_key_thumbprint =
                value.previous_binding.runtime_key_thumbprint;
        },
        (value) => { value.lease_transition.previous_run_secret_reused = true; },
    ]) {
        const value = clone(recovery);
        mutate(value);
        assert.throws(() => validateRecoveryRecord(value, {
            allowFixture: true,
            now: RECOVERY_NOW,
        }));
    }
});

test("run lease v2 is cross-bound to the exact 002B binding authority", () => {
    assert.deepEqual(lease.agent_binding, binding.agent_binding);
    assert.equal(lease.runtime_binding.binding_id, binding.binding_id);
    for (const field of ["platform", "gateway_id", "runtime_instance_id", "openclaw_agent_id"]) {
        assert.equal(lease.runtime_binding[field], binding.runtime_binding[field]);
    }
    assert.equal(
        lease.runtime_binding.runtime_key_thumbprint,
        binding.runtime_key.thumbprint_sha256,
    );
});

test("002B validator is packaged but disconnected from live hooks and live enforce stays prohibited", async () => {
    const index = await readFile(new URL("../src/index.js", import.meta.url), "utf8");
    const manifest = await readJson("openclaw.plugin.json");
    assert.doesNotMatch(index, /passport-runtime-binding/);
    assert.deepEqual(
        manifest.configSchema.properties.trustLayer.properties.mode.enum,
        ["off", "observe"],
    );
    assert.equal(
        binding.live_enforce_allowed,
        false,
    );
});
