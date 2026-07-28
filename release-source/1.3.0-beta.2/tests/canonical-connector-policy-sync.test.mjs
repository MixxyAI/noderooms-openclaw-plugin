import test from "node:test";
import assert from "node:assert/strict";
import {
    generateKeyPairSync,
    sign,
} from "node:crypto";
import { readFile } from "node:fs/promises";

import {
    canonicalPolicyBundleFingerprint,
    canonicalPolicyBundleSignaturePayload,
    canonicalPolicyCheckpointFingerprint,
    CanonicalConnectorPolicySyncController,
    CanonicalConnectorPolicySyncError,
    createCanonicalPolicySyncCheckpointV1,
    createInMemoryCanonicalPolicyCheckpointStore,
    validateCanonicalConnectorPolicyBundleV1,
    validateCanonicalPolicySyncCheckpointV1,
    validateCanonicalPolicyTrustAnchorV1,
} from "../src/canonical-connector-policy-sync.js";
import {
    sha256Fingerprint,
} from "../src/passport-runtime-binding.js";
import {
    buildRuntimeToolInventoryV1,
    descriptorsFromOpenClawCatalog,
} from "../src/universal-connector-engine.js";
import {
    buildCanonicalConnectorPolicySyncProof,
} from "../scripts/canonical-connector-policy-sync-proof.mjs";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

const [
    bundleSchema,
    anchorSchema,
    checkpointSchema,
    trustAnchor,
    bundle,
    checkpointFixture,
    descriptorFixture,
    catalogFixture,
] = await Promise.all([
    readJson("contracts/canonical-connector-policy-bundle-v1.schema.json"),
    readJson("contracts/canonical-policy-trust-anchor-v1.schema.json"),
    readJson("contracts/canonical-policy-sync-checkpoint-v1.schema.json"),
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
        + "github-draft-pr.policy-sync-checkpoint-v1.json",
    ),
    readJson(
        "contracts/fixtures/"
        + "github-draft-pr.runtime-tool-descriptor-v1.json",
    ),
    readJson(
        "contracts/fixtures/"
        + "openclaw-tools-catalog.schema-unavailable-v1.json",
    ),
]);

const NOW = Date.parse("2026-07-25T13:15:00.000Z");

function clone(value) {
    return structuredClone(value);
}

function expectCode(code, operation) {
    assert.throws(
        operation,
        (error) =>
            error instanceof CanonicalConnectorPolicySyncError
            && error.code === code,
    );
}

function sourceFor(value, calls = []) {
    return {
        async read(request) {
            calls.push(clone(request));
            return clone(value);
        },
    };
}

function exactInventory(registry = bundle.registry) {
    return buildRuntimeToolInventoryV1({
        captured_at: descriptorFixture.captured_at,
        refresh_reason: descriptorFixture.refresh_reason,
        inventory_generation: descriptorFixture.inventory_generation,
        source: clone(descriptorFixture.source),
        tools: clone(descriptorFixture.tools),
        registry: clone(registry),
    });
}

function ephemeralSignedPolicy({
    sequence,
    previousFingerprint = null,
    sequenceTag,
}) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeyJwk = publicKey.export({ format: "jwk" });
    const keyThumbprint = sha256Fingerprint({
        crv: publicKeyJwk.crv,
        kty: publicKeyJwk.kty,
        x: publicKeyJwk.x,
    });
    const anchor = {
        contract_version:
            "noderooms-canonical-policy-trust-anchor-v1",
        fixture: true,
        activation_state: "contract_only",
        canonical_origin: "https://noderooms.com",
        key_id: `nrpk_ephemeral_${sequenceTag}`,
        algorithm: "Ed25519",
        public_key_jwk: publicKeyJwk,
        key_thumbprint_sha256: keyThumbprint,
        valid_from: "2026-01-01T00:00:00.000Z",
        valid_until: "2027-01-01T00:00:00.000Z",
    };
    const value = {
        contract_version:
            "noderooms-canonical-connector-policy-bundle-v1",
        fixture: true,
        activation_state: "contract_only",
        live_policy_sync_allowed: false,
        live_enforce_allowed: false,
        bundle_id: `nrpolicy_${sequence.toString(16).padStart(32, "0")}`,
        sequence,
        canonical_source: {
            origin: "https://noderooms.com",
            path: "/.well-known/noderooms/connector-policy-v1.json",
            transport: "contract_fixture",
            redirects_allowed: false,
        },
        issued_at: "2026-07-25T13:00:00.000Z",
        not_before: "2026-07-25T13:00:00.000Z",
        expires_at: "2026-07-25T14:00:00.000Z",
        previous_bundle_fingerprint_sha256: previousFingerprint,
        registry: clone(bundle.registry),
        registry_fingerprint_sha256:
            bundle.registry_fingerprint_sha256,
        runtime_tool_bindings:
            clone(bundle.runtime_tool_bindings),
        safety: clone(bundle.safety),
    };
    value.bundle_fingerprint_sha256 =
        canonicalPolicyBundleFingerprint(value);
    value.attestation = {
        key_id: anchor.key_id,
        algorithm: "Ed25519",
        key_thumbprint_sha256: keyThumbprint,
        signed_at: "2026-07-25T13:00:01.000Z",
        signature_base64url: "",
    };
    value.attestation.signature_base64url = sign(
        null,
        Buffer.from(
            canonicalPolicyBundleSignaturePayload(value),
            "utf8",
        ),
        privateKey,
    ).toString("base64url");
    return { anchor, bundle: value };
}

test("004B schemas freeze contract-only sync and zero execution authority", () => {
    assert.equal(
        bundleSchema.properties.contract_version.const,
        "noderooms-canonical-connector-policy-bundle-v1",
    );
    assert.equal(bundleSchema.properties.fixture.const, true);
    assert.equal(
        bundleSchema.properties.live_policy_sync_allowed.const,
        false,
    );
    assert.equal(
        bundleSchema.properties.live_enforce_allowed.const,
        false,
    );
    assert.equal(
        bundleSchema.properties.runtime_tool_bindings.items
            .properties.owner.properties.resolution.const,
        "exact",
    );
    for (const key of [
        "grants_tool_authority",
        "grants_connector_execution_authority",
        "performs_network_request",
        "invokes_connector",
        "performs_external_write",
        "automates_owner_decision",
        "persists_provider_credentials",
    ]) {
        assert.equal(
            bundleSchema.properties.safety.properties[key].const,
            false,
        );
    }
    assert.equal(
        anchorSchema.properties.canonical_origin.const,
        "https://noderooms.com",
    );
    assert.equal(
        checkpointSchema.properties.canonical_origin.const,
        "https://noderooms.com",
    );
});

test("external fixture trust anchor validates only with explicit fixture opt-in", () => {
    const validated = validateCanonicalPolicyTrustAnchorV1(
        trustAnchor,
        { allowFixture: true, now: NOW },
    );
    assert.equal(
        validated.key_thumbprint_sha256,
        bundle.attestation.key_thumbprint_sha256,
    );
    expectCode(
        "POLICY_FIXTURE_REJECTED",
        () => validateCanonicalPolicyTrustAnchorV1(
            trustAnchor,
            { now: NOW },
        ),
    );
});

test("signed canonical policy bundle binds the exact registry and trust anchor", () => {
    const validated = validateCanonicalConnectorPolicyBundleV1(
        bundle,
        {
            trustAnchor,
            allowFixture: true,
            now: NOW,
        },
    );
    assert.equal(
        validated.bundle_fingerprint_sha256,
        canonicalPolicyBundleFingerprint(validated),
    );
    assert.equal(
        validated.registry_fingerprint_sha256,
        sha256Fingerprint(validated.registry),
    );
    assert.equal(validated.registry.profiles.length, 1);
    assert.equal(
        validated.registry.profiles[0].scope,
        "connector.github.pull_request.draft",
    );
    assert.equal(validated.registry.profiles[0].status, "reference_only");
});

test("active policy, wildcard scope, unsafe approval, and schema drift fail closed", () => {
    const active = clone(bundle);
    active.registry.activation_state = "active";
    expectCode(
        "POLICY_LIVE_AUTHORITY_FORBIDDEN",
        () => validateCanonicalConnectorPolicyBundleV1(active, {
            trustAnchor,
            allowFixture: true,
            now: NOW,
        }),
    );

    const wildcard = clone(bundle);
    wildcard.registry.profiles[0].scope =
        "connector.github.pull_request.*";
    expectCode(
        "POLICY_CONTRACT_INVALID",
        () => validateCanonicalConnectorPolicyBundleV1(wildcard, {
            trustAnchor,
            allowFixture: true,
            now: NOW,
        }),
    );

    const approval = clone(bundle);
    approval.registry.profiles[0].approval_policy = "none";
    expectCode(
        "POLICY_APPROVAL_INVALID",
        () => validateCanonicalConnectorPolicyBundleV1(approval, {
            trustAnchor,
            allowFixture: true,
            now: NOW,
        }),
    );

    const schemaDrift = clone(bundle);
    schemaDrift.registry.profiles[0]
        .tool_input_schema.properties.title.maxLength = 257;
    expectCode(
        "POLICY_SCHEMA_DRIFT",
        () => validateCanonicalConnectorPolicyBundleV1(schemaDrift, {
            trustAnchor,
            allowFixture: true,
            now: NOW,
        }),
    );

    const optionalResource = clone(bundle);
    optionalResource.registry.profiles[0]
        .tool_input_schema.required =
            optionalResource.registry.profiles[0]
                .tool_input_schema.required.filter(
                    (name) => name !== "base_ref",
                );
    optionalResource.registry.profiles[0]
        .tool_schema_fingerprint = sha256Fingerprint(
            optionalResource.registry.profiles[0].tool_input_schema,
        );
    expectCode(
        "POLICY_RESOURCE_INVALID",
        () => validateCanonicalConnectorPolicyBundleV1(
            optionalResource,
            {
                trustAnchor,
                allowFixture: true,
                now: NOW,
            },
        ),
    );
});

test("origin, expiry, registry fingerprint, signature, and key drift fail closed", () => {
    const cases = [
        [
            "POLICY_SOURCE_INVALID",
            (value) => {
                value.canonical_source.origin = "https://example.com";
            },
            trustAnchor,
            NOW,
        ],
        [
            "POLICY_BUNDLE_EXPIRED",
            () => {},
            trustAnchor,
            Date.parse("2026-07-25T14:00:00.000Z"),
        ],
        [
            "POLICY_REGISTRY_FINGERPRINT_DRIFT",
            (value) => {
                value.registry_fingerprint_sha256 =
                    `sha256:${"a".repeat(64)}`;
            },
            trustAnchor,
            NOW,
        ],
        [
            "POLICY_SIGNATURE_INVALID",
            (value) => {
                value.attestation.signature_base64url =
                    `${value.attestation.signature_base64url.slice(0, -1)}A`;
            },
            trustAnchor,
            NOW,
        ],
        [
            "POLICY_ATTESTATION_TRUST_MISMATCH",
            (value) => {
                value.attestation.key_id =
                    "nrpk_another_contract_key";
            },
            trustAnchor,
            NOW,
        ],
    ];
    for (const [code, mutate, anchor, now] of cases) {
        const value = clone(bundle);
        mutate(value);
        expectCode(
            code,
            () => validateCanonicalConnectorPolicyBundleV1(value, {
                trustAnchor: anchor,
                allowFixture: true,
                now,
            }),
        );
    }
});

test("sync requests one exact read-only source operation and stores one checkpoint", async () => {
    const calls = [];
    let compareAndSetCount = 0;
    const baseStore = createInMemoryCanonicalPolicyCheckpointStore();
    const store = {
        load: () => baseStore.load(),
        async compareAndSet(expected, next) {
            compareAndSetCount += 1;
            return baseStore.compareAndSet(expected, next);
        },
    };
    const controller = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle, calls),
        checkpointStore: store,
        trustAnchor,
        allowFixture: true,
        now: () => new Date(NOW),
    });
    const result = await controller.sync({ reason: "contract_test" });
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0], {
        origin: "https://noderooms.com",
        path: "/.well-known/noderooms/connector-policy-v1.json",
        accept: "application/vnd.noderooms.connector-policy+json",
        maximum_bytes: 524_288,
        redirects_allowed: false,
        timeout_ms: 4_000,
        read_only: true,
    });
    assert.equal(compareAndSetCount, 1);
    assert.equal(result.sequence, 1);
    assert.equal(result.tool_authority_granted, false);
    assert.equal(
        controller.status().activation_state,
        "policy_synced_contract_only",
    );
});

test("exact repeat and restart are idempotent without rewriting checkpoint", async () => {
    let compareAndSetCount = 0;
    const baseStore = createInMemoryCanonicalPolicyCheckpointStore();
    const store = {
        load: () => baseStore.load(),
        async compareAndSet(expected, next) {
            compareAndSetCount += 1;
            return baseStore.compareAndSet(expected, next);
        },
    };
    const first = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        checkpointStore: store,
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    assert.equal((await first.sync()).idempotent, false);
    assert.equal((await first.sync()).idempotent, true);
    const restart = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        checkpointStore: store,
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    assert.equal((await restart.sync()).idempotent, true);
    assert.equal(compareAndSetCount, 1);
});

test("checkpoint fixture is exact and rejects local drift", () => {
    const validated = validateCanonicalPolicySyncCheckpointV1(
        checkpointFixture,
    );
    assert.equal(validated.sequence, 1);
    assert.equal(
        validated.bundle_fingerprint_sha256,
        bundle.bundle_fingerprint_sha256,
    );
    const tampered = clone(checkpointFixture);
    tampered.policy_version = "nrp_rollback.001";
    expectCode(
        "POLICY_CHECKPOINT_DRIFT",
        () => validateCanonicalPolicySyncCheckpointV1(tampered),
    );
});

test("self-consistent checkpoint metadata must still match the signed bundle", async () => {
    const mismatched = clone(checkpointFixture);
    mismatched.policy_version = "nrp_checkpoint.other";
    mismatched.checkpoint_fingerprint_sha256 =
        canonicalPolicyCheckpointFingerprint(mismatched);
    validateCanonicalPolicySyncCheckpointV1(mismatched);
    const controller = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        checkpointStore:
            createInMemoryCanonicalPolicyCheckpointStore(mismatched),
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    assert.equal(await controller.sync(), null);
    assert.equal(
        controller.status().last_error.code,
        "POLICY_CHECKPOINT_BINDING_MISMATCH",
    );
});

test("rollback and same-sequence equivocation are rejected", async () => {
    const future = clone(bundle);
    future.sequence = 2;
    future.bundle_id = `nrpolicy_${"f".repeat(32)}`;
    future.bundle_fingerprint_sha256 = `sha256:${"f".repeat(64)}`;
    const futureCheckpoint = createCanonicalPolicySyncCheckpointV1(
        future,
        NOW - 1_000,
    );
    const rollback = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        checkpointStore:
            createInMemoryCanonicalPolicyCheckpointStore(
                futureCheckpoint,
            ),
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    assert.equal(await rollback.sync(), null);
    assert.equal(
        rollback.status().last_error.code,
        "POLICY_ROLLBACK_DETECTED",
    );

    const conflicting = clone(bundle);
    conflicting.bundle_id = `nrpolicy_${"e".repeat(32)}`;
    conflicting.bundle_fingerprint_sha256 = `sha256:${"e".repeat(64)}`;
    const conflictingCheckpoint =
        createCanonicalPolicySyncCheckpointV1(
            conflicting,
            NOW - 1_000,
        );
    const equivocation = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        checkpointStore:
            createInMemoryCanonicalPolicyCheckpointStore(
                conflictingCheckpoint,
            ),
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    assert.equal(await equivocation.sync(), null);
    assert.equal(
        equivocation.status().last_error.code,
        "POLICY_EQUIVOCATION_DETECTED",
    );
});

test("sequence gaps and invalid predecessor bindings are rejected", async () => {
    const first = ephemeralSignedPolicy({
        sequence: 1,
        sequenceTag: "gap_fixture",
    });
    const firstValidated = validateCanonicalConnectorPolicyBundleV1(
        first.bundle,
        {
            trustAnchor: first.anchor,
            allowFixture: true,
            now: NOW,
        },
    );
    const firstCheckpoint = createCanonicalPolicySyncCheckpointV1(
        firstValidated,
        NOW - 1_000,
    );
    const third = ephemeralSignedPolicy({
        sequence: 3,
        previousFingerprint:
            firstValidated.bundle_fingerprint_sha256,
        sequenceTag: "third_fixture",
    });
    const gap = new CanonicalConnectorPolicySyncController({
        source: sourceFor(third.bundle),
        checkpointStore:
            createInMemoryCanonicalPolicyCheckpointStore(
                firstCheckpoint,
            ),
        trustAnchor: third.anchor,
        allowFixture: true,
        now: () => NOW,
    });
    assert.equal(await gap.sync(), null);
    assert.equal(gap.status().last_error.code, "POLICY_SEQUENCE_GAP");

    const second = ephemeralSignedPolicy({
        sequence: 2,
        previousFingerprint: `sha256:${"d".repeat(64)}`,
        sequenceTag: "second_fixture",
    });
    const brokenChain = new CanonicalConnectorPolicySyncController({
        source: sourceFor(second.bundle),
        checkpointStore:
            createInMemoryCanonicalPolicyCheckpointStore(
                firstCheckpoint,
            ),
        trustAnchor: second.anchor,
        allowFixture: true,
        now: () => NOW,
    });
    assert.equal(await brokenChain.sync(), null);
    assert.equal(
        brokenChain.status().last_error.code,
        "POLICY_CHAIN_INVALID",
    );
});

test("untrusted genesis sequence and checkpoint conflicts stop safely", async () => {
    const untrustedGenesis = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        trustAnchor,
        allowFixture: true,
        minimumSequence: 2,
        now: () => NOW,
    });
    assert.equal(await untrustedGenesis.sync(), null);
    assert.equal(
        untrustedGenesis.status().last_error.code,
        "POLICY_UNTRUSTED_GENESIS",
    );

    const conflict = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        checkpointStore: {
            async load() {
                return null;
            },
            async compareAndSet() {
                return false;
            },
        },
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    assert.equal(await conflict.sync(), null);
    assert.equal(
        conflict.status().last_error.code,
        "POLICY_CHECKPOINT_CONFLICT",
    );
});

test("source failure and malformed source data leave no verified registry", async () => {
    const sourceFailure = new CanonicalConnectorPolicySyncController({
        source: {
            async read() {
                throw new Error("remote text must not escape");
            },
        },
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    assert.equal(await sourceFailure.sync(), null);
    assert.equal(sourceFailure.verifiedRegistry(), null);
    assert.equal(
        sourceFailure.status().last_error.code,
        "POLICY_SYNC_UNAVAILABLE",
    );
    assert.doesNotMatch(
        JSON.stringify(sourceFailure.status()),
        /remote text must not escape/,
    );

    const malformed = new CanonicalConnectorPolicySyncController({
        source: sourceFor({ unexpected: "data" }),
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    assert.equal(await malformed.sync(), null);
    assert.equal(malformed.verifiedRegistry(), null);
    assert.equal(malformed.status().last_error.failed_closed, true);
});

test("concurrent sync requests share one bounded source read", async () => {
    let resolveRead;
    let readCount = 0;
    const source = {
        async read() {
            readCount += 1;
            return new Promise((resolve) => {
                resolveRead = resolve;
            });
        },
    };
    const controller = new CanonicalConnectorPolicySyncController({
        source,
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    const left = controller.sync({ reason: "contract_test" });
    const right = controller.sync({ reason: "owner_inspection" });
    await new Promise((resolve) => setImmediate(resolve));
    resolveRead(clone(bundle));
    const [leftResult, rightResult] = await Promise.all([left, right]);
    assert.equal(readCount, 1);
    assert.equal(leftResult, rightResult);
});

test("exact 004A inventory binds to the signed policy without granting authority", async () => {
    const controller = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    await controller.sync({ reason: "contract_test" });
    const binding = controller.bindInventory(
        exactInventory(controller.verifiedRegistry()),
    );
    assert.equal(binding.metrics.required_profile_count, 1);
    assert.equal(binding.metrics.ready_profile_count, 1);
    assert.equal(binding.metrics.blocked_profile_count, 0);
    assert.equal(binding.profiles[0].owner_exact, true);
    assert.equal(binding.profiles[0].schema_matches, true);
    assert.equal(binding.profiles[0].policy_matches, true);
    assert.equal(
        binding.profiles[0].coverage_status,
        "covered_contract_only",
    );
    assert.equal(binding.phase4c_contract_prerequisite_ready, true);
    assert.equal(
        binding.phase4c_external_write_authority_granted,
        false,
    );
    assert.equal(binding.safety.invokes_connectors, false);
    assert.equal(binding.safety.performs_external_write, false);
});

test("OpenClaw catalog schema gap blocks the Phase 4C prerequisite", async () => {
    const controller = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    await controller.sync({ reason: "contract_test" });
    const catalog = descriptorsFromOpenClawCatalog(catalogFixture);
    const inventory = buildRuntimeToolInventoryV1({
        captured_at: "2026-07-25T13:16:00.000Z",
        refresh_reason: "contract_test",
        inventory_generation: 1,
        source: {
            platform: "openclaw",
            catalog_kind: "tools_catalog",
            agent_id: catalog.agent_id,
        },
        tools: catalog.tools,
        registry: controller.verifiedRegistry(),
    });
    const binding = controller.bindInventory(inventory);
    assert.equal(
        binding.profiles[0].coverage_status,
        "schema_unavailable",
    );
    assert.equal(binding.metrics.blocked_profile_count, 1);
    assert.equal(binding.phase4c_contract_prerequisite_ready, false);
});

test("runtime tool owner drift blocks the Phase 4C prerequisite", async () => {
    const controller = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    await controller.sync({ reason: "contract_test" });
    const descriptor = clone(descriptorFixture);
    descriptor.tools[0].owner.owner_id = "github-other";
    const inventory = buildRuntimeToolInventoryV1({
        captured_at: descriptor.captured_at,
        refresh_reason: descriptor.refresh_reason,
        inventory_generation: descriptor.inventory_generation,
        source: descriptor.source,
        tools: descriptor.tools,
        registry: controller.verifiedRegistry(),
    });
    const binding = controller.bindInventory(inventory);
    assert.equal(binding.profiles[0].owner_exact, false);
    assert.equal(binding.metrics.blocked_profile_count, 1);
    assert.equal(binding.phase4c_contract_prerequisite_ready, false);
    assert.equal(
        binding.phase4c_external_write_authority_granted,
        false,
    );
});

test("inventory policy-version drift remains visible and non-authoritative", async () => {
    const controller = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    await controller.sync({ reason: "contract_test" });
    const driftedRegistry = clone(bundle.registry);
    driftedRegistry.policy_version = "nrp_2026-07-25.drift";
    const binding = controller.bindInventory(
        exactInventory(driftedRegistry),
    );
    assert.equal(
        binding.inventory_binding.version_matches,
        false,
    );
    assert.equal(binding.phase4c_contract_prerequisite_ready, false);
    assert.equal(
        binding.phase4c_external_write_authority_granted,
        false,
    );
});

test("status exposes bounded metadata and no schema, signature, or credential", async () => {
    const controller = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    await controller.sync({ reason: "contract_test" });
    controller.bindInventory(exactInventory());
    const serialized = JSON.stringify(controller.status());
    assert.doesNotMatch(serialized, /tool_input_schema/);
    assert.doesNotMatch(serialized, /signature_base64url/);
    assert.doesNotMatch(serialized, /public_key_jwk/);
    assert.doesNotMatch(
        serialized,
        /(?:authorization|cookie|private_key|credential_value)/i,
    );
});

test("clearing runtime cache removes verified policy but not external checkpoint state", async () => {
    const store = createInMemoryCanonicalPolicyCheckpointStore();
    const controller = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        checkpointStore: store,
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    await controller.sync();
    controller.clearRuntimeCache();
    assert.equal(controller.verifiedRegistry(), null);
    assert.equal(controller.status().activation_state, "not_synced");
    const restart = new CanonicalConnectorPolicySyncController({
        source: sourceFor(bundle),
        checkpointStore: store,
        trustAnchor,
        allowFixture: true,
        now: () => NOW,
    });
    assert.equal((await restart.sync()).idempotent, true);
});

test("PHASE4B_CANONICAL_CONNECTOR_POLICY_SYNC=PASS", async () => {
    const proof = await buildCanonicalConnectorPolicySyncProof();
    assert.equal(proof.canonical_sync.source_read_only, true);
    assert.equal(proof.canonical_sync.redirects_allowed, false);
    assert.equal(proof.canonical_sync.source_read_count, 1);
    assert.equal(
        proof.canonical_sync.signature_trust_anchor_external,
        true,
    );
    assert.equal(proof.monotonicity.exact_restart_idempotent, true);
    assert.equal(proof.monotonicity.rollback_blocked, true);
    assert.equal(proof.monotonicity.signature_tamper_blocked, true);
    assert.equal(
        proof.exact_inventory_binding
            .phase4c_contract_prerequisite_ready,
        true,
    );
    assert.equal(
        proof.host_catalog_gap
            .phase4c_contract_prerequisite_ready,
        false,
    );
    assert.deepEqual(proof.safety, {
        live_policy_fetch_allowed: false,
        live_enforce_allowed: false,
        tool_authority_granted: false,
        tool_execution_attempted: false,
        connector_call_attempted: false,
        external_network_attempted: false,
        external_write_attempted: false,
        owner_decision_automated: false,
        raw_schema_persisted: false,
        raw_parameters_persisted: false,
        raw_results_persisted: false,
        provider_credentials_persisted: false,
        publish_attempted: false,
        live_install_attempted: false,
        gateway_restart_attempted: false,
        production_modified: false,
    });
    assert.equal(proof.closure.phase4b_acceptance, "pass");
    assert.equal(
        proof.closure.phase4b_live_policy_sync_authority_granted,
        false,
    );
    assert.equal(
        proof.closure.phase4c_github_write_authority_granted,
        false,
    );
    console.log("NR_OC_CONNECTOR_004B=PASS");
});
