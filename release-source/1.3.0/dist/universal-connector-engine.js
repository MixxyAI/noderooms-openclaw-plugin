import { sha256Fingerprint } from "./passport-runtime-binding.js";

export const RUNTIME_TOOL_INVENTORY_CONTRACT_VERSION =
    "noderooms-runtime-tool-inventory-v1";
export const UNIVERSAL_CONNECTOR_ENGINE_LIVE_ENFORCE_ALLOWED = false;

const TOOL_NAME_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const OWNER_ID_PATTERN = /^[A-Za-z0-9._:@/-]{1,160}$/;
const PROFILE_ID_PATTERN = /^nrscp_[a-z0-9][a-z0-9_]{2,95}$/;
const SCOPE_PATTERN =
    /^connector\.[a-z][a-z0-9_]{1,31}\.[a-z][a-z0-9_]{1,47}\.[a-z][a-z0-9_]{1,47}$/;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const PROVIDER_PATTERN = /^[a-z][a-z0-9_]{1,31}$/;
const CONNECTOR_PATTERN = /^[a-z][a-z0-9._:-]{2,127}$/;
const CONNECTOR_VERSION_PATTERN =
    /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/;
const ACTION_PATTERN = /^[a-z][a-z0-9_]{1,63}$/;
const MAX_TOOLS = 2_048;
const MAX_SCHEMA_BYTES = 262_144;
const MAX_OBSERVED_UNLISTED = 128;

const OWNER_KINDS = new Set(["core", "plugin", "channel", "mcp"]);
const OWNER_RESOLUTIONS = new Set(["exact", "unresolved"]);
const RISKS = new Set(["low", "medium", "high", "critical", "unknown"]);
const SIDE_EFFECT_CLASSES = new Set([
    "read",
    "write",
    "destructive",
    "admin",
    "unknown",
]);
const REPLAY_SEMANTICS = new Set([
    "replay_safe_read",
    "at_most_once_dispatch",
    "provider_idempotent",
    "unknown",
]);
const RECEIPT_PROFILES = new Set([
    "read_observation_v1",
    "external_action_receipt_v2",
    "unknown",
]);
const COVERAGE_STATUSES = new Set([
    "covered_contract_only",
    "covered_active",
    "internal_bypass",
    "unclassified",
    "owner_unresolved",
    "schema_unavailable",
    "schema_drift",
    "policy_drift",
]);
const REFRESH_REASONS = new Set([
    "gateway_start",
    "owner_inspection",
    "plugin_or_mcp_change",
    "unknown_tool_observed",
    "contract_test",
]);

const GITHUB_DRAFT_PR_INPUT_SCHEMA = Object.freeze({
    type: "object",
    additionalProperties: false,
    required: Object.freeze([
        "repository_full_name",
        "head_ref",
        "base_ref",
        "title",
        "body",
        "draft",
    ]),
    properties: Object.freeze({
        repository_full_name: Object.freeze({
            type: "string",
            pattern: "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
            maxLength: 200,
        }),
        head_ref: Object.freeze({
            type: "string",
            minLength: 1,
            maxLength: 255,
        }),
        base_ref: Object.freeze({
            type: "string",
            minLength: 1,
            maxLength: 255,
        }),
        title: Object.freeze({
            type: "string",
            minLength: 1,
            maxLength: 256,
        }),
        body: Object.freeze({
            type: "string",
            maxLength: 65_536,
        }),
        draft: Object.freeze({ const: true }),
    }),
});

export const REFERENCE_CONNECTOR_REGISTRY_V1 = Object.freeze({
    contract_version: "noderooms-connector-scope-registry-v1",
    registry_version: "nrcr_2026-07-23.001",
    policy_version: "nrp_2026-07-23.001",
    activation_state: "contract_only",
    live_enforce_allowed: false,
    profiles: Object.freeze([
        Object.freeze({
            profile_id: "nrscp_github_pull_request_draft_v1",
            scope: "connector.github.pull_request.draft",
            status: "reference_only",
            provider: "github",
            connector_id: "openclaw.reference.github",
            connector_version: "0.0.0-reference.1",
            tool_name: "github_create_pull_request",
            tool_schema_fingerprint:
                "sha256:c12e12e4f6a0d03d85c46dbe4e17cfe814f7a988f56ecc4c2b40089d621f8c37",
            tool_input_schema: GITHUB_DRAFT_PR_INPUT_SCHEMA,
            action: "create_draft",
            resource_type: "github_repository",
            risk: "high",
            side_effect_class: "write",
            replay_semantics: "at_most_once_dispatch",
            approval_policy: "allow_once",
            receipt_profile: "external_action_receipt_v2",
        }),
    ]),
});

export class UniversalConnectorInventoryError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "UniversalConnectorInventoryError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new UniversalConnectorInventoryError(code, message);
}

function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, required, optional, label) {
    if (!isRecord(value)) {
        fail("INVENTORY_CONTRACT_INVALID", `${label} must be an object.`);
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail(
                "INVENTORY_CONTRACT_INVALID",
                `${label} contains unsupported field ${key}.`,
            );
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail(
                "INVENTORY_CONTRACT_INVALID",
                `${label} is missing ${key}.`,
            );
        }
    }
}

function exactString(value, pattern, label, maxLength = 512) {
    if (typeof value !== "string"
        || value.length < 1
        || value.length > maxLength
        || !pattern.test(value)) {
        fail("INVENTORY_CONTRACT_INVALID", `${label} is invalid.`);
    }
    return value;
}

function nullableEnum(value, values, label) {
    if (value === null || value === undefined) {
        return null;
    }
    if (!values.has(value) || value === "unknown") {
        fail("INVENTORY_CONTRACT_INVALID", `${label} is invalid.`);
    }
    return value;
}

function nullableBoolean(value, label) {
    if (value === null || value === undefined) {
        return null;
    }
    if (typeof value !== "boolean") {
        fail("INVENTORY_CONTRACT_INVALID", `${label} is invalid.`);
    }
    return value;
}

function normalizeTags(value) {
    if (value === null || value === undefined) {
        return [];
    }
    if (!Array.isArray(value) || value.length > 32) {
        fail("INVENTORY_CONTRACT_INVALID", "host_tags is invalid.");
    }
    const tags = value.map((entry, index) =>
        exactString(
            entry,
            /^[A-Za-z0-9._:@/-]{1,80}$/,
            `host_tags[${index}]`,
            80,
        ));
    if (new Set(tags).size !== tags.length) {
        fail("INVENTORY_CONTRACT_INVALID", "host_tags contains duplicates.");
    }
    return tags.toSorted();
}

function cloneSchema(value, label) {
    if (value === null || value === undefined) {
        return null;
    }
    if (!isRecord(value)) {
        fail("INVENTORY_SCHEMA_INVALID", `${label} must be an object.`);
    }
    let serialized;
    try {
        serialized = JSON.stringify(value);
    }
    catch {
        fail("INVENTORY_SCHEMA_INVALID", `${label} is not JSON-compatible.`);
    }
    if (!serialized
        || Buffer.byteLength(serialized, "utf8") > MAX_SCHEMA_BYTES) {
        fail(
            "INVENTORY_SCHEMA_INVALID",
            `${label} exceeds the bounded schema size.`,
        );
    }
    try {
        return JSON.parse(serialized);
    }
    catch {
        fail("INVENTORY_SCHEMA_INVALID", `${label} is not valid JSON.`);
    }
}

function normalizeOwner(value, label) {
    assertExactKeys(
        value,
        ["kind", "owner_id", "resolution"],
        [],
        label,
    );
    if (!OWNER_KINDS.has(value.kind)
        || !OWNER_RESOLUTIONS.has(value.resolution)) {
        fail("INVENTORY_OWNER_INVALID", `${label} is invalid.`);
    }
    return Object.freeze({
        kind: value.kind,
        owner_id: exactString(
            value.owner_id,
            OWNER_ID_PATTERN,
            `${label}.owner_id`,
            160,
        ),
        resolution: value.resolution,
    });
}

function normalizeDescriptor(value, index) {
    const label = `tools[${index}]`;
    assertExactKeys(
        value,
        ["tool_name", "owner"],
        [
            "input_schema",
            "declared_output_profile",
            "declared_replay_semantics",
            "declared_replay_safe",
            "declared_side_effect_class",
            "declared_risk",
            "host_optional",
            "host_tags",
        ],
        label,
    );
    return Object.freeze({
        tool_name: exactString(
            value.tool_name,
            TOOL_NAME_PATTERN,
            `${label}.tool_name`,
            128,
        ),
        owner: normalizeOwner(value.owner, `${label}.owner`),
        input_schema: cloneSchema(
            value.input_schema,
            `${label}.input_schema`,
        ),
        declared_output_profile: nullableEnum(
            value.declared_output_profile,
            RECEIPT_PROFILES,
            `${label}.declared_output_profile`,
        ),
        declared_replay_semantics: nullableEnum(
            value.declared_replay_semantics,
            REPLAY_SEMANTICS,
            `${label}.declared_replay_semantics`,
        ),
        declared_replay_safe: nullableBoolean(
            value.declared_replay_safe,
            `${label}.declared_replay_safe`,
        ),
        declared_side_effect_class: nullableEnum(
            value.declared_side_effect_class,
            SIDE_EFFECT_CLASSES,
            `${label}.declared_side_effect_class`,
        ),
        declared_risk: nullableEnum(
            value.declared_risk,
            RISKS,
            `${label}.declared_risk`,
        ),
        host_optional: value.host_optional === true,
        host_tags: Object.freeze(normalizeTags(value.host_tags)),
    });
}

function normalizeRegistry(registry) {
    assertExactKeys(
        registry,
        [
            "contract_version",
            "registry_version",
            "policy_version",
            "activation_state",
            "live_enforce_allowed",
            "profiles",
        ],
        ["$schema", "source_provenance"],
        "connector registry",
    );
    if (registry.contract_version
            !== "noderooms-connector-scope-registry-v1"
        || !["contract_only", "active", "retired"].includes(
            registry.activation_state,
        )
        || typeof registry.live_enforce_allowed !== "boolean") {
        fail(
            "INVENTORY_REGISTRY_INVALID",
            "Connector registry activation metadata is invalid.",
        );
    }
    exactString(
        registry.registry_version,
        /^nrcr_[a-z0-9][a-z0-9._-]{2,63}$/,
        "registry_version",
        68,
    );
    exactString(
        registry.policy_version,
        /^nrp_[a-z0-9][a-z0-9._-]{2,63}$/,
        "policy_version",
        67,
    );
    if (!Array.isArray(registry.profiles)
        || registry.profiles.length < 1
        || registry.profiles.length > 256) {
        fail(
            "INVENTORY_REGISTRY_INVALID",
            "Connector registry profiles are invalid.",
        );
    }
    const profiles = registry.profiles.map((value, index) => {
        const label = `profiles[${index}]`;
        if (!isRecord(value)) {
            fail("INVENTORY_REGISTRY_INVALID", `${label} is invalid.`);
        }
        const required = [
            "profile_id",
            "scope",
            "status",
            "provider",
            "connector_id",
            "connector_version",
            "tool_name",
            "tool_schema_fingerprint",
            "tool_input_schema",
            "action",
            "resource_type",
            "risk",
            "side_effect_class",
            "replay_semantics",
            "approval_policy",
            "receipt_profile",
        ];
        for (const key of required) {
            if (!Object.hasOwn(value, key)) {
                fail(
                    "INVENTORY_REGISTRY_INVALID",
                    `${label} is missing ${key}.`,
                );
            }
        }
        exactString(
            value.profile_id,
            PROFILE_ID_PATTERN,
            `${label}.profile_id`,
            100,
        );
        exactString(value.scope, SCOPE_PATTERN, `${label}.scope`, 150);
        exactString(
            value.tool_name,
            TOOL_NAME_PATTERN,
            `${label}.tool_name`,
            128,
        );
        exactString(
            value.tool_schema_fingerprint,
            SHA256_PATTERN,
            `${label}.tool_schema_fingerprint`,
            71,
        );
        exactString(
            value.provider,
            PROVIDER_PATTERN,
            `${label}.provider`,
            32,
        );
        exactString(
            value.connector_id,
            CONNECTOR_PATTERN,
            `${label}.connector_id`,
            128,
        );
        exactString(
            value.connector_version,
            CONNECTOR_VERSION_PATTERN,
            `${label}.connector_version`,
            128,
        );
        exactString(
            value.action,
            ACTION_PATTERN,
            `${label}.action`,
            64,
        );
        exactString(
            value.resource_type,
            ACTION_PATTERN,
            `${label}.resource_type`,
            64,
        );
        if (!["reference_only", "active", "deprecated", "blocked"].includes(
            value.status,
        )
            || !RISKS.has(value.risk)
            || value.risk === "unknown"
            || !SIDE_EFFECT_CLASSES.has(value.side_effect_class)
            || value.side_effect_class === "unknown"
            || !REPLAY_SEMANTICS.has(value.replay_semantics)
            || value.replay_semantics === "unknown"
            || !RECEIPT_PROFILES.has(value.receipt_profile)
            || value.receipt_profile === "unknown"
            || !["none", "allow_once"].includes(value.approval_policy)) {
            fail(
                "INVENTORY_REGISTRY_INVALID",
                `${label} policy metadata is invalid.`,
            );
        }
        const schema = cloneSchema(
            value.tool_input_schema,
            `${label}.tool_input_schema`,
        );
        if (sha256Fingerprint(schema) !== value.tool_schema_fingerprint) {
            fail(
                "INVENTORY_REGISTRY_SCHEMA_DRIFT",
                `${label} input schema fingerprint has drifted.`,
            );
        }
        if ((value.risk === "high" || value.risk === "critical")
            && value.approval_policy !== "allow_once") {
            fail(
                "INVENTORY_REGISTRY_APPROVAL_INVALID",
                `${label} requires allow-once approval.`,
            );
        }
        return Object.freeze({
            profile_id: value.profile_id,
            scope: value.scope,
            status: value.status,
            provider: value.provider,
            connector_id: value.connector_id,
            connector_version: value.connector_version,
            tool_name: value.tool_name,
            tool_schema_fingerprint: value.tool_schema_fingerprint,
            action: value.action,
            resource_type: value.resource_type,
            risk: value.risk,
            side_effect_class: value.side_effect_class,
            replay_semantics: value.replay_semantics,
            approval_policy: value.approval_policy,
            receipt_profile: value.receipt_profile,
        });
    });
    const profileIds = profiles.map((profile) => profile.profile_id);
    const toolNames = profiles.map((profile) => profile.tool_name);
    if (new Set(profileIds).size !== profileIds.length
        || new Set(toolNames).size !== toolNames.length) {
        fail(
            "INVENTORY_REGISTRY_DUPLICATE",
            "Connector registry contains duplicate profile or tool bindings.",
        );
    }
    if (registry.activation_state !== "active"
        && registry.live_enforce_allowed !== false) {
        fail(
            "INVENTORY_REGISTRY_ACTIVATION_INVALID",
            "A non-active registry cannot allow live enforcement.",
        );
    }
    return Object.freeze({
        contract_version: registry.contract_version,
        registry_version: registry.registry_version,
        policy_version: registry.policy_version,
        activation_state: registry.activation_state,
        live_enforce_allowed: registry.live_enforce_allowed,
        profiles: Object.freeze(profiles),
    });
}

function driftStatus(
    descriptor,
    profile,
    registry,
    actualSchemaFingerprint,
) {
    if (profile.status === "blocked" || profile.status === "deprecated") {
        return "policy_drift";
    }
    if (descriptor.owner.resolution !== "exact") {
        return "owner_unresolved";
    }
    if (actualSchemaFingerprint === null) {
        return "schema_unavailable";
    }
    if (actualSchemaFingerprint !== profile.tool_schema_fingerprint) {
        return "schema_drift";
    }
    const declaredPairs = [
        [
            descriptor.declared_output_profile,
            profile.receipt_profile,
        ],
        [
            descriptor.declared_replay_semantics,
            profile.replay_semantics,
        ],
        [
            descriptor.declared_side_effect_class,
            profile.side_effect_class,
        ],
        [descriptor.declared_risk, profile.risk],
    ];
    if (declaredPairs.some(([declared, expected]) =>
        declared !== null && declared !== expected)) {
        return "policy_drift";
    }
    return profile.status === "active"
        && registry.activation_state === "active"
        ? "covered_active"
        : "covered_contract_only";
}

function buildToolEntry(descriptor, profile, registry) {
    const actualSchemaFingerprint = descriptor.input_schema === null
        ? null
        : sha256Fingerprint(descriptor.input_schema);
    let coverageStatus;
    if (descriptor.tool_name.startsWith("noderooms_")) {
        coverageStatus = "internal_bypass";
    }
    else if (!profile) {
        coverageStatus = descriptor.owner.resolution === "exact"
            ? "unclassified"
            : "owner_unresolved";
    }
    else {
        coverageStatus = driftStatus(
            descriptor,
            profile,
            registry,
            actualSchemaFingerprint,
        );
    }
    const canonicalRisk = profile?.risk ?? descriptor.declared_risk ?? "unknown";
    const canonicalSideEffect =
        profile?.side_effect_class
        ?? descriptor.declared_side_effect_class
        ?? "unknown";
    const canonicalReplay =
        profile?.replay_semantics
        ?? descriptor.declared_replay_semantics
        ?? "unknown";
    const canonicalReceipt =
        profile?.receipt_profile
        ?? descriptor.declared_output_profile
        ?? "unknown";
    const potentialSideEffect = coverageStatus !== "internal_bypass"
        && (canonicalSideEffect !== "read"
            || canonicalRisk === "medium"
            || canonicalRisk === "high"
            || canonicalRisk === "critical"
            || canonicalRisk === "unknown");
    return Object.freeze({
        tool_name: descriptor.tool_name,
        owner: descriptor.owner,
        actual_input_schema_fingerprint_sha256: actualSchemaFingerprint,
        expected_input_schema_fingerprint_sha256:
            profile?.tool_schema_fingerprint ?? null,
        output_receipt_profile: canonicalReceipt,
        declared_replay_safe: descriptor.declared_replay_safe,
        replay_semantics: canonicalReplay,
        side_effect_class: canonicalSideEffect,
        risk: canonicalRisk,
        host_optional: descriptor.host_optional,
        host_tags: descriptor.host_tags,
        coverage_status: coverageStatus,
        policy_binding: profile
            ? Object.freeze({
                registry_version: registry.registry_version,
                policy_version: registry.policy_version,
                profile_id: profile.profile_id,
                scope: profile.scope,
                profile_status: profile.status,
                provider: profile.provider,
                connector_id: profile.connector_id,
                connector_version: profile.connector_version,
                action: profile.action,
                resource_type: profile.resource_type,
                approval_policy: profile.approval_policy,
            })
            : null,
        potential_side_effect: potentialSideEffect,
        enforce_eligible: false,
        authority_status: "inventory_only_no_authority",
    });
}

function inventoryProjection(snapshot) {
    return {
        contract_version: snapshot.contract_version,
        activation_state: snapshot.activation_state,
        live_enforce_allowed: snapshot.live_enforce_allowed,
        captured_at: snapshot.captured_at,
        refresh_reason: snapshot.refresh_reason,
        inventory_generation: snapshot.inventory_generation,
        source: snapshot.source,
        registry_binding: snapshot.registry_binding,
        metrics: snapshot.metrics,
        tools: snapshot.tools,
        safety: snapshot.safety,
    };
}

export function runtimeToolInventoryFingerprint(snapshot) {
    return sha256Fingerprint(inventoryProjection(snapshot));
}

export function buildRuntimeToolInventoryV1(input) {
    assertExactKeys(
        input,
        [
            "captured_at",
            "refresh_reason",
            "inventory_generation",
            "source",
            "tools",
        ],
        ["registry"],
        "inventory input",
    );
    const capturedAt = Date.parse(input.captured_at);
    if (!Number.isFinite(capturedAt)
        || !REFRESH_REASONS.has(input.refresh_reason)
        || !Number.isSafeInteger(input.inventory_generation)
        || input.inventory_generation < 1) {
        fail(
            "INVENTORY_CONTRACT_INVALID",
            "Inventory capture metadata is invalid.",
        );
    }
    assertExactKeys(
        input.source,
        ["platform", "catalog_kind", "agent_id"],
        ["session_key_fingerprint_sha256"],
        "source",
    );
    if (input.source.platform !== "openclaw"
        || !["tools_catalog", "tools_effective", "contract_fixture"].includes(
            input.source.catalog_kind,
        )) {
        fail("INVENTORY_SOURCE_INVALID", "Inventory source is invalid.");
    }
    exactString(
        input.source.agent_id,
        OWNER_ID_PATTERN,
        "source.agent_id",
        160,
    );
    if (input.source.session_key_fingerprint_sha256 !== undefined) {
        exactString(
            input.source.session_key_fingerprint_sha256,
            SHA256_PATTERN,
            "source.session_key_fingerprint_sha256",
            71,
        );
    }
    if (!Array.isArray(input.tools)
        || input.tools.length < 1
        || input.tools.length > MAX_TOOLS) {
        fail("INVENTORY_TOOLS_INVALID", "Inventory tools are invalid.");
    }
    const descriptors = input.tools.map(normalizeDescriptor);
    const toolNames = descriptors.map((entry) => entry.tool_name);
    if (new Set(toolNames).size !== toolNames.length) {
        fail(
            "INVENTORY_TOOL_DUPLICATE",
            "Runtime inventory contains duplicate effective tool names.",
        );
    }
    const registry = normalizeRegistry(
        input.registry ?? REFERENCE_CONNECTOR_REGISTRY_V1,
    );
    const profilesByTool = new Map(
        registry.profiles.map((profile) => [profile.tool_name, profile]),
    );
    const tools = descriptors
        .map((descriptor) => buildToolEntry(
            descriptor,
            profilesByTool.get(descriptor.tool_name),
            registry,
        ))
        .toSorted((left, right) => left.tool_name.localeCompare(right.tool_name));
    const coveredCount = tools.filter((entry) =>
        entry.coverage_status === "covered_contract_only"
        || entry.coverage_status === "covered_active"
        || entry.coverage_status === "internal_bypass").length;
    const driftedCount = tools.filter((entry) =>
        entry.coverage_status === "schema_drift"
        || entry.coverage_status === "policy_drift").length;
    const unclassifiedCount = tools.length - coveredCount;
    const sideEffectingUnclassifiedCount = tools.filter((entry) =>
        entry.potential_side_effect
        && !["covered_contract_only", "covered_active"].includes(
            entry.coverage_status,
        )).length;
    const metrics = Object.freeze({
        source_tool_count: descriptors.length,
        inventory_tool_count: tools.length,
        inventory_completeness_percent: 100,
        covered_tool_count: coveredCount,
        unclassified_tool_count: unclassifiedCount,
        drifted_tool_count: driftedCount,
        side_effecting_unclassified_tool_count:
            sideEffectingUnclassifiedCount,
        classification_coverage_percent: Number(
            ((coveredCount / tools.length) * 100).toFixed(2),
        ),
        enforce_profile_ready: false,
    });
    const snapshot = {
        contract_version: RUNTIME_TOOL_INVENTORY_CONTRACT_VERSION,
        activation_state: "inventory_only",
        live_enforce_allowed: UNIVERSAL_CONNECTOR_ENGINE_LIVE_ENFORCE_ALLOWED,
        captured_at: new Date(capturedAt).toISOString(),
        refresh_reason: input.refresh_reason,
        inventory_generation: input.inventory_generation,
        source: Object.freeze({
            platform: input.source.platform,
            catalog_kind: input.source.catalog_kind,
            agent_id: input.source.agent_id,
            ...(input.source.session_key_fingerprint_sha256 === undefined
                ? {}
                : {
                    session_key_fingerprint_sha256:
                        input.source.session_key_fingerprint_sha256,
                }),
        }),
        registry_binding: Object.freeze({
            contract_version: registry.contract_version,
            registry_version: registry.registry_version,
            policy_version: registry.policy_version,
            activation_state: registry.activation_state,
            live_enforce_allowed: registry.live_enforce_allowed,
        }),
        metrics,
        tools: Object.freeze(tools),
        safety: Object.freeze({
            grants_authority: false,
            executes_tools: false,
            invokes_connectors: false,
            performs_network_request: false,
            performs_external_write: false,
            persists_raw_schema: false,
            persists_raw_parameters: false,
            persists_raw_results: false,
            persists_provider_credentials: false,
            owner_decision_automatable: false,
        }),
    };
    snapshot.snapshot_fingerprint_sha256 =
        runtimeToolInventoryFingerprint(snapshot);
    return Object.freeze(snapshot);
}

export function validateRuntimeToolInventoryV1(snapshot) {
    if (!isRecord(snapshot)
        || snapshot.contract_version
            !== RUNTIME_TOOL_INVENTORY_CONTRACT_VERSION
        || snapshot.activation_state !== "inventory_only"
        || snapshot.live_enforce_allowed !== false
        || !Array.isArray(snapshot.tools)
        || snapshot.tools.length < 1
        || snapshot.tools.length > MAX_TOOLS
        || !isRecord(snapshot.metrics)
        || !isRecord(snapshot.safety)
        || !SHA256_PATTERN.test(
            snapshot.snapshot_fingerprint_sha256 ?? "",
        )) {
        fail(
            "INVENTORY_SNAPSHOT_INVALID",
            "Runtime tool inventory snapshot is invalid.",
        );
    }
    const coveredCount = snapshot.tools.filter((entry) =>
        entry?.coverage_status === "covered_contract_only"
        || entry?.coverage_status === "covered_active"
        || entry?.coverage_status === "internal_bypass").length;
    const driftedCount = snapshot.tools.filter((entry) =>
        entry?.coverage_status === "schema_drift"
        || entry?.coverage_status === "policy_drift").length;
    const unclassifiedCount = snapshot.tools.length - coveredCount;
    const sideEffectingUnclassifiedCount = snapshot.tools.filter((entry) =>
        entry?.potential_side_effect === true
        && !["covered_contract_only", "covered_active"].includes(
            entry?.coverage_status,
        )).length;
    const classificationCoverage = Number(
        ((coveredCount / snapshot.tools.length) * 100).toFixed(2),
    );
    if (snapshot.metrics.source_tool_count !== snapshot.tools.length
        || snapshot.metrics.inventory_tool_count !== snapshot.tools.length
        || snapshot.metrics.inventory_completeness_percent !== 100
        || snapshot.metrics.covered_tool_count !== coveredCount
        || snapshot.metrics.unclassified_tool_count !== unclassifiedCount
        || snapshot.metrics.drifted_tool_count !== driftedCount
        || snapshot.metrics.side_effecting_unclassified_tool_count
            !== sideEffectingUnclassifiedCount
        || snapshot.metrics.classification_coverage_percent
            !== classificationCoverage
        || snapshot.metrics.enforce_profile_ready !== false
        || snapshot.safety.grants_authority !== false
        || snapshot.safety.executes_tools !== false
        || snapshot.safety.invokes_connectors !== false
        || snapshot.safety.performs_network_request !== false
        || snapshot.safety.performs_external_write !== false
        || snapshot.safety.persists_raw_schema !== false
        || snapshot.safety.persists_raw_parameters !== false
        || snapshot.safety.persists_raw_results !== false
        || snapshot.safety.persists_provider_credentials !== false
        || snapshot.safety.owner_decision_automatable !== false) {
        fail(
            "INVENTORY_SAFETY_INVALID",
            "Runtime tool inventory safety metrics are invalid.",
        );
    }
    for (const [index, entry] of snapshot.tools.entries()) {
        if (!isRecord(entry)
            || !TOOL_NAME_PATTERN.test(entry.tool_name ?? "")
            || !COVERAGE_STATUSES.has(entry.coverage_status)
            || entry.enforce_eligible !== false
            || entry.authority_status !== "inventory_only_no_authority"
            || !RISKS.has(entry.risk)
            || !SIDE_EFFECT_CLASSES.has(entry.side_effect_class)
            || !REPLAY_SEMANTICS.has(entry.replay_semantics)
            || !RECEIPT_PROFILES.has(entry.output_receipt_profile)) {
            fail(
                "INVENTORY_SNAPSHOT_INVALID",
                `Runtime inventory tool ${index} is invalid.`,
            );
        }
    }
    if (runtimeToolInventoryFingerprint(snapshot)
        !== snapshot.snapshot_fingerprint_sha256) {
        fail(
            "INVENTORY_SNAPSHOT_DRIFT",
            "Runtime tool inventory fingerprint has drifted.",
        );
    }
    return snapshot;
}

function sourceOwner(group, tool) {
    const source = tool.source ?? group.source;
    const kind = OWNER_KINDS.has(source) ? source : "plugin";
    let ownerId;
    let resolution = "exact";
    if (kind === "core") {
        ownerId = "openclaw.core";
    }
    else if (kind === "plugin") {
        ownerId = tool.pluginId ?? group.pluginId ?? group.id;
    }
    else if (kind === "channel") {
        ownerId = tool.channelId ?? group.channelId ?? group.id;
    }
    else {
        ownerId = tool.mcpServerId ?? tool.pluginId ?? group.mcpServerId
            ?? group.id;
        if (!tool.mcpServerId && !group.mcpServerId) {
            resolution = "unresolved";
        }
    }
    const normalized = typeof ownerId === "string" && ownerId.trim()
        ? ownerId.trim().slice(0, 160)
        : `${kind}.unresolved`;
    if (!OWNER_ID_PATTERN.test(normalized)) {
        return {
            kind,
            owner_id: `${kind}.unresolved`,
            resolution: "unresolved",
        };
    }
    return { kind, owner_id: normalized, resolution };
}

export function descriptorsFromOpenClawCatalog(catalog) {
    if (!isRecord(catalog)
        || typeof catalog.agentId !== "string"
        || !Array.isArray(catalog.groups)) {
        fail(
            "OPENCLAW_CATALOG_INVALID",
            "OpenClaw tool catalog is invalid.",
        );
    }
    const descriptors = [];
    for (const [groupIndex, group] of catalog.groups.entries()) {
        if (!isRecord(group) || !Array.isArray(group.tools)) {
            fail(
                "OPENCLAW_CATALOG_INVALID",
                `OpenClaw tool group ${groupIndex} is invalid.`,
            );
        }
        for (const [toolIndex, tool] of group.tools.entries()) {
            if (!isRecord(tool)) {
                fail(
                    "OPENCLAW_CATALOG_INVALID",
                    `OpenClaw tool ${groupIndex}.${toolIndex} is invalid.`,
                );
            }
            const inputSchema = tool.inputSchema
                ?? tool.input_schema
                ?? tool.parameters
                ?? null;
            descriptors.push({
                tool_name: tool.id,
                owner: sourceOwner(group, tool),
                input_schema: inputSchema,
                declared_output_profile:
                    tool.outputReceiptProfile
                    ?? tool.output_receipt_profile
                    ?? null,
                declared_replay_semantics:
                    tool.replaySemantics
                    ?? tool.replay_semantics
                    ?? null,
                declared_replay_safe:
                    typeof tool.replaySafe === "boolean"
                        ? tool.replaySafe
                        : null,
                declared_side_effect_class:
                    tool.sideEffectClass
                    ?? tool.side_effect_class
                    ?? null,
                declared_risk: tool.risk ?? null,
                host_optional: tool.optional === true,
                host_tags: Array.isArray(tool.tags) ? tool.tags : [],
            });
        }
    }
    return Object.freeze({
        agent_id: catalog.agentId,
        tools: Object.freeze(descriptors),
    });
}

function safeToolName(value) {
    return typeof value === "string" && TOOL_NAME_PATTERN.test(value)
        ? value
        : null;
}

export class UniversalConnectorInventoryController {
    constructor(options) {
        this.gateway = options.gateway;
        this.registry = options.registry ?? REFERENCE_CONNECTOR_REGISTRY_V1;
        this.now = typeof options.now === "function"
            ? options.now
            : () => new Date();
        this.snapshot = null;
        this.generation = 0;
        this.lastError = null;
        this.refreshPromise = null;
        this.observedUnlisted = new Set();
        this.epoch = 0;
    }

    async refresh(input = {}) {
        if (this.refreshPromise) {
            return this.refreshPromise;
        }
        const operation = this.refreshInternal(input, this.epoch);
        this.refreshPromise = operation.finally(() => {
            this.refreshPromise = null;
        });
        return this.refreshPromise;
    }

    async refreshInternal(input, epoch) {
        const reason = REFRESH_REASONS.has(input.reason)
            ? input.reason
            : "owner_inspection";
        try {
            if (!this.gateway
                || typeof this.gateway.request !== "function") {
                throw new Error("Gateway catalog API is unavailable.");
            }
            const catalog = await this.gateway.request(
                "tools.catalog",
                {
                    ...(typeof input.agentId === "string" && input.agentId
                        ? { agentId: input.agentId }
                        : {}),
                    includePlugins: true,
                },
                { timeoutMs: 4_000 },
            );
            if (epoch !== this.epoch) {
                return null;
            }
            const normalized = descriptorsFromOpenClawCatalog(catalog);
            this.generation += 1;
            this.snapshot = buildRuntimeToolInventoryV1({
                captured_at: this.now().toISOString(),
                refresh_reason: reason,
                inventory_generation: this.generation,
                source: {
                    platform: "openclaw",
                    catalog_kind: "tools_catalog",
                    agent_id: normalized.agent_id,
                },
                tools: normalized.tools,
                registry: this.registry,
            });
            this.lastError = null;
            const currentNames = new Set(
                this.snapshot.tools.map((entry) => entry.tool_name),
            );
            for (const name of this.observedUnlisted) {
                if (currentNames.has(name)) {
                    this.observedUnlisted.delete(name);
                }
            }
            return this.snapshot;
        }
        catch {
            if (epoch !== this.epoch) {
                return null;
            }
            this.lastError = Object.freeze({
                code: "RUNTIME_TOOL_INVENTORY_UNAVAILABLE",
                message:
                    "The OpenClaw tool catalog could not be inventoried safely.",
                failed_closed: true,
            });
            return null;
        }
    }

    observeBeforeToolCall(event) {
        const toolName = safeToolName(event?.toolName);
        if (!toolName || toolName.startsWith("noderooms_")) {
            return;
        }
        const known = this.snapshot?.tools.some(
            (entry) => entry.tool_name === toolName,
        ) === true;
        if (!known && this.observedUnlisted.size < MAX_OBSERVED_UNLISTED) {
            this.observedUnlisted.add(toolName);
        }
    }

    status() {
        return Object.freeze({
            contract_version:
                "noderooms-universal-connector-engine-status-v1",
            activation_state: "inventory_only",
            live_enforce_allowed:
                UNIVERSAL_CONNECTOR_ENGINE_LIVE_ENFORCE_ALLOWED,
            snapshot: this.snapshot,
            refresh_required: this.snapshot === null
                || this.observedUnlisted.size > 0,
            observed_unlisted_tools: Object.freeze(
                [...this.observedUnlisted].toSorted(),
            ),
            last_error: this.lastError,
            safety: Object.freeze({
                grants_authority: false,
                invokes_connectors: false,
                performs_external_write: false,
                stores_raw_parameters: false,
                stores_raw_results: false,
                stores_provider_credentials: false,
            }),
        });
    }

    connectors() {
        const discovered = new Map(
            (this.snapshot?.tools ?? []).map((entry) => [
                entry.tool_name,
                entry,
            ]),
        );
        return Object.freeze({
            contract_version: "noderooms-connector-coverage-status-v1",
            activation_state: "inventory_only",
            live_enforce_allowed: false,
            connectors: Object.freeze(
                this.registry.profiles.map((profile) => {
                    const tool = discovered.get(profile.tool_name);
                    return Object.freeze({
                        provider: profile.provider,
                        connector_id: profile.connector_id,
                        connector_version: profile.connector_version,
                        profile_id: profile.profile_id,
                        scope: profile.scope,
                        tool_name: profile.tool_name,
                        discovered: Boolean(tool),
                        coverage_status:
                            tool?.coverage_status ?? "not_discovered",
                        authority_status: "inventory_only_no_authority",
                    });
                }),
            ),
        });
    }

    clearRuntimeCache() {
        this.epoch += 1;
        this.snapshot = null;
        this.generation = 0;
        this.lastError = null;
        this.refreshPromise = null;
        this.observedUnlisted.clear();
    }
}
