import { sha256Fingerprint } from "./passport-runtime-binding.js";
import {
    validateRuntimeToolInventoryV1,
} from "./universal-connector-engine.js";

export const CONNECTOR_BETA_FOUNDATION_CONTRACT_VERSION =
    "noderooms-openclaw-connector-beta-foundation-v1";
export const CONNECTOR_BETA_DEVELOPMENT_IDENTITY =
    "1.4.0-alpha.1-dev.1";
export const CONNECTOR_BETA_LIVE_CONNECTOR_USE_ALLOWED = false;

const FOUNDATION_ID_PATTERN =
    /^nrcbf_[a-z0-9][a-z0-9._-]{2,95}$/;
const CONNECTOR_KEY_PATTERN =
    /^nrcbc_[a-z0-9][a-z0-9_]{2,95}$/;
const TOOL_NAME_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const OWNER_ID_PATTERN = /^[A-Za-z0-9._:@/-]{1,160}$/;
const PROVIDER_PATTERN = /^[a-z][a-z0-9_]{1,31}$/;
const CONNECTOR_ID_PATTERN = /^[a-z][a-z0-9._:-]{2,127}$/;
const PROFILE_ID_PATTERN = /^nrscp_[a-z0-9][a-z0-9_]{2,95}$/;
const SCOPE_PATTERN =
    /^connector\.[a-z][a-z0-9_]{1,31}\.[a-z][a-z0-9_]{1,47}\.[a-z][a-z0-9_]{1,47}$/;
const ACTION_PATTERN = /^[a-z][a-z0-9_]{1,63}$/;
const REGISTRY_VERSION_PATTERN =
    /^nrcr_[a-z0-9][a-z0-9._-]{2,63}$/;
const POLICY_VERSION_PATTERN =
    /^nrp_[a-z0-9][a-z0-9._-]{2,63}$/;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const VERSION_PATTERN =
    /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/;

const CAPTURE_KINDS = new Set(["contract_fixture", "runtime_capture"]);
const CONNECTOR_FAMILIES = new Set([
    "email",
    "discord",
    "whatsapp",
    "sms",
    "reference",
]);
const VERSION_SOURCES = new Set([
    "contract_fixture",
    "runtime_plugin_manifest",
    "runtime_package",
    "runtime_mcp_handshake",
]);
const OWNER_KINDS = new Set(["plugin", "channel", "mcp"]);
const RECEIPT_PROFILES = new Set([
    "read_observation_v1",
    "external_action_receipt_v2",
]);
const REPLAY_SEMANTICS = new Set([
    "replay_safe_read",
    "at_most_once_dispatch",
    "provider_idempotent",
]);
const SIDE_EFFECT_CLASSES = new Set([
    "read",
    "write",
    "destructive",
    "admin",
]);
const RISKS = new Set(["low", "medium", "high", "critical"]);
const APPROVAL_POLICIES = new Set(["none", "allow_once"]);
const MAX_CONNECTORS = 64;
const MAX_TOOLS_PER_CONNECTOR = 128;

export class ConnectorBetaFoundationError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "ConnectorBetaFoundationError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new ConnectorBetaFoundationError(code, message);
}

function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, required, optional, label) {
    if (!isRecord(value)) {
        fail("CONNECTOR_BETA_CONTRACT_INVALID", `${label} must be an object.`);
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail(
                "CONNECTOR_BETA_CONTRACT_INVALID",
                `${label} contains unsupported field ${key}.`,
            );
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail(
                "CONNECTOR_BETA_CONTRACT_INVALID",
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
        fail("CONNECTOR_BETA_CONTRACT_INVALID", `${label} is invalid.`);
    }
    return value;
}

function exactVersion(value, label) {
    return exactString(value, VERSION_PATTERN, label, 128);
}

function sameOwner(left, right) {
    return left.kind === right.kind
        && left.owner_id === right.owner_id
        && left.resolution === right.resolution;
}

function samePolicyConnector(left, right) {
    return left.provider === right.provider
        && left.connector_id === right.connector_id
        && left.connector_version === right.connector_version;
}

function normalizedCandidate(candidate, index, captureKind) {
    const label = `connector_candidates[${index}]`;
    assertExactKeys(
        candidate,
        [
            "connector_key",
            "family",
            "owner_version",
            "version_source",
            "tool_names",
        ],
        [],
        label,
    );
    exactString(
        candidate.connector_key,
        CONNECTOR_KEY_PATTERN,
        `${label}.connector_key`,
        101,
    );
    if (!CONNECTOR_FAMILIES.has(candidate.family)) {
        fail(
            "CONNECTOR_BETA_FAMILY_INVALID",
            `${label}.family is invalid.`,
        );
    }
    if ((captureKind === "contract_fixture")
            !== (candidate.family === "reference")) {
        fail(
            "CONNECTOR_BETA_FAMILY_INVALID",
            `${label}.family does not match capture_kind.`,
        );
    }
    exactVersion(candidate.owner_version, `${label}.owner_version`);
    if (!VERSION_SOURCES.has(candidate.version_source)) {
        fail(
            "CONNECTOR_BETA_VERSION_SOURCE_INVALID",
            `${label}.version_source is invalid.`,
        );
    }
    const fixtureVersion =
        candidate.version_source === "contract_fixture";
    if ((captureKind === "contract_fixture") !== fixtureVersion) {
        fail(
            "CONNECTOR_BETA_CAPTURE_SOURCE_MISMATCH",
            `${label} version source does not match capture_kind.`,
        );
    }
    if (!Array.isArray(candidate.tool_names)
        || candidate.tool_names.length < 1
        || candidate.tool_names.length > MAX_TOOLS_PER_CONNECTOR) {
        fail(
            "CONNECTOR_BETA_TOOLS_INVALID",
            `${label}.tool_names is invalid.`,
        );
    }
    const toolNames = candidate.tool_names.map((toolName, toolIndex) =>
        exactString(
            toolName,
            TOOL_NAME_PATTERN,
            `${label}.tool_names[${toolIndex}]`,
            128,
        ));
    if (new Set(toolNames).size !== toolNames.length) {
        fail(
            "CONNECTOR_BETA_TOOL_DUPLICATE",
            `${label}.tool_names contains duplicates.`,
        );
    }
    return Object.freeze({
        connector_key: candidate.connector_key,
        family: candidate.family,
        owner_version: candidate.owner_version,
        version_source: candidate.version_source,
        tool_names: Object.freeze(toolNames.toSorted()),
    });
}

function exactToolBinding(entry, label) {
    if (!isRecord(entry)
        || entry.owner?.resolution !== "exact"
        || !OWNER_KINDS.has(entry.owner?.kind)) {
        fail(
            "CONNECTOR_BETA_OWNER_UNRESOLVED",
            `${label} has no exact external owner.`,
        );
    }
    if (!SHA256_PATTERN.test(
        entry.actual_input_schema_fingerprint_sha256 ?? "",
    )) {
        fail(
            "CONNECTOR_BETA_SCHEMA_UNAVAILABLE",
            `${label} has no exact input-schema fingerprint.`,
        );
    }
    if (entry.actual_input_schema_fingerprint_sha256
            !== entry.expected_input_schema_fingerprint_sha256) {
        fail(
            "CONNECTOR_BETA_SCHEMA_DRIFT",
            `${label} input schema does not match its policy profile.`,
        );
    }
    if (entry.coverage_status !== "covered_contract_only"
        || entry.enforce_eligible !== false
        || entry.authority_status !== "inventory_only_no_authority"
        || !isRecord(entry.policy_binding)
        || entry.policy_binding.profile_status !== "reference_only") {
        fail(
            "CONNECTOR_BETA_POLICY_NOT_REFERENCE_ONLY",
            `${label} is not an exact non-live reference binding.`,
        );
    }
    const policy = entry.policy_binding;
    exactString(policy.profile_id, PROFILE_ID_PATTERN, `${label}.profile_id`);
    exactString(policy.scope, SCOPE_PATTERN, `${label}.scope`, 150);
    exactString(policy.provider, PROVIDER_PATTERN, `${label}.provider`, 32);
    exactString(
        policy.connector_id,
        CONNECTOR_ID_PATTERN,
        `${label}.connector_id`,
        128,
    );
    exactVersion(policy.connector_version, `${label}.connector_version`);
    exactString(policy.action, ACTION_PATTERN, `${label}.action`, 64);
    exactString(
        policy.resource_type,
        ACTION_PATTERN,
        `${label}.resource_type`,
        64,
    );
    if (!RECEIPT_PROFILES.has(entry.output_receipt_profile)
        || !REPLAY_SEMANTICS.has(entry.replay_semantics)
        || !SIDE_EFFECT_CLASSES.has(entry.side_effect_class)
        || !RISKS.has(entry.risk)
        || !APPROVAL_POLICIES.has(policy.approval_policy)) {
        fail(
            "CONNECTOR_BETA_POLICY_INVALID",
            `${label} policy metadata is invalid.`,
        );
    }
    if ((entry.risk === "high" || entry.risk === "critical")
        && policy.approval_policy !== "allow_once") {
        fail(
            "CONNECTOR_BETA_APPROVAL_INVALID",
            `${label} requires allow-once approval.`,
        );
    }
    return Object.freeze({
        tool_name: entry.tool_name,
        profile_id: policy.profile_id,
        scope: policy.scope,
        input_schema_fingerprint_sha256:
            entry.actual_input_schema_fingerprint_sha256,
        output_receipt_profile: entry.output_receipt_profile,
        replay_semantics: entry.replay_semantics,
        side_effect_class: entry.side_effect_class,
        risk: entry.risk,
        approval_policy: policy.approval_policy,
        action: policy.action,
        resource_type: policy.resource_type,
        coverage_status: "covered_contract_only",
        enforce_eligible: false,
        authority_status: "discovery_only_no_authority",
    });
}

function foundationProjection(snapshot) {
    return {
        contract_version: snapshot.contract_version,
        development_identity: snapshot.development_identity,
        activation_state: snapshot.activation_state,
        live_connector_use_allowed: snapshot.live_connector_use_allowed,
        foundation_id: snapshot.foundation_id,
        capture_kind: snapshot.capture_kind,
        captured_at: snapshot.captured_at,
        runtime_binding: snapshot.runtime_binding,
        metrics: snapshot.metrics,
        connectors: snapshot.connectors,
        safety: snapshot.safety,
    };
}

export function connectorBetaFoundationFingerprint(snapshot) {
    return sha256Fingerprint(foundationProjection(snapshot));
}

export function buildConnectorBetaFoundationV1(input) {
    assertExactKeys(
        input,
        [
            "foundation_id",
            "capture_kind",
            "captured_at",
            "openclaw_version",
            "plugin_api_version",
            "inventory_snapshot",
            "connector_candidates",
        ],
        [],
        "connector beta input",
    );
    exactString(
        input.foundation_id,
        FOUNDATION_ID_PATTERN,
        "foundation_id",
        101,
    );
    if (!CAPTURE_KINDS.has(input.capture_kind)) {
        fail(
            "CONNECTOR_BETA_CAPTURE_KIND_INVALID",
            "capture_kind is invalid.",
        );
    }
    const capturedAt = Date.parse(input.captured_at);
    if (!Number.isFinite(capturedAt)) {
        fail(
            "CONNECTOR_BETA_CAPTURE_TIME_INVALID",
            "captured_at is invalid.",
        );
    }
    exactVersion(input.openclaw_version, "openclaw_version");
    exactVersion(input.plugin_api_version, "plugin_api_version");
    const inventory = validateRuntimeToolInventoryV1(input.inventory_snapshot);
    const fixtureInventory =
        inventory.source?.catalog_kind === "contract_fixture";
    if ((input.capture_kind === "contract_fixture") !== fixtureInventory
        || inventory.activation_state !== "inventory_only"
        || inventory.live_enforce_allowed !== false
        || inventory.registry_binding?.activation_state !== "contract_only"
        || inventory.registry_binding?.live_enforce_allowed !== false) {
        fail(
            "CONNECTOR_BETA_INVENTORY_BOUNDARY_INVALID",
            "Runtime inventory is outside the non-live C001 boundary.",
        );
    }
    if (!Array.isArray(input.connector_candidates)
        || input.connector_candidates.length < 1
        || input.connector_candidates.length > MAX_CONNECTORS) {
        fail(
            "CONNECTOR_BETA_CONNECTORS_INVALID",
            "connector_candidates is invalid.",
        );
    }
    const candidates = input.connector_candidates.map(
        (candidate, index) =>
            normalizedCandidate(candidate, index, input.capture_kind),
    );
    const connectorKeys = candidates.map(
        (candidate) => candidate.connector_key,
    );
    if (new Set(connectorKeys).size !== connectorKeys.length) {
        fail(
            "CONNECTOR_BETA_CONNECTOR_DUPLICATE",
            "connector_candidates contains duplicate connector keys.",
        );
    }
    const inventoryTools = new Map(
        inventory.tools.map((entry) => [entry.tool_name, entry]),
    );
    const claimedToolNames = new Set();
    const connectors = candidates.map((candidate, candidateIndex) => {
        const entries = candidate.tool_names.map((toolName) => {
            if (claimedToolNames.has(toolName)) {
                fail(
                    "CONNECTOR_BETA_TOOL_REUSED",
                    `Tool ${toolName} is bound to more than one connector.`,
                );
            }
            const entry = inventoryTools.get(toolName);
            if (!entry) {
                fail(
                    "CONNECTOR_BETA_TOOL_NOT_IN_INVENTORY",
                    `Tool ${toolName} is absent from the bound inventory.`,
                );
            }
            claimedToolNames.add(toolName);
            return entry;
        });
        const first = entries[0];
        const tools = entries.map((entry, toolIndex) =>
            exactToolBinding(
                entry,
                `connector_candidates[${candidateIndex}].tools[${toolIndex}]`,
            )).toSorted((left, right) =>
            left.tool_name.localeCompare(right.tool_name));
        for (const entry of entries) {
            if (!sameOwner(first.owner, entry.owner)) {
                fail(
                    "CONNECTOR_BETA_OWNER_DRIFT",
                    `connector_candidates[${candidateIndex}] spans owners.`,
                );
            }
            if (!samePolicyConnector(
                first.policy_binding,
                entry.policy_binding,
            )) {
                fail(
                    "CONNECTOR_BETA_CONNECTOR_DRIFT",
                    `connector_candidates[${candidateIndex}] spans connector identities.`,
                );
            }
        }
        const policy = first.policy_binding;
        return Object.freeze({
            connector_key: candidate.connector_key,
            family: candidate.family,
            status: input.capture_kind === "contract_fixture"
                ? "reference_only"
                : "inventory_verified_non_live",
            owner: Object.freeze({
                kind: first.owner.kind,
                owner_id: first.owner.owner_id,
                resolution: "exact",
                owner_version: candidate.owner_version,
                version_source: candidate.version_source,
            }),
            provider: policy.provider,
            connector_id: policy.connector_id,
            connector_version: policy.connector_version,
            credential_custodian: "openclaw",
            noderooms_stores_provider_credentials: false,
            tools: Object.freeze(tools),
            authority_status: "discovery_only_no_authority",
        });
    }).toSorted((left, right) =>
        left.connector_key.localeCompare(right.connector_key));
    const familyCount = new Set(
        connectors.map((connector) => connector.family),
    ).size;
    const toolBindingCount = connectors.reduce(
        (count, connector) => count + connector.tools.length,
        0,
    );
    const snapshot = {
        contract_version: CONNECTOR_BETA_FOUNDATION_CONTRACT_VERSION,
        development_identity: CONNECTOR_BETA_DEVELOPMENT_IDENTITY,
        activation_state: "discovery_only",
        live_connector_use_allowed:
            CONNECTOR_BETA_LIVE_CONNECTOR_USE_ALLOWED,
        foundation_id: input.foundation_id,
        capture_kind: input.capture_kind,
        captured_at: new Date(capturedAt).toISOString(),
        runtime_binding: Object.freeze({
            platform: "openclaw",
            openclaw_version: input.openclaw_version,
            plugin_api_version: input.plugin_api_version,
            catalog_kind: inventory.source.catalog_kind,
            agent_id_fingerprint_sha256: sha256Fingerprint({
                platform: "openclaw",
                agent_id: inventory.source.agent_id,
            }),
            inventory_contract_version: inventory.contract_version,
            inventory_generation: inventory.inventory_generation,
            inventory_snapshot_fingerprint_sha256:
                inventory.snapshot_fingerprint_sha256,
            registry_version: inventory.registry_binding.registry_version,
            policy_version: inventory.registry_binding.policy_version,
        }),
        metrics: Object.freeze({
            connector_count: connectors.length,
            connector_family_count: familyCount,
            tool_binding_count: toolBindingCount,
            schema_verified_tool_count: toolBindingCount,
            unclassified_tool_count: 0,
            drifted_tool_count: 0,
        }),
        connectors: Object.freeze(connectors),
        safety: Object.freeze({
            grants_authority: false,
            executes_tools: false,
            invokes_connectors: false,
            performs_network_request: false,
            performs_external_write: false,
            stores_provider_credentials: false,
            stores_raw_schema: false,
            stores_raw_parameters: false,
            stores_raw_results: false,
            automates_owner_decision: false,
        }),
    };
    snapshot.foundation_fingerprint_sha256 =
        connectorBetaFoundationFingerprint(snapshot);
    return Object.freeze(snapshot);
}

function validateToolSnapshot(tool, label) {
    assertExactKeys(
        tool,
        [
            "tool_name",
            "profile_id",
            "scope",
            "input_schema_fingerprint_sha256",
            "output_receipt_profile",
            "replay_semantics",
            "side_effect_class",
            "risk",
            "approval_policy",
            "action",
            "resource_type",
            "coverage_status",
            "enforce_eligible",
            "authority_status",
        ],
        [],
        label,
    );
    exactString(tool.tool_name, TOOL_NAME_PATTERN, `${label}.tool_name`, 128);
    exactString(tool.profile_id, PROFILE_ID_PATTERN, `${label}.profile_id`);
    exactString(tool.scope, SCOPE_PATTERN, `${label}.scope`, 150);
    exactString(
        tool.input_schema_fingerprint_sha256,
        SHA256_PATTERN,
        `${label}.input_schema_fingerprint_sha256`,
        71,
    );
    exactString(tool.action, ACTION_PATTERN, `${label}.action`, 64);
    exactString(
        tool.resource_type,
        ACTION_PATTERN,
        `${label}.resource_type`,
        64,
    );
    if (!RECEIPT_PROFILES.has(tool.output_receipt_profile)
        || !REPLAY_SEMANTICS.has(tool.replay_semantics)
        || !SIDE_EFFECT_CLASSES.has(tool.side_effect_class)
        || !RISKS.has(tool.risk)
        || !APPROVAL_POLICIES.has(tool.approval_policy)
        || tool.coverage_status !== "covered_contract_only"
        || tool.enforce_eligible !== false
        || tool.authority_status !== "discovery_only_no_authority") {
        fail(
            "CONNECTOR_BETA_SNAPSHOT_INVALID",
            `${label} is invalid.`,
        );
    }
    if ((tool.risk === "high" || tool.risk === "critical")
        && tool.approval_policy !== "allow_once") {
        fail(
            "CONNECTOR_BETA_APPROVAL_INVALID",
            `${label} requires allow-once approval.`,
        );
    }
}

export function validateConnectorBetaFoundationV1(snapshot) {
    assertExactKeys(
        snapshot,
        [
            "contract_version",
            "development_identity",
            "activation_state",
            "live_connector_use_allowed",
            "foundation_id",
            "capture_kind",
            "captured_at",
            "runtime_binding",
            "metrics",
            "connectors",
            "safety",
            "foundation_fingerprint_sha256",
        ],
        [],
        "connector beta foundation",
    );
    if (snapshot.contract_version
            !== CONNECTOR_BETA_FOUNDATION_CONTRACT_VERSION
        || snapshot.development_identity
            !== CONNECTOR_BETA_DEVELOPMENT_IDENTITY
        || snapshot.activation_state !== "discovery_only"
        || snapshot.live_connector_use_allowed !== false
        || !CAPTURE_KINDS.has(snapshot.capture_kind)
        || !Number.isFinite(Date.parse(snapshot.captured_at))) {
        fail(
            "CONNECTOR_BETA_SNAPSHOT_INVALID",
            "Connector Beta foundation metadata is invalid.",
        );
    }
    exactString(
        snapshot.foundation_id,
        FOUNDATION_ID_PATTERN,
        "foundation_id",
        101,
    );
    assertExactKeys(
        snapshot.runtime_binding,
        [
            "platform",
            "openclaw_version",
            "plugin_api_version",
            "catalog_kind",
            "agent_id_fingerprint_sha256",
            "inventory_contract_version",
            "inventory_generation",
            "inventory_snapshot_fingerprint_sha256",
            "registry_version",
            "policy_version",
        ],
        [],
        "runtime_binding",
    );
    if (snapshot.runtime_binding.platform !== "openclaw"
        || snapshot.runtime_binding.inventory_contract_version
            !== "noderooms-runtime-tool-inventory-v1"
        || !["tools_catalog", "tools_effective", "contract_fixture"].includes(
            snapshot.runtime_binding.catalog_kind,
        )
        || (snapshot.capture_kind === "contract_fixture")
            !== (snapshot.runtime_binding.catalog_kind === "contract_fixture")
        || !Number.isSafeInteger(
            snapshot.runtime_binding.inventory_generation,
        )
        || snapshot.runtime_binding.inventory_generation < 1) {
        fail(
            "CONNECTOR_BETA_RUNTIME_BINDING_INVALID",
            "runtime_binding is invalid.",
        );
    }
    exactVersion(
        snapshot.runtime_binding.openclaw_version,
        "runtime_binding.openclaw_version",
    );
    exactVersion(
        snapshot.runtime_binding.plugin_api_version,
        "runtime_binding.plugin_api_version",
    );
    for (const key of [
        "agent_id_fingerprint_sha256",
        "inventory_snapshot_fingerprint_sha256",
    ]) {
        exactString(
            snapshot.runtime_binding[key],
            SHA256_PATTERN,
            `runtime_binding.${key}`,
            71,
        );
    }
    exactString(
        snapshot.runtime_binding.registry_version,
        REGISTRY_VERSION_PATTERN,
        "runtime_binding.registry_version",
        68,
    );
    exactString(
        snapshot.runtime_binding.policy_version,
        POLICY_VERSION_PATTERN,
        "runtime_binding.policy_version",
        67,
    );
    assertExactKeys(
        snapshot.metrics,
        [
            "connector_count",
            "connector_family_count",
            "tool_binding_count",
            "schema_verified_tool_count",
            "unclassified_tool_count",
            "drifted_tool_count",
        ],
        [],
        "metrics",
    );
    if (!Array.isArray(snapshot.connectors)
        || snapshot.connectors.length < 1
        || snapshot.connectors.length > MAX_CONNECTORS) {
        fail(
            "CONNECTOR_BETA_SNAPSHOT_INVALID",
            "connectors is invalid.",
        );
    }
    const connectorKeys = [];
    const allToolNames = [];
    const families = new Set();
    let toolBindingCount = 0;
    for (const [connectorIndex, connector] of snapshot.connectors.entries()) {
        const label = `connectors[${connectorIndex}]`;
        assertExactKeys(
            connector,
            [
                "connector_key",
                "family",
                "status",
                "owner",
                "provider",
                "connector_id",
                "connector_version",
                "credential_custodian",
                "noderooms_stores_provider_credentials",
                "tools",
                "authority_status",
            ],
            [],
            label,
        );
        exactString(
            connector.connector_key,
            CONNECTOR_KEY_PATTERN,
            `${label}.connector_key`,
            101,
        );
        if (!CONNECTOR_FAMILIES.has(connector.family)
            || (snapshot.capture_kind === "contract_fixture")
                !== (connector.family === "reference")
            || connector.status !== (
                snapshot.capture_kind === "contract_fixture"
                    ? "reference_only"
                    : "inventory_verified_non_live"
            )
            || connector.credential_custodian !== "openclaw"
            || connector.noderooms_stores_provider_credentials !== false
            || connector.authority_status
                !== "discovery_only_no_authority") {
            fail(
                "CONNECTOR_BETA_SNAPSHOT_INVALID",
                `${label} safety metadata is invalid.`,
            );
        }
        assertExactKeys(
            connector.owner,
            [
                "kind",
                "owner_id",
                "resolution",
                "owner_version",
                "version_source",
            ],
            [],
            `${label}.owner`,
        );
        if (!OWNER_KINDS.has(connector.owner.kind)
            || connector.owner.resolution !== "exact"
            || !VERSION_SOURCES.has(connector.owner.version_source)
            || (snapshot.capture_kind === "contract_fixture")
                !== (connector.owner.version_source === "contract_fixture")) {
            fail(
                "CONNECTOR_BETA_OWNER_INVALID",
                `${label}.owner is invalid.`,
            );
        }
        exactString(
            connector.owner.owner_id,
            OWNER_ID_PATTERN,
            `${label}.owner.owner_id`,
            160,
        );
        exactVersion(
            connector.owner.owner_version,
            `${label}.owner.owner_version`,
        );
        exactString(
            connector.provider,
            PROVIDER_PATTERN,
            `${label}.provider`,
            32,
        );
        exactString(
            connector.connector_id,
            CONNECTOR_ID_PATTERN,
            `${label}.connector_id`,
            128,
        );
        exactVersion(
            connector.connector_version,
            `${label}.connector_version`,
        );
        if (!Array.isArray(connector.tools)
            || connector.tools.length < 1
            || connector.tools.length > MAX_TOOLS_PER_CONNECTOR) {
            fail(
                "CONNECTOR_BETA_TOOLS_INVALID",
                `${label}.tools is invalid.`,
            );
        }
        for (const [toolIndex, tool] of connector.tools.entries()) {
            validateToolSnapshot(tool, `${label}.tools[${toolIndex}]`);
            allToolNames.push(tool.tool_name);
        }
        connectorKeys.push(connector.connector_key);
        families.add(connector.family);
        toolBindingCount += connector.tools.length;
    }
    if (new Set(connectorKeys).size !== connectorKeys.length
        || new Set(allToolNames).size !== allToolNames.length) {
        fail(
            "CONNECTOR_BETA_SNAPSHOT_DUPLICATE",
            "Connector Beta snapshot contains duplicate bindings.",
        );
    }
    if (snapshot.metrics.connector_count !== snapshot.connectors.length
        || snapshot.metrics.connector_family_count !== families.size
        || snapshot.metrics.tool_binding_count !== toolBindingCount
        || snapshot.metrics.schema_verified_tool_count !== toolBindingCount
        || snapshot.metrics.unclassified_tool_count !== 0
        || snapshot.metrics.drifted_tool_count !== 0) {
        fail(
            "CONNECTOR_BETA_METRICS_INVALID",
            "Connector Beta metrics are invalid.",
        );
    }
    assertExactKeys(
        snapshot.safety,
        [
            "grants_authority",
            "executes_tools",
            "invokes_connectors",
            "performs_network_request",
            "performs_external_write",
            "stores_provider_credentials",
            "stores_raw_schema",
            "stores_raw_parameters",
            "stores_raw_results",
            "automates_owner_decision",
        ],
        [],
        "safety",
    );
    if (Object.values(snapshot.safety).some((value) => value !== false)) {
        fail(
            "CONNECTOR_BETA_SAFETY_INVALID",
            "Connector Beta safety boundary is invalid.",
        );
    }
    exactString(
        snapshot.foundation_fingerprint_sha256,
        SHA256_PATTERN,
        "foundation_fingerprint_sha256",
        71,
    );
    if (connectorBetaFoundationFingerprint(snapshot)
        !== snapshot.foundation_fingerprint_sha256) {
        fail(
            "CONNECTOR_BETA_FINGERPRINT_DRIFT",
            "Connector Beta foundation fingerprint has drifted.",
        );
    }
    return snapshot;
}
