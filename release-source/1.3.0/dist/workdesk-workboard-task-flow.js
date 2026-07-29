import { sha256Fingerprint } from "./passport-runtime-binding.js";

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const WORK_ITEM_PATTERN = /^nrwork_[a-f0-9]{32}$/;
const MISSION_PATTERN = /^nrmission_[a-f0-9]{32}$/;
const WORK_RECEIPT_PATTERN = /^nrworkrcpt_[a-f0-9]{32}$/;
const ARTIFACT_PATTERN = /^nrartifact_[a-f0-9]{32}$/;
const LEASE_PATTERN = /^nrlv2_[a-f0-9]{32}$/;
const EXTERNAL_RECEIPT_PATTERN = /^nrear_[a-f0-9]{32}$/;
const PASSPORT_PATTERN = /^NRP-[0-9]{6}-AGENT$/;
const OWNER_BINDING_PATTERN = /^NRPB-[A-F0-9]{24}$/;
const RUNTIME_BINDING_PATTERN = /^nrbind_[a-f0-9]{32}$/;
const STEP_PATTERN = /^[a-z][a-z0-9_]{1,63}$/;
const CONTEXT_ID_PATTERN = /^[A-Za-z0-9._:/-]{1,200}$/;
const CONTROLLER_PATTERN = /^[a-z][a-z0-9._/-]{2,127}$/;
const PROFILE_PATTERN = /^nrscp_[a-z0-9][a-z0-9_]{2,95}$/;
const SCOPE_PATTERN = /^connector\.[a-z][a-z0-9_]{1,31}\.[a-z][a-z0-9_]{1,47}\.[a-z][a-z0-9_]{1,47}$/;
const TOOL_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const RESOURCE_TYPE_PATTERN = /^[a-z][a-z0-9_]{1,63}$/;
const CURRENCY_PATTERN = /^[A-Z]{3}$/;
const TIMEZONE_PATTERN = /^[A-Za-z_]+(?:\/[A-Za-z0-9_+-]+)+$/;
const LOCAL_TIME_PATTERN = /^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/;
const WORKBOARD_STATUSES = new Set([
    "triage",
    "backlog",
    "todo",
    "scheduled",
    "ready",
    "running",
    "review",
    "blocked",
    "done",
]);
const FLOW_STATUSES = new Set([
    "queued",
    "running",
    "waiting",
    "blocked",
    "succeeded",
    "failed",
    "cancelled",
    "lost",
]);
const TASK_STATUSES = new Set([
    "queued",
    "running",
    "completed",
    "blocked",
    "cancelled",
]);
const OWNER_GATE_STATUSES = new Set([
    "waiting",
    "approved",
    "rejected",
    "cancelled",
]);
const MAX_STEPS = 32;
const MAX_ARTIFACTS_PER_RECEIPT = 32;
const MAX_WORK_ITEM_TTL_MS = 90 * 24 * 60 * 60 * 1000;

export class WorkdeskTaskFlowContractError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "WorkdeskTaskFlowContractError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new WorkdeskTaskFlowContractError(code, message);
}

function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function assertObjectShape(value, required, optional, label) {
    if (!isRecord(value)) {
        fail("INVALID_OBJECT", `${label} must be an object.`);
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail("UNKNOWN_FIELD", `${label} contains unsupported field ${key}.`);
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail("MISSING_FIELD", `${label} is missing ${key}.`);
        }
    }
}

function assertString(value, pattern, label) {
    if (typeof value !== "string" || !pattern.test(value)) {
        fail("INVALID_STRING", `${label} is invalid.`);
    }
    return value;
}

function assertBoundedString(value, label, minimum = 1, maximum = 256) {
    if (typeof value !== "string"
        || value.length < minimum
        || value.length > maximum) {
        fail("INVALID_STRING", `${label} is invalid.`);
    }
    return value;
}

function assertBoolean(value, expected, label) {
    if (typeof value !== "boolean"
        || (expected !== undefined && value !== expected)) {
        fail("INVALID_BOOLEAN", `${label} is invalid.`);
    }
    return value;
}

function assertInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        fail("INVALID_INTEGER", `${label} is invalid.`);
    }
    return value;
}

function parseTime(value, label) {
    const parsed = typeof value === "string" ? Date.parse(value) : Number.NaN;
    if (!Number.isFinite(parsed)) {
        fail("INVALID_TIMESTAMP", `${label} is invalid.`);
    }
    return parsed;
}

function normalizeNow(value) {
    const parsed = value instanceof Date ? value.getTime() : Number(value);
    if (!Number.isFinite(parsed)) {
        fail("INVALID_NOW", "The evaluation time is invalid.");
    }
    return parsed;
}

function assertNullableString(value, pattern, label) {
    if (value !== null) {
        assertString(value, pattern, label);
    }
}

function assertStringArray(value, label, options = {}) {
    const {
        pattern,
        minimum = 0,
        maximum = 128,
        unique = true,
    } = options;
    if (!Array.isArray(value)
        || value.length < minimum
        || value.length > maximum) {
        fail("INVALID_ARRAY", `${label} is invalid.`);
    }
    for (const [index, entry] of value.entries()) {
        if (pattern) {
            assertString(entry, pattern, `${label}[${index}]`);
        } else {
            assertBoundedString(entry, `${label}[${index}]`, 1, 256);
        }
    }
    if (unique && new Set(value).size !== value.length) {
        fail("DUPLICATE_VALUE", `${label} contains duplicate values.`);
    }
    return value;
}

function sameJson(left, right) {
    return sha256Fingerprint(left) === sha256Fingerprint(right);
}

function sameStringSet(left, right) {
    return left.length === right.length
        && [...left].sort().every((value, index) => value === [...right].sort()[index]);
}

function fixtureGate(value, allowFixture, label) {
    assertBoolean(value.fixture, undefined, `${label}.fixture`);
    if (value.fixture && !allowFixture) {
        fail("FIXTURE_REJECTED", `${label} is a non-live fixture.`);
    }
}

function contractOnlyGate(value, allowContractOnly, label) {
    if (value.activation_state !== "contract_only") {
        fail("ACTIVATION_STATE_INVALID", `${label} is not contract-only.`);
    }
    assertBoolean(
        value.live_dispatch_allowed,
        false,
        `${label}.live_dispatch_allowed`,
    );
    if (!allowContractOnly) {
        fail("LIVE_DISPATCH_PROHIBITED", `${label} cannot authorize live work.`);
    }
}

function assertNoWildcard(value, path = "$") {
    if (typeof value === "string") {
        if (/[*{}[\]]/.test(value)) {
            fail("WILDCARD_FORBIDDEN", `Wildcard-like syntax is forbidden at ${path}.`);
        }
        return;
    }
    if (Array.isArray(value)) {
        value.forEach((entry, index) => assertNoWildcard(entry, `${path}[${index}]`));
        return;
    }
    if (!isRecord(value)) {
        return;
    }
    for (const [key, entry] of Object.entries(value)) {
        if (/[*{}[\]]/.test(key)) {
            fail("WILDCARD_FORBIDDEN", `Wildcard-like key is forbidden at ${path}.${key}.`);
        }
        assertNoWildcard(entry, `${path}.${key}`);
    }
}

function assertNoSensitiveFields(value, path = "$") {
    if (Array.isArray(value)) {
        value.forEach((entry, index) => assertNoSensitiveFields(entry, `${path}[${index}]`));
        return;
    }
    if (!isRecord(value)) {
        return;
    }
    for (const [key, entry] of Object.entries(value)) {
        const safePolicyBoolean = typeof entry === "boolean"
            && /(?:allowed|included|persisted|performed|required|inherited|automated|redacted|safe)$/i
                .test(key);
        if (!safePolicyBoolean
            && /(?:secret|token|authorization|cookie|credential|private_key|raw_prompt|raw_request|raw_response|raw_result|raw_body)/i
                .test(key)) {
            fail(
                "SENSITIVE_FIELD_FORBIDDEN",
                `Sensitive field is forbidden at ${path}.${key}.`,
            );
        }
        assertNoSensitiveFields(entry, `${path}.${key}`);
    }
}

function validateAgentBinding(value, label = "agent_binding") {
    assertObjectShape(value, [
        "noderooms_agent_id",
        "passport_id",
        "owner_binding_id",
        "verified_owner_required",
    ], [], label);
    assertInteger(value.noderooms_agent_id, `${label}.noderooms_agent_id`, 1);
    assertString(value.passport_id, PASSPORT_PATTERN, `${label}.passport_id`);
    assertString(value.owner_binding_id, OWNER_BINDING_PATTERN, `${label}.owner_binding_id`);
    assertBoolean(value.verified_owner_required, true, `${label}.verified_owner_required`);
    return value;
}

function validateRuntimeBinding(value, label = "runtime_binding") {
    assertObjectShape(value, [
        "binding_id",
        "openclaw_agent_id",
        "session_key_fingerprint_sha256",
        "requester_origin_fingerprint_sha256",
    ], [], label);
    assertString(value.binding_id, RUNTIME_BINDING_PATTERN, `${label}.binding_id`);
    assertString(value.openclaw_agent_id, CONTEXT_ID_PATTERN, `${label}.openclaw_agent_id`);
    assertString(
        value.session_key_fingerprint_sha256,
        SHA256_PATTERN,
        `${label}.session_key_fingerprint_sha256`,
    );
    assertString(
        value.requester_origin_fingerprint_sha256,
        SHA256_PATTERN,
        `${label}.requester_origin_fingerprint_sha256`,
    );
    return value;
}

function validateExactResource(value, label = "resource") {
    assertObjectShape(value, [
        "resource_type",
        "selector",
        "selector_fingerprint_sha256",
    ], [], label);
    assertString(value.resource_type, RESOURCE_TYPE_PATTERN, `${label}.resource_type`);
    if (!isRecord(value.selector) || Object.keys(value.selector).length === 0) {
        fail("RESOURCE_SELECTOR_INVALID", `${label}.selector must be a non-empty object.`);
    }
    for (const [key, entry] of Object.entries(value.selector)) {
        assertString(key, /^[a-z][a-z0-9_]{1,63}$/, `${label}.selector key`);
        assertBoundedString(entry, `${label}.selector.${key}`, 1, 256);
    }
    assertString(
        value.selector_fingerprint_sha256,
        SHA256_PATTERN,
        `${label}.selector_fingerprint_sha256`,
    );
    if (value.selector_fingerprint_sha256 !== sha256Fingerprint(value.selector)) {
        fail("RESOURCE_FINGERPRINT_MISMATCH", `${label} selector fingerprint has drifted.`);
    }
    assertNoWildcard(value, label);
    return value;
}

function validateLeaseBinding(value, label = "lease_binding") {
    assertObjectShape(value, [
        "lease_id",
        "lease_authority_fingerprint_sha256",
        "contract_version",
    ], [], label);
    assertString(value.lease_id, LEASE_PATTERN, `${label}.lease_id`);
    assertString(
        value.lease_authority_fingerprint_sha256,
        SHA256_PATTERN,
        `${label}.lease_authority_fingerprint_sha256`,
    );
    if (value.contract_version !== "noderooms-run-lease-v2") {
        fail("LEASE_CONTRACT_MISMATCH", `${label}.contract_version is unsupported.`);
    }
    return value;
}

function validateArtifactReference(value, label = "artifact") {
    assertObjectShape(value, [
        "artifact_id",
        "kind",
        "content_sha256",
        "visibility",
        "raw_content_included",
    ], [], label);
    assertString(value.artifact_id, ARTIFACT_PATTERN, `${label}.artifact_id`);
    assertString(value.kind, /^[a-z][a-z0-9_]{1,63}$/, `${label}.kind`);
    assertString(value.content_sha256, SHA256_PATTERN, `${label}.content_sha256`);
    if (!["owner_only", "private_working", "public_safe_projection"].includes(value.visibility)) {
        fail("ARTIFACT_VISIBILITY_INVALID", `${label}.visibility is invalid.`);
    }
    assertBoolean(value.raw_content_included, false, `${label}.raw_content_included`);
    return value;
}

function validateStepDefinition(value, index, earlierStepIds) {
    const label = `steps[${index}]`;
    assertObjectShape(value, [
        "step_id",
        "kind",
        "depends_on",
        "execution_class",
        "connector_profile_id",
        "owner_gate_required",
        "lease_required",
        "receipt_required",
    ], [], label);
    assertString(value.step_id, STEP_PATTERN, `${label}.step_id`);
    if (!["task", "owner_gate"].includes(value.kind)) {
        fail("STEP_KIND_INVALID", `${label}.kind is invalid.`);
    }
    assertStringArray(value.depends_on, `${label}.depends_on`, {
        pattern: STEP_PATTERN,
        maximum: MAX_STEPS,
    });
    for (const dependency of value.depends_on) {
        if (!earlierStepIds.has(dependency)) {
            fail("STEP_DEPENDENCY_INVALID", `${label} has a missing or forward dependency.`);
        }
    }
    if (!["read", "local", "write", "none"].includes(value.execution_class)) {
        fail("EXECUTION_CLASS_INVALID", `${label}.execution_class is invalid.`);
    }
    assertNullableString(
        value.connector_profile_id,
        PROFILE_PATTERN,
        `${label}.connector_profile_id`,
    );
    assertBoolean(value.owner_gate_required, undefined, `${label}.owner_gate_required`);
    assertBoolean(value.lease_required, undefined, `${label}.lease_required`);
    assertBoolean(value.receipt_required, undefined, `${label}.receipt_required`);
    if (value.kind === "owner_gate") {
        if (value.execution_class !== "none"
            || value.connector_profile_id !== null
            || value.owner_gate_required !== true
            || value.lease_required !== false
            || value.receipt_required !== false) {
            fail("OWNER_GATE_POLICY_INVALID", `${label} owner gate policy is invalid.`);
        }
    } else if (value.execution_class === "none"
        || value.lease_required !== true
        || value.receipt_required !== true) {
        fail("TASK_AUTHORITY_POLICY_INVALID", `${label} task authority policy is invalid.`);
    }
    if (value.execution_class === "write"
        && (value.connector_profile_id === null || value.owner_gate_required !== true)) {
        fail("WRITE_STEP_POLICY_INVALID", `${label} write policy is invalid.`);
    }
    if (value.execution_class !== "write" && value.connector_profile_id !== null) {
        fail("CONNECTOR_PROFILE_UNEXPECTED", `${label} has an unexpected connector profile.`);
    }
    return value;
}

function validateConnectorAllowance(value, index) {
    const label = `connector_allowlist[${index}]`;
    assertObjectShape(value, [
        "profile_id",
        "scope",
        "tool_name",
        "resource",
        "max_actions",
        "owner_review_required",
    ], [], label);
    assertString(value.profile_id, PROFILE_PATTERN, `${label}.profile_id`);
    assertString(value.scope, SCOPE_PATTERN, `${label}.scope`);
    assertString(value.tool_name, TOOL_PATTERN, `${label}.tool_name`);
    validateExactResource(value.resource, `${label}.resource`);
    assertInteger(value.max_actions, `${label}.max_actions`, 1, 10);
    assertBoolean(
        value.owner_review_required,
        true,
        `${label}.owner_review_required`,
    );
    return value;
}

export function workItemProjection(workItem) {
    return {
        contract_version: workItem.contract_version,
        fixture: workItem.fixture,
        activation_state: workItem.activation_state,
        live_dispatch_allowed: workItem.live_dispatch_allowed,
        work_item_id: workItem.work_item_id,
        mission_id: workItem.mission_id,
        revision: workItem.revision,
        objective: workItem.objective,
        agent_binding: workItem.agent_binding,
        runtime_binding: workItem.runtime_binding,
        owner_policy: workItem.owner_policy,
        work_schedule: workItem.work_schedule,
        deadline_at: workItem.deadline_at,
        budget: workItem.budget,
        connector_allowlist: workItem.connector_allowlist,
        steps: workItem.steps,
        workflow: workItem.workflow,
        receipt_policy: workItem.receipt_policy,
        constraints: workItem.constraints,
        created_at: workItem.created_at,
        updated_at: workItem.updated_at,
    };
}

export function workItemFingerprint(workItem) {
    return sha256Fingerprint(workItemProjection(workItem));
}

export function validateWorkItemV1(workItem, options = {}) {
    const allowFixture = options.allowFixture === true;
    const allowContractOnly = options.allowContractOnly === true;
    const now = normalizeNow(options.now ?? Date.now());
    assertObjectShape(workItem, [
        "contract_version",
        "fixture",
        "activation_state",
        "live_dispatch_allowed",
        "work_item_id",
        "mission_id",
        "revision",
        "objective",
        "agent_binding",
        "runtime_binding",
        "owner_policy",
        "work_schedule",
        "deadline_at",
        "budget",
        "connector_allowlist",
        "steps",
        "workflow",
        "receipt_policy",
        "constraints",
        "created_at",
        "updated_at",
        "work_item_fingerprint_sha256",
    ], ["$schema", "$comment"], "work item");
    fixtureGate(workItem, allowFixture, "work item");
    contractOnlyGate(workItem, allowContractOnly, "work item");
    if (workItem.contract_version !== "noderooms-work-item-v1") {
        fail("CONTRACT_VERSION_MISMATCH", "Work item contract version is unsupported.");
    }
    assertString(workItem.work_item_id, WORK_ITEM_PATTERN, "work_item_id");
    assertString(workItem.mission_id, MISSION_PATTERN, "mission_id");
    assertInteger(workItem.revision, "revision", 1);
    assertObjectShape(workItem.objective, [
        "title",
        "summary_sha256",
        "completion_criteria_sha256",
    ], [], "objective");
    assertBoundedString(workItem.objective.title, "objective.title", 1, 160);
    assertString(workItem.objective.summary_sha256, SHA256_PATTERN, "objective.summary_sha256");
    assertString(
        workItem.objective.completion_criteria_sha256,
        SHA256_PATTERN,
        "objective.completion_criteria_sha256",
    );
    validateAgentBinding(workItem.agent_binding);
    validateRuntimeBinding(workItem.runtime_binding);

    assertObjectShape(workItem.owner_policy, [
        "owner_binding_id",
        "verified_human_owner_required",
        "automatic_owner_decision_allowed",
        "owner_review_step_id",
    ], [], "owner_policy");
    assertString(
        workItem.owner_policy.owner_binding_id,
        OWNER_BINDING_PATTERN,
        "owner_policy.owner_binding_id",
    );
    if (workItem.owner_policy.owner_binding_id !== workItem.agent_binding.owner_binding_id) {
        fail("OWNER_BINDING_MISMATCH", "Work item Owner binding has drifted.");
    }
    assertBoolean(
        workItem.owner_policy.verified_human_owner_required,
        true,
        "owner_policy.verified_human_owner_required",
    );
    assertBoolean(
        workItem.owner_policy.automatic_owner_decision_allowed,
        false,
        "owner_policy.automatic_owner_decision_allowed",
    );
    assertString(
        workItem.owner_policy.owner_review_step_id,
        STEP_PATTERN,
        "owner_policy.owner_review_step_id",
    );

    assertObjectShape(workItem.work_schedule, [
        "timezone",
        "working_days",
        "local_start",
        "local_end",
        "availability",
        "after_hours_start_allowed",
    ], [], "work_schedule");
    assertString(workItem.work_schedule.timezone, TIMEZONE_PATTERN, "work_schedule.timezone");
    if (!Array.isArray(workItem.work_schedule.working_days)
        || workItem.work_schedule.working_days.length === 0
        || workItem.work_schedule.working_days.length > 7
        || new Set(workItem.work_schedule.working_days).size
            !== workItem.work_schedule.working_days.length) {
        fail("WORKING_DAYS_INVALID", "work_schedule.working_days is invalid.");
    }
    for (const day of workItem.work_schedule.working_days) {
        assertInteger(day, "work_schedule.working_days[]", 1, 7);
    }
    assertString(
        workItem.work_schedule.local_start,
        LOCAL_TIME_PATTERN,
        "work_schedule.local_start",
    );
    assertString(
        workItem.work_schedule.local_end,
        LOCAL_TIME_PATTERN,
        "work_schedule.local_end",
    );
    if (workItem.work_schedule.local_start >= workItem.work_schedule.local_end) {
        fail("WORKING_HOURS_INVALID", "Working hours must have a positive local window.");
    }
    if (!["available", "busy", "off_hours", "paused"].includes(
        workItem.work_schedule.availability,
    )) {
        fail("AVAILABILITY_INVALID", "work_schedule.availability is invalid.");
    }
    assertBoolean(
        workItem.work_schedule.after_hours_start_allowed,
        false,
        "work_schedule.after_hours_start_allowed",
    );

    assertObjectShape(workItem.budget, [
        "currency",
        "max_minor_units",
        "automatic_spend_allowed",
    ], [], "budget");
    assertString(workItem.budget.currency, CURRENCY_PATTERN, "budget.currency");
    assertInteger(workItem.budget.max_minor_units, "budget.max_minor_units", 0, 1_000_000_000);
    assertBoolean(
        workItem.budget.automatic_spend_allowed,
        false,
        "budget.automatic_spend_allowed",
    );

    if (!Array.isArray(workItem.connector_allowlist)
        || workItem.connector_allowlist.length === 0
        || workItem.connector_allowlist.length > 16) {
        fail("CONNECTOR_ALLOWLIST_INVALID", "connector_allowlist is invalid.");
    }
    workItem.connector_allowlist.forEach(validateConnectorAllowance);
    const profileIds = workItem.connector_allowlist.map((entry) => entry.profile_id);
    if (new Set(profileIds).size !== profileIds.length) {
        fail("DUPLICATE_CONNECTOR_PROFILE", "connector_allowlist has duplicate profiles.");
    }

    if (!Array.isArray(workItem.steps)
        || workItem.steps.length < 2
        || workItem.steps.length > MAX_STEPS) {
        fail("STEPS_INVALID", "Work item steps are invalid.");
    }
    const earlierStepIds = new Set();
    for (const [index, step] of workItem.steps.entries()) {
        validateStepDefinition(step, index, earlierStepIds);
        if (earlierStepIds.has(step.step_id)) {
            fail("DUPLICATE_STEP_ID", `Duplicate step id ${step.step_id}.`);
        }
        earlierStepIds.add(step.step_id);
    }
    const ownerGates = workItem.steps.filter((step) => step.kind === "owner_gate");
    if (ownerGates.length !== 1
        || ownerGates[0].step_id !== workItem.owner_policy.owner_review_step_id) {
        fail("OWNER_GATE_MISMATCH", "Work item must have one exact Owner-review gate.");
    }
    const writeSteps = workItem.steps.filter((step) => step.execution_class === "write");
    if (writeSteps.length === 0) {
        fail("WRITE_STEP_MISSING", "Work item has no governed external write step.");
    }
    for (const step of writeSteps) {
        if (!profileIds.includes(step.connector_profile_id)) {
            fail("WRITE_PROFILE_NOT_ALLOWED", `Step ${step.step_id} profile is not allowed.`);
        }
    }

    assertObjectShape(workItem.workflow, [
        "controller_id",
        "status",
        "current_step_id",
        "ordered_step_ids",
    ], [], "workflow");
    assertString(workItem.workflow.controller_id, CONTROLLER_PATTERN, "workflow.controller_id");
    if (![
        "accepted",
        "running",
        "waiting_owner_review",
        "blocked",
        "completed",
        "cancelled",
    ].includes(workItem.workflow.status)) {
        fail("WORKFLOW_STATUS_INVALID", "workflow.status is invalid.");
    }
    assertString(workItem.workflow.current_step_id, STEP_PATTERN, "workflow.current_step_id");
    const stepIds = workItem.steps.map((step) => step.step_id);
    assertStringArray(workItem.workflow.ordered_step_ids, "workflow.ordered_step_ids", {
        pattern: STEP_PATTERN,
        minimum: workItem.steps.length,
        maximum: workItem.steps.length,
    });
    if (!sameJson(stepIds, workItem.workflow.ordered_step_ids)
        || !stepIds.includes(workItem.workflow.current_step_id)) {
        fail("WORKFLOW_STEP_ORDER_MISMATCH", "Workflow step ordering has drifted.");
    }
    if (workItem.workflow.status === "waiting_owner_review"
        && workItem.workflow.current_step_id !== workItem.owner_policy.owner_review_step_id) {
        fail("OWNER_REVIEW_STATE_INVALID", "Owner-review wait must point to its gate.");
    }

    assertObjectShape(workItem.receipt_policy, [
        "per_task_step_receipt_required",
        "external_write_receipt_required",
        "public_safe_projection_required",
        "raw_work_content_persisted",
    ], [], "receipt_policy");
    assertBoolean(
        workItem.receipt_policy.per_task_step_receipt_required,
        true,
        "receipt_policy.per_task_step_receipt_required",
    );
    assertBoolean(
        workItem.receipt_policy.external_write_receipt_required,
        true,
        "receipt_policy.external_write_receipt_required",
    );
    assertBoolean(
        workItem.receipt_policy.public_safe_projection_required,
        true,
        "receipt_policy.public_safe_projection_required",
    );
    assertBoolean(
        workItem.receipt_policy.raw_work_content_persisted,
        false,
        "receipt_policy.raw_work_content_persisted",
    );

    assertObjectShape(workItem.constraints, [
        "noderooms_workdesk_is_canonical",
        "workboard_can_grant_authority",
        "per_task_step_lease_required",
        "subagent_privilege_inheritance_allowed",
        "shared_lease_allowed",
        "wildcard_scope_allowed",
        "public_write_allowed",
        "automatic_external_write_retry_allowed",
        "owner_decision_automated",
    ], [], "constraints");
    assertBoolean(
        workItem.constraints.noderooms_workdesk_is_canonical,
        true,
        "constraints.noderooms_workdesk_is_canonical",
    );
    for (const field of [
        "workboard_can_grant_authority",
        "subagent_privilege_inheritance_allowed",
        "shared_lease_allowed",
        "wildcard_scope_allowed",
        "public_write_allowed",
        "automatic_external_write_retry_allowed",
        "owner_decision_automated",
    ]) {
        assertBoolean(workItem.constraints[field], false, `constraints.${field}`);
    }
    assertBoolean(
        workItem.constraints.per_task_step_lease_required,
        true,
        "constraints.per_task_step_lease_required",
    );

    const createdAt = parseTime(workItem.created_at, "created_at");
    const updatedAt = parseTime(workItem.updated_at, "updated_at");
    const deadlineAt = parseTime(workItem.deadline_at, "deadline_at");
    if (updatedAt < createdAt
        || deadlineAt <= createdAt
        || deadlineAt - createdAt > MAX_WORK_ITEM_TTL_MS) {
        fail("WORK_ITEM_TIME_WINDOW_INVALID", "Work item time window is invalid.");
    }
    if (options.requireUnexpired === true && now >= deadlineAt) {
        fail("WORK_ITEM_EXPIRED", "Work item deadline has passed.");
    }
    assertString(
        workItem.work_item_fingerprint_sha256,
        SHA256_PATTERN,
        "work_item_fingerprint_sha256",
    );
    if (workItem.work_item_fingerprint_sha256 !== workItemFingerprint(workItem)) {
        fail("WORK_ITEM_FINGERPRINT_MISMATCH", "Work item fingerprint has drifted.");
    }
    assertNoWildcard(workItem, "work item");
    assertNoSensitiveFields(workItem, "work item");
    return workItem;
}

export function publicWorkReceiptProjection(receipt) {
    return {
        contract_version: receipt.public_projection.contract_version,
        work_item_id: receipt.public_projection.work_item_id,
        mission_id: receipt.public_projection.mission_id,
        step_id: receipt.public_projection.step_id,
        noderooms_agent_id: receipt.public_projection.noderooms_agent_id,
        outcome_status: receipt.public_projection.outcome_status,
        completed_at: receipt.public_projection.completed_at,
        artifact_count: receipt.public_projection.artifact_count,
        external_write_performed: receipt.public_projection.external_write_performed,
        raw_content_included: receipt.public_projection.raw_content_included,
        provider_credentials_included:
            receipt.public_projection.provider_credentials_included,
        safe_for_public: receipt.public_projection.safe_for_public,
    };
}

export function publicWorkReceiptProjectionFingerprint(receipt) {
    return sha256Fingerprint(publicWorkReceiptProjection(receipt));
}

export function workStepReceiptProjection(receipt) {
    return {
        contract_version: receipt.contract_version,
        fixture: receipt.fixture,
        activation_state: receipt.activation_state,
        live_dispatch_allowed: receipt.live_dispatch_allowed,
        receipt_id: receipt.receipt_id,
        work_item_binding: receipt.work_item_binding,
        step_binding: receipt.step_binding,
        agent_binding: receipt.agent_binding,
        runtime_binding: receipt.runtime_binding,
        outcome: receipt.outcome,
        artifacts: receipt.artifacts,
        external_action_receipt_binding: receipt.external_action_receipt_binding,
        public_projection: receipt.public_projection,
        constraints: receipt.constraints,
        recorded_at: receipt.recorded_at,
    };
}

export function workStepReceiptFingerprint(receipt) {
    return sha256Fingerprint(workStepReceiptProjection(receipt));
}

export function validateWorkStepReceiptV1(receipt, workItem, options = {}) {
    validateWorkItemV1(workItem, options);
    const allowFixture = options.allowFixture === true;
    const allowContractOnly = options.allowContractOnly === true;
    assertObjectShape(receipt, [
        "contract_version",
        "fixture",
        "activation_state",
        "live_dispatch_allowed",
        "receipt_id",
        "work_item_binding",
        "step_binding",
        "agent_binding",
        "runtime_binding",
        "outcome",
        "artifacts",
        "external_action_receipt_binding",
        "public_projection",
        "constraints",
        "recorded_at",
        "receipt_fingerprint_sha256",
    ], ["$schema", "$comment"], "work-step receipt");
    fixtureGate(receipt, allowFixture, "work-step receipt");
    contractOnlyGate(receipt, allowContractOnly, "work-step receipt");
    if (receipt.contract_version !== "noderooms-work-step-receipt-v1") {
        fail("CONTRACT_VERSION_MISMATCH", "Work-step receipt version is unsupported.");
    }
    assertString(receipt.receipt_id, WORK_RECEIPT_PATTERN, "receipt_id");
    assertObjectShape(receipt.work_item_binding, [
        "work_item_id",
        "mission_id",
        "work_item_revision",
        "work_item_fingerprint_sha256",
    ], [], "work_item_binding");
    if (receipt.work_item_binding.work_item_id !== workItem.work_item_id
        || receipt.work_item_binding.mission_id !== workItem.mission_id
        || receipt.work_item_binding.work_item_revision !== workItem.revision
        || receipt.work_item_binding.work_item_fingerprint_sha256
            !== workItem.work_item_fingerprint_sha256) {
        fail("WORK_ITEM_BINDING_MISMATCH", "Receipt work-item binding has drifted.");
    }

    assertObjectShape(receipt.step_binding, [
        "step_id",
        "execution_class",
        "attempt",
        "lease",
    ], [], "step_binding");
    assertString(receipt.step_binding.step_id, STEP_PATTERN, "step_binding.step_id");
    assertInteger(receipt.step_binding.attempt, "step_binding.attempt", 1, 10);
    validateLeaseBinding(receipt.step_binding.lease, "step_binding.lease");
    const step = workItem.steps.find(
        (candidate) => candidate.step_id === receipt.step_binding.step_id,
    );
    if (!step || step.kind !== "task") {
        fail("RECEIPT_STEP_INVALID", "Receipt does not bind an executable task step.");
    }
    if (receipt.step_binding.execution_class !== step.execution_class) {
        fail("RECEIPT_STEP_MISMATCH", "Receipt execution class has drifted.");
    }
    validateAgentBinding(receipt.agent_binding);
    validateRuntimeBinding(receipt.runtime_binding);
    if (!sameJson(receipt.agent_binding, workItem.agent_binding)
        || !sameJson(receipt.runtime_binding, workItem.runtime_binding)) {
        fail("RECEIPT_ACTOR_MISMATCH", "Receipt actor binding has drifted.");
    }

    assertObjectShape(receipt.outcome, [
        "status",
        "reason_code",
        "started_at",
        "completed_at",
    ], [], "outcome");
    if (!["completed", "blocked", "cancelled"].includes(receipt.outcome.status)) {
        fail("RECEIPT_OUTCOME_INVALID", "Receipt outcome status is invalid.");
    }
    if (receipt.outcome.reason_code !== null) {
        assertString(
            receipt.outcome.reason_code,
            /^[A-Z][A-Z0-9_]{2,95}$/,
            "outcome.reason_code",
        );
    }
    const startedAt = parseTime(receipt.outcome.started_at, "outcome.started_at");
    const completedAt = parseTime(receipt.outcome.completed_at, "outcome.completed_at");
    if (completedAt < startedAt) {
        fail("RECEIPT_TIME_ORDER_INVALID", "Receipt completion precedes its start.");
    }
    if (!Array.isArray(receipt.artifacts)
        || receipt.artifacts.length > MAX_ARTIFACTS_PER_RECEIPT) {
        fail("RECEIPT_ARTIFACTS_INVALID", "Receipt artifacts are invalid.");
    }
    receipt.artifacts.forEach((artifact, index) => {
        validateArtifactReference(artifact, `artifacts[${index}]`);
    });
    const artifactIds = receipt.artifacts.map((artifact) => artifact.artifact_id);
    if (new Set(artifactIds).size !== artifactIds.length) {
        fail("DUPLICATE_ARTIFACT_ID", "Receipt contains duplicate artifacts.");
    }

    if (step.execution_class === "write") {
        assertObjectShape(receipt.external_action_receipt_binding, [
            "receipt_id",
            "receipt_fingerprint_sha256",
        ], [], "external_action_receipt_binding");
        assertString(
            receipt.external_action_receipt_binding.receipt_id,
            EXTERNAL_RECEIPT_PATTERN,
            "external_action_receipt_binding.receipt_id",
        );
        assertString(
            receipt.external_action_receipt_binding.receipt_fingerprint_sha256,
            SHA256_PATTERN,
            "external_action_receipt_binding.receipt_fingerprint_sha256",
        );
    } else if (receipt.external_action_receipt_binding !== null) {
        fail(
            "EXTERNAL_RECEIPT_UNEXPECTED",
            "Non-write work receipt cannot claim an external action receipt.",
        );
    }

    assertObjectShape(receipt.public_projection, [
        "contract_version",
        "work_item_id",
        "mission_id",
        "step_id",
        "noderooms_agent_id",
        "outcome_status",
        "completed_at",
        "artifact_count",
        "external_write_performed",
        "raw_content_included",
        "provider_credentials_included",
        "safe_for_public",
        "projection_fingerprint_sha256",
    ], [], "public_projection");
    if (receipt.public_projection.contract_version
            !== "noderooms-public-work-receipt-v1"
        || receipt.public_projection.work_item_id !== workItem.work_item_id
        || receipt.public_projection.mission_id !== workItem.mission_id
        || receipt.public_projection.step_id !== step.step_id
        || receipt.public_projection.noderooms_agent_id
            !== workItem.agent_binding.noderooms_agent_id
        || receipt.public_projection.outcome_status !== receipt.outcome.status
        || receipt.public_projection.completed_at !== receipt.outcome.completed_at
        || receipt.public_projection.artifact_count !== receipt.artifacts.length) {
        fail("PUBLIC_RECEIPT_BINDING_MISMATCH", "Public receipt projection has drifted.");
    }
    assertBoolean(
        receipt.public_projection.external_write_performed,
        step.execution_class === "write",
        "public_projection.external_write_performed",
    );
    assertBoolean(
        receipt.public_projection.raw_content_included,
        false,
        "public_projection.raw_content_included",
    );
    assertBoolean(
        receipt.public_projection.provider_credentials_included,
        false,
        "public_projection.provider_credentials_included",
    );
    assertBoolean(
        receipt.public_projection.safe_for_public,
        true,
        "public_projection.safe_for_public",
    );
    assertString(
        receipt.public_projection.projection_fingerprint_sha256,
        SHA256_PATTERN,
        "public_projection.projection_fingerprint_sha256",
    );
    if (receipt.public_projection.projection_fingerprint_sha256
            !== publicWorkReceiptProjectionFingerprint(receipt)) {
        fail(
            "PUBLIC_RECEIPT_FINGERPRINT_MISMATCH",
            "Public receipt projection fingerprint has drifted.",
        );
    }

    assertObjectShape(receipt.constraints, [
        "raw_prompt_included",
        "raw_result_included",
        "provider_credentials_included",
        "noderooms_public_write_performed",
        "reputation_mutation_allowed",
    ], [], "constraints");
    for (const field of [
        "raw_prompt_included",
        "raw_result_included",
        "provider_credentials_included",
        "noderooms_public_write_performed",
        "reputation_mutation_allowed",
    ]) {
        assertBoolean(receipt.constraints[field], false, `constraints.${field}`);
    }
    if (parseTime(receipt.recorded_at, "recorded_at") < completedAt) {
        fail("RECEIPT_RECORDED_TIME_INVALID", "Receipt was recorded before completion.");
    }
    assertString(
        receipt.receipt_fingerprint_sha256,
        SHA256_PATTERN,
        "receipt_fingerprint_sha256",
    );
    if (receipt.receipt_fingerprint_sha256 !== workStepReceiptFingerprint(receipt)) {
        fail("WORK_RECEIPT_FINGERPRINT_MISMATCH", "Work receipt fingerprint has drifted.");
    }
    assertNoWildcard(receipt, "work-step receipt");
    assertNoSensitiveFields(receipt, "work-step receipt");
    return receipt;
}

function validateTaskBinding(value, label) {
    assertObjectShape(value, [
        "task_id",
        "run_id",
        "status",
    ], [], label);
    assertString(value.task_id, CONTEXT_ID_PATTERN, `${label}.task_id`);
    assertString(value.run_id, CONTEXT_ID_PATTERN, `${label}.run_id`);
    if (!["queued", "running", "succeeded", "failed", "cancelled", "lost"].includes(
        value.status,
    )) {
        fail("TASK_BINDING_STATUS_INVALID", `${label}.status is invalid.`);
    }
    return value;
}

function validateFlowNode(value, index, workItem, receiptMap) {
    const label = `nodes[${index}]`;
    assertObjectShape(value, [
        "step_id",
        "kind",
        "status",
        "depends_on",
        "task_binding",
        "lease_binding",
        "receipt_binding",
        "artifact_refs",
        "external_action_receipt_binding",
        "started_at",
        "completed_at",
    ], [], label);
    assertString(value.step_id, STEP_PATTERN, `${label}.step_id`);
    const definition = workItem.steps.find((step) => step.step_id === value.step_id);
    if (!definition
        || definition.kind !== value.kind
        || !sameJson(definition.depends_on, value.depends_on)) {
        fail("FLOW_NODE_DEFINITION_MISMATCH", `${label} does not match the work item.`);
    }
    assertStringArray(value.depends_on, `${label}.depends_on`, {
        pattern: STEP_PATTERN,
        maximum: MAX_STEPS,
    });
    assertStringArray(value.artifact_refs, `${label}.artifact_refs`, {
        pattern: ARTIFACT_PATTERN,
        maximum: MAX_ARTIFACTS_PER_RECEIPT,
    });

    if (definition.kind === "owner_gate") {
        if (!OWNER_GATE_STATUSES.has(value.status)
            || value.task_binding !== null
            || value.lease_binding !== null
            || value.receipt_binding !== null
            || value.external_action_receipt_binding !== null
            || value.started_at !== null
            || value.completed_at !== null
            || value.artifact_refs.length !== 0) {
            fail("OWNER_GATE_RUNTIME_INVALID", `${label} owner-gate runtime is invalid.`);
        }
        return value;
    }

    if (!TASK_STATUSES.has(value.status)) {
        fail("TASK_STEP_STATUS_INVALID", `${label}.status is invalid.`);
    }
    if (value.status === "queued") {
        if (value.task_binding !== null
            || value.lease_binding !== null
            || value.receipt_binding !== null
            || value.external_action_receipt_binding !== null
            || value.started_at !== null
            || value.completed_at !== null
            || value.artifact_refs.length !== 0) {
            fail("QUEUED_STEP_AUTHORITY_INVALID", `${label} queued step must be unclaimed.`);
        }
        return value;
    }

    if (value.lease_binding === null) {
        fail("CLAIM_WITHOUT_LEASE", `${label} cannot be active without a run lease.`);
    }
    validateLeaseBinding(value.lease_binding, `${label}.lease_binding`);
    if (value.task_binding === null) {
        fail("TASK_BINDING_REQUIRED", `${label} active task is missing its task binding.`);
    }
    validateTaskBinding(value.task_binding, `${label}.task_binding`);
    parseTime(value.started_at, `${label}.started_at`);

    if (value.status === "running") {
        if (value.receipt_binding !== null
            || value.completed_at !== null
            || value.artifact_refs.length !== 0) {
            fail("RUNNING_STEP_RECEIPT_INVALID", `${label} running step is already receipted.`);
        }
        return value;
    }

    if (value.receipt_binding === null || value.completed_at === null) {
        fail("COMPLETED_STEP_RECEIPT_REQUIRED", `${label} terminal step is not receipted.`);
    }
    assertObjectShape(value.receipt_binding, [
        "receipt_id",
        "receipt_fingerprint_sha256",
    ], [], `${label}.receipt_binding`);
    assertString(
        value.receipt_binding.receipt_id,
        WORK_RECEIPT_PATTERN,
        `${label}.receipt_binding.receipt_id`,
    );
    assertString(
        value.receipt_binding.receipt_fingerprint_sha256,
        SHA256_PATTERN,
        `${label}.receipt_binding.receipt_fingerprint_sha256`,
    );
    const receipt = receiptMap.get(value.receipt_binding.receipt_id);
    if (!receipt
        || receipt.receipt_fingerprint_sha256
            !== value.receipt_binding.receipt_fingerprint_sha256
        || receipt.step_binding.step_id !== value.step_id
        || receipt.step_binding.lease.lease_id !== value.lease_binding.lease_id
        || receipt.step_binding.lease.lease_authority_fingerprint_sha256
            !== value.lease_binding.lease_authority_fingerprint_sha256
        || receipt.outcome.completed_at !== value.completed_at
        || !sameStringSet(
            receipt.artifacts.map((artifact) => artifact.artifact_id),
            value.artifact_refs,
        )) {
        fail("FLOW_RECEIPT_BINDING_MISMATCH", `${label} receipt binding has drifted.`);
    }
    if (definition.execution_class === "write") {
        if (!sameJson(
            value.external_action_receipt_binding,
            receipt.external_action_receipt_binding,
        )) {
            fail(
                "EXTERNAL_RECEIPT_BINDING_MISMATCH",
                `${label} external receipt binding has drifted.`,
            );
        }
    } else if (value.external_action_receipt_binding !== null) {
        fail("EXTERNAL_RECEIPT_UNEXPECTED", `${label} has an external write receipt.`);
    }
    return value;
}

export function taskFlowRunProjection(flow) {
    return {
        contract_version: flow.contract_version,
        fixture: flow.fixture,
        activation_state: flow.activation_state,
        live_dispatch_allowed: flow.live_dispatch_allowed,
        flow_id: flow.flow_id,
        sync_mode: flow.sync_mode,
        controller_id: flow.controller_id,
        work_item_binding: flow.work_item_binding,
        runtime_binding: flow.runtime_binding,
        status: flow.status,
        revision: flow.revision,
        current_step_id: flow.current_step_id,
        nodes: flow.nodes,
        wait: flow.wait,
        checkpoint: flow.checkpoint,
        cancellation: flow.cancellation,
        constraints: flow.constraints,
        created_at: flow.created_at,
        updated_at: flow.updated_at,
    };
}

export function taskFlowRunFingerprint(flow) {
    return sha256Fingerprint(taskFlowRunProjection(flow));
}

export function validateTaskFlowRunV1(input, options = {}) {
    const {
        flow,
        workItem,
        receipts = [],
    } = input;
    validateWorkItemV1(workItem, options);
    const allowFixture = options.allowFixture === true;
    const allowContractOnly = options.allowContractOnly === true;
    assertObjectShape(flow, [
        "contract_version",
        "fixture",
        "activation_state",
        "live_dispatch_allowed",
        "flow_id",
        "sync_mode",
        "controller_id",
        "work_item_binding",
        "runtime_binding",
        "status",
        "revision",
        "current_step_id",
        "nodes",
        "wait",
        "checkpoint",
        "cancellation",
        "constraints",
        "created_at",
        "updated_at",
        "flow_fingerprint_sha256",
    ], ["$schema", "$comment"], "task flow");
    fixtureGate(flow, allowFixture, "task flow");
    contractOnlyGate(flow, allowContractOnly, "task flow");
    if (flow.contract_version !== "noderooms-openclaw-task-flow-binding-v1") {
        fail("CONTRACT_VERSION_MISMATCH", "Task Flow binding version is unsupported.");
    }
    assertString(flow.flow_id, CONTEXT_ID_PATTERN, "flow_id");
    if (flow.sync_mode !== "managed") {
        fail("TASK_FLOW_MODE_INVALID", "NodeRooms missions require a managed Task Flow.");
    }
    assertString(flow.controller_id, CONTROLLER_PATTERN, "controller_id");
    if (flow.controller_id !== workItem.workflow.controller_id) {
        fail("CONTROLLER_MISMATCH", "Task Flow controller has drifted.");
    }
    assertObjectShape(flow.work_item_binding, [
        "work_item_id",
        "mission_id",
        "work_item_revision",
        "work_item_fingerprint_sha256",
    ], [], "work_item_binding");
    if (flow.work_item_binding.work_item_id !== workItem.work_item_id
        || flow.work_item_binding.mission_id !== workItem.mission_id
        || flow.work_item_binding.work_item_revision !== workItem.revision
        || flow.work_item_binding.work_item_fingerprint_sha256
            !== workItem.work_item_fingerprint_sha256) {
        fail("WORK_ITEM_BINDING_MISMATCH", "Task Flow work-item binding has drifted.");
    }
    validateRuntimeBinding(flow.runtime_binding);
    if (!sameJson(flow.runtime_binding, workItem.runtime_binding)) {
        fail("FLOW_RUNTIME_MISMATCH", "Task Flow runtime binding has drifted.");
    }
    if (!FLOW_STATUSES.has(flow.status)) {
        fail("TASK_FLOW_STATUS_INVALID", "Task Flow status is invalid.");
    }
    assertInteger(flow.revision, "revision", 1);
    assertString(flow.current_step_id, STEP_PATTERN, "current_step_id");
    if (flow.current_step_id !== workItem.workflow.current_step_id) {
        fail("CURRENT_STEP_MISMATCH", "Task Flow current step has drifted.");
    }
    if (!Array.isArray(receipts) || receipts.length > MAX_STEPS) {
        fail("RECEIPTS_INVALID", "Task Flow receipts are invalid.");
    }
    const receiptMap = new Map();
    for (const receipt of receipts) {
        validateWorkStepReceiptV1(receipt, workItem, options);
        if (receiptMap.has(receipt.receipt_id)) {
            fail("DUPLICATE_WORK_RECEIPT", "Task Flow receipt list contains duplicates.");
        }
        receiptMap.set(receipt.receipt_id, receipt);
    }
    if (!Array.isArray(flow.nodes) || flow.nodes.length !== workItem.steps.length) {
        fail("FLOW_NODES_INVALID", "Task Flow nodes do not match the work item.");
    }
    const nodeIds = flow.nodes.map((node) => node.step_id);
    if (!sameJson(nodeIds, workItem.workflow.ordered_step_ids)
        || new Set(nodeIds).size !== nodeIds.length) {
        fail("FLOW_NODE_ORDER_MISMATCH", "Task Flow node order has drifted.");
    }
    flow.nodes.forEach((node, index) => {
        validateFlowNode(node, index, workItem, receiptMap);
    });
    const leaseIds = flow.nodes
        .map((node) => node.lease_binding?.lease_id)
        .filter(Boolean);
    if (new Set(leaseIds).size !== leaseIds.length) {
        fail("STEP_LEASE_REUSE", "A run lease is shared across task steps.");
    }
    const boundReceiptIds = flow.nodes
        .map((node) => node.receipt_binding?.receipt_id)
        .filter(Boolean);
    if (new Set(boundReceiptIds).size !== boundReceiptIds.length
        || !sameStringSet(boundReceiptIds, [...receiptMap.keys()])) {
        fail("FLOW_RECEIPT_SET_MISMATCH", "Task Flow receipt set has drifted.");
    }

    if (flow.status === "waiting") {
        assertObjectShape(flow.wait, [
            "kind",
            "step_id",
            "owner_binding_id",
            "decision_id",
            "expires_at",
        ], [], "wait");
        if (flow.wait.kind !== "owner_review"
            || flow.wait.step_id !== workItem.owner_policy.owner_review_step_id
            || flow.wait.owner_binding_id !== workItem.agent_binding.owner_binding_id
            || flow.wait.decision_id !== null
            || flow.current_step_id !== flow.wait.step_id) {
            fail("OWNER_REVIEW_WAIT_INVALID", "Task Flow Owner-review wait has drifted.");
        }
        parseTime(flow.wait.expires_at, "wait.expires_at");
        const gate = flow.nodes.find((node) => node.step_id === flow.wait.step_id);
        if (!gate || gate.kind !== "owner_gate" || gate.status !== "waiting") {
            fail("OWNER_REVIEW_GATE_INVALID", "Task Flow Owner gate is not waiting.");
        }
        const nextWrite = flow.nodes.find(
            (node) => workItem.steps.find(
                (step) => step.step_id === node.step_id,
            )?.execution_class === "write",
        );
        if (!nextWrite || nextWrite.status !== "queued" || nextWrite.lease_binding !== null) {
            fail("WRITE_STARTED_BEFORE_OWNER_REVIEW", "Write step started before Owner review.");
        }
    } else if (flow.wait !== null) {
        fail("UNEXPECTED_WAIT_STATE", "Non-waiting Task Flow has wait metadata.");
    }

    assertObjectShape(flow.checkpoint, [
        "store",
        "last_persisted_revision",
        "restart_count",
        "recovery_state",
        "reconciliation_mode",
        "stale_write_strategy",
        "resume_without_reconcile_allowed",
        "last_reconciled_at",
    ], [], "checkpoint");
    if (flow.checkpoint.store !== "openclaw_sqlite_flow_runs"
        || flow.checkpoint.last_persisted_revision !== flow.revision
        || flow.checkpoint.recovery_state !== "reconciled"
        || flow.checkpoint.reconciliation_mode !== "read_only"
        || flow.checkpoint.stale_write_strategy
            !== "reject_revision_conflict_reread"
        || flow.checkpoint.resume_without_reconcile_allowed !== false) {
        fail("RESTART_RECOVERY_INVALID", "Task Flow restart checkpoint is not fail-closed.");
    }
    assertInteger(flow.checkpoint.restart_count, "checkpoint.restart_count", 0);
    if (flow.checkpoint.restart_count > 0) {
        parseTime(flow.checkpoint.last_reconciled_at, "checkpoint.last_reconciled_at");
    } else if (flow.checkpoint.last_reconciled_at !== null) {
        fail("RESTART_RECONCILE_TIME_INVALID", "Fresh flow has unexpected reconcile time.");
    }

    assertObjectShape(flow.cancellation, [
        "state",
        "requested",
        "requested_at",
        "no_new_tasks_when_requested",
        "cancel_is_sticky",
    ], [], "cancellation");
    if (!["not_requested", "requested", "settled"].includes(flow.cancellation.state)) {
        fail("CANCELLATION_STATE_INVALID", "Task Flow cancellation state is invalid.");
    }
    assertBoolean(
        flow.cancellation.no_new_tasks_when_requested,
        true,
        "cancellation.no_new_tasks_when_requested",
    );
    assertBoolean(
        flow.cancellation.cancel_is_sticky,
        true,
        "cancellation.cancel_is_sticky",
    );
    if (flow.cancellation.state === "not_requested") {
        assertBoolean(flow.cancellation.requested, false, "cancellation.requested");
        if (flow.cancellation.requested_at !== null) {
            fail("CANCELLATION_TIME_INVALID", "Unrequested cancellation has a timestamp.");
        }
    } else {
        assertBoolean(flow.cancellation.requested, true, "cancellation.requested");
        parseTime(flow.cancellation.requested_at, "cancellation.requested_at");
        if (flow.nodes.some((node) => node.status === "running")) {
            fail("TASK_STARTED_AFTER_CANCEL", "Cancelled Task Flow still has active work.");
        }
    }

    assertObjectShape(flow.constraints, [
        "expected_revision_required",
        "per_task_step_lease_required",
        "per_task_step_receipt_required",
        "subagent_privilege_inheritance_allowed",
        "one_active_task_max",
        "automatic_write_retry_allowed",
        "pause_cancel_revoke_stop_before_next_step",
        "claim_token_persisted",
    ], [], "constraints");
    for (const field of [
        "expected_revision_required",
        "per_task_step_lease_required",
        "per_task_step_receipt_required",
        "pause_cancel_revoke_stop_before_next_step",
    ]) {
        assertBoolean(flow.constraints[field], true, `constraints.${field}`);
    }
    for (const field of [
        "subagent_privilege_inheritance_allowed",
        "automatic_write_retry_allowed",
        "claim_token_persisted",
    ]) {
        assertBoolean(flow.constraints[field], false, `constraints.${field}`);
    }
    assertInteger(flow.constraints.one_active_task_max, "constraints.one_active_task_max", 1, 1);
    if (flow.nodes.filter((node) => node.status === "running").length > 1) {
        fail("TOO_MANY_ACTIVE_TASKS", "Task Flow has more than one active task.");
    }

    const createdAt = parseTime(flow.created_at, "created_at");
    const updatedAt = parseTime(flow.updated_at, "updated_at");
    if (updatedAt < createdAt) {
        fail("FLOW_TIME_ORDER_INVALID", "Task Flow update precedes creation.");
    }
    assertString(
        flow.flow_fingerprint_sha256,
        SHA256_PATTERN,
        "flow_fingerprint_sha256",
    );
    if (flow.flow_fingerprint_sha256 !== taskFlowRunFingerprint(flow)) {
        fail("TASK_FLOW_FINGERPRINT_MISMATCH", "Task Flow fingerprint has drifted.");
    }
    assertNoWildcard(flow, "task flow");
    assertNoSensitiveFields(flow, "task flow");
    return flow;
}

export function workboardCardProjection(card) {
    return {
        contract_version: card.contract_version,
        fixture: card.fixture,
        activation_state: card.activation_state,
        live_dispatch_allowed: card.live_dispatch_allowed,
        mapping_revision: card.mapping_revision,
        work_item_binding: card.work_item_binding,
        openclaw_card: card.openclaw_card,
        task_flow_binding: card.task_flow_binding,
        claim: card.claim,
        proof_refs: card.proof_refs,
        handoff: card.handoff,
        constraints: card.constraints,
        created_at: card.created_at,
        updated_at: card.updated_at,
    };
}

export function workboardCardFingerprint(card) {
    return sha256Fingerprint(workboardCardProjection(card));
}

export function validateWorkboardCardV1(input, options = {}) {
    const {
        card,
        workItem,
        flow,
        receipts = [],
    } = input;
    validateTaskFlowRunV1({ flow, workItem, receipts }, options);
    const allowFixture = options.allowFixture === true;
    const allowContractOnly = options.allowContractOnly === true;
    assertObjectShape(card, [
        "contract_version",
        "fixture",
        "activation_state",
        "live_dispatch_allowed",
        "mapping_revision",
        "work_item_binding",
        "openclaw_card",
        "task_flow_binding",
        "claim",
        "proof_refs",
        "handoff",
        "constraints",
        "created_at",
        "updated_at",
        "card_fingerprint_sha256",
    ], ["$schema", "$comment"], "Workboard card binding");
    fixtureGate(card, allowFixture, "Workboard card binding");
    contractOnlyGate(card, allowContractOnly, "Workboard card binding");
    if (card.contract_version !== "noderooms-openclaw-workboard-binding-v1") {
        fail("CONTRACT_VERSION_MISMATCH", "Workboard binding version is unsupported.");
    }
    assertInteger(card.mapping_revision, "mapping_revision", 1);
    assertObjectShape(card.work_item_binding, [
        "work_item_id",
        "mission_id",
        "work_item_revision",
        "work_item_fingerprint_sha256",
        "create_idempotency_key_sha256",
    ], [], "work_item_binding");
    if (card.work_item_binding.work_item_id !== workItem.work_item_id
        || card.work_item_binding.mission_id !== workItem.mission_id
        || card.work_item_binding.work_item_revision !== workItem.revision
        || card.work_item_binding.work_item_fingerprint_sha256
            !== workItem.work_item_fingerprint_sha256
        || card.work_item_binding.create_idempotency_key_sha256 !== sha256Fingerprint({
            mission_id: workItem.mission_id,
            work_item_id: workItem.work_item_id,
            mapping_revision: card.mapping_revision,
        })) {
        fail("WORK_ITEM_BINDING_MISMATCH", "Workboard work-item binding has drifted.");
    }

    assertObjectShape(card.openclaw_card, [
        "board_id",
        "card_id",
        "status",
        "priority",
        "agent_id",
        "linked_task_flow_id",
        "linked_session_key_fingerprint_sha256",
    ], [], "openclaw_card");
    assertString(card.openclaw_card.board_id, CONTEXT_ID_PATTERN, "openclaw_card.board_id");
    assertString(card.openclaw_card.card_id, CONTEXT_ID_PATTERN, "openclaw_card.card_id");
    if (!WORKBOARD_STATUSES.has(card.openclaw_card.status)) {
        fail("WORKBOARD_STATUS_INVALID", "Workboard card status is invalid.");
    }
    if (!["low", "normal", "high", "urgent"].includes(card.openclaw_card.priority)) {
        fail("WORKBOARD_PRIORITY_INVALID", "Workboard card priority is invalid.");
    }
    if (card.openclaw_card.agent_id !== workItem.runtime_binding.openclaw_agent_id
        || card.openclaw_card.linked_task_flow_id !== flow.flow_id
        || card.openclaw_card.linked_session_key_fingerprint_sha256
            !== workItem.runtime_binding.session_key_fingerprint_sha256) {
        fail("WORKBOARD_RUNTIME_MISMATCH", "Workboard runtime mapping has drifted.");
    }

    assertObjectShape(card.task_flow_binding, [
        "flow_id",
        "flow_revision",
        "flow_fingerprint_sha256",
        "current_step_id",
    ], [], "task_flow_binding");
    if (card.task_flow_binding.flow_id !== flow.flow_id
        || card.task_flow_binding.flow_revision !== flow.revision
        || card.task_flow_binding.flow_fingerprint_sha256
            !== flow.flow_fingerprint_sha256
        || card.task_flow_binding.current_step_id !== flow.current_step_id) {
        fail("TASK_FLOW_BINDING_MISMATCH", "Workboard Task Flow binding has drifted.");
    }

    assertObjectShape(card.claim, [
        "state",
        "lease_id",
        "claimed_by_runtime_binding_id",
        "heartbeat_at",
        "expires_at",
        "token_redacted",
        "token_persisted",
    ], [], "claim");
    if (!["unclaimed", "active", "released"].includes(card.claim.state)) {
        fail("CLAIM_STATE_INVALID", "Workboard claim state is invalid.");
    }
    assertBoolean(card.claim.token_redacted, true, "claim.token_redacted");
    assertBoolean(
        card.claim.token_persisted,
        false,
        "claim.token_persisted",
    );
    if (card.claim.state === "active") {
        if (card.claim.lease_id === null) {
            fail("CLAIM_WITHOUT_LEASE", "Workboard card cannot be claimed without a run lease.");
        }
        assertString(card.claim.lease_id, LEASE_PATTERN, "claim.lease_id");
        if (card.claim.claimed_by_runtime_binding_id
                !== workItem.runtime_binding.binding_id) {
            fail("CLAIM_RUNTIME_MISMATCH", "Workboard claim runtime has drifted.");
        }
        parseTime(card.claim.heartbeat_at, "claim.heartbeat_at");
        parseTime(card.claim.expires_at, "claim.expires_at");
    } else if (card.claim.lease_id !== null
        || card.claim.claimed_by_runtime_binding_id !== null
        || card.claim.heartbeat_at !== null
        || card.claim.expires_at !== null) {
        fail("INACTIVE_CLAIM_AUTHORITY_PRESENT", "Inactive Workboard claim retains authority.");
    }

    assertObjectShape(card.proof_refs, [
        "work_receipt_ids",
        "artifact_ids",
        "external_action_receipt_ids",
    ], [], "proof_refs");
    assertStringArray(card.proof_refs.work_receipt_ids, "proof_refs.work_receipt_ids", {
        pattern: WORK_RECEIPT_PATTERN,
        maximum: MAX_STEPS,
    });
    assertStringArray(card.proof_refs.artifact_ids, "proof_refs.artifact_ids", {
        pattern: ARTIFACT_PATTERN,
        maximum: MAX_STEPS * MAX_ARTIFACTS_PER_RECEIPT,
    });
    assertStringArray(
        card.proof_refs.external_action_receipt_ids,
        "proof_refs.external_action_receipt_ids",
        {
            pattern: EXTERNAL_RECEIPT_PATTERN,
            maximum: MAX_STEPS,
        },
    );
    const expectedReceiptIds = receipts.map((receipt) => receipt.receipt_id);
    const expectedArtifactIds = receipts.flatMap(
        (receipt) => receipt.artifacts.map((artifact) => artifact.artifact_id),
    );
    const expectedExternalReceiptIds = receipts
        .map((receipt) => receipt.external_action_receipt_binding?.receipt_id)
        .filter(Boolean);
    if (!sameStringSet(card.proof_refs.work_receipt_ids, expectedReceiptIds)
        || !sameStringSet(card.proof_refs.artifact_ids, expectedArtifactIds)
        || !sameStringSet(
            card.proof_refs.external_action_receipt_ids,
            expectedExternalReceiptIds,
        )) {
        fail("WORKBOARD_PROOF_MISMATCH", "Workboard proof references have drifted.");
    }

    assertObjectShape(card.handoff, [
        "state",
        "from_step_id",
        "to_step_id",
        "claim_released",
        "owner_review_required",
    ], [], "handoff");
    if (!["none", "waiting_owner", "released", "completed"].includes(card.handoff.state)) {
        fail("HANDOFF_STATE_INVALID", "Workboard handoff state is invalid.");
    }
    assertNullableString(card.handoff.from_step_id, STEP_PATTERN, "handoff.from_step_id");
    assertNullableString(card.handoff.to_step_id, STEP_PATTERN, "handoff.to_step_id");
    assertBoolean(card.handoff.claim_released, undefined, "handoff.claim_released");
    assertBoolean(
        card.handoff.owner_review_required,
        undefined,
        "handoff.owner_review_required",
    );
    if (flow.status === "waiting") {
        if (card.openclaw_card.status !== "review"
            || card.claim.state !== "released"
            || card.handoff.state !== "waiting_owner"
            || card.handoff.to_step_id !== workItem.owner_policy.owner_review_step_id
            || card.handoff.claim_released !== true
            || card.handoff.owner_review_required !== true) {
            fail("OWNER_REVIEW_CARD_STATE_INVALID", "Workboard Owner-review state is invalid.");
        }
    }

    assertObjectShape(card.constraints, [
        "canonical_source",
        "card_can_grant_authority",
        "local_edits_are_proposals",
        "unknown_state_rewritten",
        "public_projection_safe",
    ], [], "constraints");
    if (card.constraints.canonical_source !== "noderooms_workdesk") {
        fail("CANONICAL_SOURCE_INVALID", "Workboard card is not bound to NodeRooms Workdesk.");
    }
    assertBoolean(
        card.constraints.card_can_grant_authority,
        false,
        "constraints.card_can_grant_authority",
    );
    assertBoolean(
        card.constraints.local_edits_are_proposals,
        true,
        "constraints.local_edits_are_proposals",
    );
    assertBoolean(
        card.constraints.unknown_state_rewritten,
        false,
        "constraints.unknown_state_rewritten",
    );
    assertBoolean(
        card.constraints.public_projection_safe,
        true,
        "constraints.public_projection_safe",
    );
    const createdAt = parseTime(card.created_at, "created_at");
    const updatedAt = parseTime(card.updated_at, "updated_at");
    if (updatedAt < createdAt) {
        fail("CARD_TIME_ORDER_INVALID", "Workboard card update precedes creation.");
    }
    assertString(
        card.card_fingerprint_sha256,
        SHA256_PATTERN,
        "card_fingerprint_sha256",
    );
    if (card.card_fingerprint_sha256 !== workboardCardFingerprint(card)) {
        fail("WORKBOARD_CARD_FINGERPRINT_MISMATCH", "Workboard card fingerprint has drifted.");
    }
    assertNoWildcard(card, "Workboard card binding");
    assertNoSensitiveFields(card, "Workboard card binding");
    return card;
}

export function validateMissionSet(records, options = {}) {
    if (!Array.isArray(records) || records.length === 0 || records.length > 1000) {
        fail("MISSION_SET_INVALID", "Mission set is invalid.");
    }
    const missionIds = new Set();
    const workItemIds = new Set();
    const cardIds = new Set();
    const flowIds = new Set();
    const idempotencyKeys = new Set();
    for (const record of records) {
        assertObjectShape(record, [
            "workItem",
            "card",
            "flow",
            "receipts",
        ], [], "mission record");
        validateWorkboardCardV1(record, options);
        const {
            workItem,
            card,
            flow,
        } = record;
        for (const [set, value, code] of [
            [missionIds, workItem.mission_id, "DUPLICATE_MISSION_ID"],
            [workItemIds, workItem.work_item_id, "DUPLICATE_WORK_ITEM_ID"],
            [cardIds, card.openclaw_card.card_id, "DUPLICATE_WORKBOARD_CARD_ID"],
            [flowIds, flow.flow_id, "DUPLICATE_TASK_FLOW_ID"],
            [
                idempotencyKeys,
                card.work_item_binding.create_idempotency_key_sha256,
                "DUPLICATE_CARD_IDEMPOTENCY_KEY",
            ],
        ]) {
            if (set.has(value)) {
                fail(code, `${code} is forbidden.`);
            }
            set.add(value);
        }
    }
    return Object.freeze({
        mission_count: records.length,
        work_item_count: workItemIds.size,
        workboard_card_count: cardIds.size,
        task_flow_count: flowIds.size,
        one_to_one_mapping: true,
        live_dispatch_allowed: false,
    });
}

export function evaluateWorkMissionV1(input, options = {}) {
    try {
        validateWorkboardCardV1(input, options);
        return Object.freeze({
            decision: "contract_match_not_dispatched",
            reason_code: "LIVE_DISPATCH_PROHIBITED",
            work_item_id: input.workItem.work_item_id,
            mission_id: input.workItem.mission_id,
            card_id: input.card.openclaw_card.card_id,
            flow_id: input.flow.flow_id,
            current_step_id: input.flow.current_step_id,
            work_receipt_count: input.receipts.length,
            mission_card_idempotent: true,
            owner_review_waiting: input.flow.status === "waiting",
            restart_reconciled:
                input.flow.checkpoint.recovery_state === "reconciled",
            live_dispatch_allowed: false,
        });
    } catch (error) {
        if (error instanceof WorkdeskTaskFlowContractError) {
            return Object.freeze({
                decision: "block_invalid_work_mission",
                reason_code: error.code,
                live_dispatch_allowed: false,
            });
        }
        throw error;
    }
}
