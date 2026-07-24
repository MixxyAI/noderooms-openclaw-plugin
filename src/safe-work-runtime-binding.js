import { createHash, randomUUID } from "node:crypto";
import {
    chmod,
    lstat,
    mkdir,
    open,
    readFile,
    rename,
    rm,
    stat,
    writeFile,
} from "node:fs/promises";
import path from "node:path";

import { NodeRoomsError } from "./contracts.js";
import {
    canonicalJson,
    sha256Fingerprint,
} from "./passport-runtime-binding.js";
import {
    validateWorkItemV1,
} from "./workdesk-workboard-task-flow.js";

export const LIVE_WORK_RUNTIME_ARMED_ALLOWED = false;
export const SAFE_WORK_RUNTIME_CONTRACT_VERSION =
    "noderooms-safe-work-runtime-binding-v1";

const STORE_VERSION = 1;
const STORE_MAX_FILE_BYTES = 1_048_576;
const DEFAULT_MAX_ENTRIES = 128;
const MAX_WORK_ITEM_BYTES = 65_536;
const LOCK_STALE_MS = 30_000;
const LOCK_RETRY_COUNT = 100;
const LOCK_RETRY_DELAY_MS = 10;
const CONTROLLER_ID = "noderooms/workdesk-shadow-v1";
const WORKBOARD_TOOL_NAME = "workboard_create";
const NODEROOMS_TENANT = "noderooms";
const IDEMPOTENCY_PREFIX = "noderooms-work:";
const BINDING_ID_PATTERN = /^nrrtb_[a-f0-9]{32}$/;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const WORK_ITEM_ID_PATTERN = /^nrwork_[a-f0-9]{32}$/;
const MISSION_ID_PATTERN = /^nrmission_[a-f0-9]{32}$/;
const OWNER_BINDING_PATTERN = /^NRPB-[A-F0-9]{24}$/;
const CONTEXT_ID_PATTERN = /^[A-Za-z0-9._:-]{1,160}$/;
const BOARD_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,79}$/;
const CARD_ID_PATTERN = /^[A-Za-z0-9._:-]{1,160}$/;
const FLOW_ID_PATTERN = /^[A-Za-z0-9._:-]{1,200}$/;
const TOOL_CALL_ID_PATTERN = /^[A-Za-z0-9._:-]{1,200}$/;
const RUNTIME_STATES = new Set([
    "creating_flow",
    "prepared",
    "creating_card",
    "bound",
    "reconcile_required",
    "cancelled",
]);

function fail(code, message) {
    throw new NodeRoomsError(code, message);
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function boundedString(value, pattern, label, maxLength = 512) {
    if (typeof value !== "string"
        || value.length < 1
        || value.length > maxLength
        || (pattern && !pattern.test(value))) {
        fail("WORK_RUNTIME_STATE_INVALID", `${label} is invalid.`);
    }
    return value;
}

function requiredInteger(value, label, minimum = 0) {
    if (!Number.isSafeInteger(value) || value < minimum) {
        fail("WORK_RUNTIME_STATE_INVALID", `${label} is invalid.`);
    }
    return value;
}

function assertExactKeys(value, required, optional, label) {
    if (!isRecord(value)) {
        fail("WORK_RUNTIME_STATE_INVALID", `${label} must be an object.`);
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail("WORK_RUNTIME_STATE_INVALID", `${label} contains unsupported field ${key}.`);
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail("WORK_RUNTIME_STATE_INVALID", `${label} is missing ${key}.`);
        }
    }
}

function sameJson(left, right) {
    return canonicalJson(left) === canonicalJson(right);
}

function digest32(value) {
    return createHash("sha256")
        .update(canonicalJson(value), "utf8")
        .digest("hex")
        .slice(0, 32);
}

function publicState(record, activeFlowBindings, activeCardCalls) {
    if (record.state === "creating_flow"
        && !activeFlowBindings.has(record.bindingId)) {
        return "reconcile_required";
    }
    if (record.state === "creating_card"
        && !activeCardCalls.has(record.activeToolCallId ?? "")) {
        return "reconcile_required";
    }
    return record.state;
}

function requesterChannel(ctx) {
    const direct = typeof ctx?.messageChannel === "string"
        ? ctx.messageChannel.trim()
        : "";
    if (direct) {
        return direct;
    }
    const delivery = isRecord(ctx?.deliveryContext)
        && typeof ctx.deliveryContext.channel === "string"
        ? ctx.deliveryContext.channel.trim()
        : "";
    if (delivery) {
        return delivery;
    }
    return typeof ctx?.channel === "string" ? ctx.channel.trim() : "";
}

function requesterSenderId(ctx) {
    const toolSender = typeof ctx?.requesterSenderId === "string"
        ? ctx.requesterSenderId.trim()
        : "";
    if (toolSender) {
        return toolSender;
    }
    return typeof ctx?.senderId === "string" ? ctx.senderId.trim() : "";
}

function requireOwnerContext(ctx, command = false) {
    if (ctx?.senderIsOwner !== true
        || (command && ctx?.isAuthorizedSender !== true)) {
        fail(
            "WORK_RUNTIME_OWNER_REQUIRED",
            "Only the authenticated human OpenClaw Owner may bind or cancel a NodeRooms work runtime.",
        );
    }
    const agentId = typeof ctx.agentId === "string" ? ctx.agentId.trim() : "";
    const sessionKey = typeof ctx.sessionKey === "string" ? ctx.sessionKey.trim() : "";
    const channel = requesterChannel(ctx);
    const senderId = requesterSenderId(ctx);
    if (!CONTEXT_ID_PATTERN.test(agentId)
        || sessionKey.length < 1
        || sessionKey.length > 512
        || channel.length < 1
        || channel.length > 160
        || senderId.length < 1
        || senderId.length > 256) {
        fail(
            "WORK_RUNTIME_CONTEXT_REQUIRED",
            "The trusted OpenClaw Agent, session, channel, and Owner sender context are required.",
        );
    }
    const fingerprints = runtimeContextFingerprints({
        agentId,
        sessionKey,
        channel,
        requesterSenderId: senderId,
    });
    return {
        agentId,
        sessionKey,
        channel,
        requesterSenderId: senderId,
        ...fingerprints,
    };
}

function parseWorkItemJson(value) {
    if (typeof value !== "string"
        || value.length < 2
        || Buffer.byteLength(value, "utf8") > MAX_WORK_ITEM_BYTES) {
        fail(
            "WORK_RUNTIME_WORK_ITEM_INVALID",
            "The canonical work item JSON is missing or exceeds the safe size limit.",
        );
    }
    try {
        const parsed = JSON.parse(value);
        if (!isRecord(parsed)) {
            throw new Error("not an object");
        }
        return parsed;
    }
    catch {
        fail(
            "WORK_RUNTIME_WORK_ITEM_INVALID",
            "The canonical work item JSON could not be parsed safely.",
        );
    }
}

function validateShadowWorkItem(workItem, ownerContext, now) {
    let validated;
    try {
        validated = validateWorkItemV1(workItem, {
            allowFixture: false,
            allowContractOnly: true,
            requireUnexpired: true,
            now,
        });
    }
    catch {
        fail(
            "WORK_RUNTIME_WORK_ITEM_REJECTED",
            "The NodeRooms work item failed the strict 003A contract gate.",
        );
    }
    if (validated.workflow.status !== "waiting_owner_review"
        || validated.workflow.current_step_id
            !== validated.owner_policy.owner_review_step_id) {
        fail(
            "WORK_RUNTIME_OWNER_WAIT_REQUIRED",
            "Only a canonical work item already waiting at its exact Owner-review step may enter shadow runtime binding.",
        );
    }
    if (validated.runtime_binding.openclaw_agent_id
            !== ownerContext.agentId
        || validated.runtime_binding.session_key_fingerprint_sha256
            !== ownerContext.sessionFingerprintSha256
        || validated.runtime_binding.requester_origin_fingerprint_sha256
            !== ownerContext.requesterOriginFingerprintSha256) {
        fail(
            "WORK_RUNTIME_CONTEXT_MISMATCH",
            "The canonical work item is bound to a different OpenClaw Agent, session, or Owner origin.",
        );
    }
    return validated;
}

function workboardIdempotencyKey(workItem) {
    return [
        IDEMPOTENCY_PREFIX,
        workItem.work_item_id,
        `:r${workItem.revision}:`,
        workItem.work_item_fingerprint_sha256.slice("sha256:".length, 31),
    ].join("");
}

function buildWorkboardParams(workItem, config) {
    return {
        title: workItem.objective.title,
        notes: [
            `Canonical NodeRooms mission: ${workItem.mission_id}`,
            `Work item: ${workItem.work_item_id} revision ${workItem.revision}`,
            `Fingerprint: ${workItem.work_item_fingerprint_sha256}`,
            "Shadow binding only. This review card grants no authority and must not be claimed or dispatched.",
        ].join("\n"),
        status: "review",
        priority: "high",
        labels: ["noderooms", "owner-review", "shadow-runtime"],
        agentId: workItem.runtime_binding.openclaw_agent_id,
        tenant: NODEROOMS_TENANT,
        boardId: config.boardId,
        idempotencyKey: workboardIdempotencyKey(workItem),
    };
}

function validateExpectedParams(value) {
    assertExactKeys(value, [
        "title",
        "notes",
        "status",
        "priority",
        "labels",
        "agentId",
        "tenant",
        "boardId",
        "idempotencyKey",
    ], [], "expected Workboard parameters");
    boundedString(value.title, undefined, "expected Workboard title", 180);
    boundedString(value.notes, undefined, "expected Workboard notes", 4_000);
    if (value.status !== "review"
        || value.priority !== "high"
        || value.tenant !== NODEROOMS_TENANT
        || !BOARD_ID_PATTERN.test(value.boardId)
        || !value.idempotencyKey.startsWith(IDEMPOTENCY_PREFIX)
        || value.idempotencyKey.length > 160
        || !CONTEXT_ID_PATTERN.test(value.agentId)
        || !Array.isArray(value.labels)
        || !sameJson(value.labels, [
            "noderooms",
            "owner-review",
            "shadow-runtime",
        ])) {
        fail(
            "WORK_RUNTIME_STATE_INVALID",
            "The expected Workboard parameters are unsafe or inconsistent.",
        );
    }
    return value;
}

function validateStoredRecord(value) {
    assertExactKeys(value, [
        "bindingId",
        "state",
        "workItemId",
        "missionId",
        "workItemRevision",
        "workItemFingerprintSha256",
        "ownerBindingId",
        "ownerReviewStepId",
        "agentId",
        "sessionFingerprintSha256",
        "requesterOriginFingerprintSha256",
        "boardId",
        "expectedWorkboardParams",
        "expectedWorkboardParamsFingerprintSha256",
        "taskFlowId",
        "taskFlowRevision",
        "workboardCardId",
        "workboardCardStatus",
        "activeToolCallId",
        "createdAtMs",
        "updatedAtMs",
        "uncertainReason",
    ], [], "runtime binding record");
    boundedString(value.bindingId, BINDING_ID_PATTERN, "bindingId", 64);
    if (!RUNTIME_STATES.has(value.state)) {
        fail("WORK_RUNTIME_STATE_INVALID", "runtime binding state is invalid.");
    }
    boundedString(value.workItemId, WORK_ITEM_ID_PATTERN, "workItemId", 64);
    boundedString(value.missionId, MISSION_ID_PATTERN, "missionId", 64);
    requiredInteger(value.workItemRevision, "workItemRevision", 1);
    boundedString(
        value.workItemFingerprintSha256,
        SHA256_PATTERN,
        "workItemFingerprintSha256",
        71,
    );
    boundedString(value.ownerBindingId, OWNER_BINDING_PATTERN, "ownerBindingId", 64);
    boundedString(value.ownerReviewStepId, CONTEXT_ID_PATTERN, "ownerReviewStepId", 128);
    boundedString(value.agentId, CONTEXT_ID_PATTERN, "agentId", 160);
    boundedString(
        value.sessionFingerprintSha256,
        SHA256_PATTERN,
        "sessionFingerprintSha256",
        71,
    );
    boundedString(
        value.requesterOriginFingerprintSha256,
        SHA256_PATTERN,
        "requesterOriginFingerprintSha256",
        71,
    );
    boundedString(value.boardId, BOARD_ID_PATTERN, "boardId", 80);
    validateExpectedParams(value.expectedWorkboardParams);
    boundedString(
        value.expectedWorkboardParamsFingerprintSha256,
        SHA256_PATTERN,
        "expectedWorkboardParamsFingerprintSha256",
        71,
    );
    if (value.expectedWorkboardParamsFingerprintSha256
        !== workboardCreateParamsFingerprint(value.expectedWorkboardParams)) {
        fail(
            "WORK_RUNTIME_STATE_INVALID",
            "The expected Workboard parameter fingerprint has drifted.",
        );
    }
    if (value.taskFlowId !== null) {
        boundedString(value.taskFlowId, FLOW_ID_PATTERN, "taskFlowId", 200);
    }
    if (value.taskFlowRevision !== null) {
        requiredInteger(value.taskFlowRevision, "taskFlowRevision", 0);
    }
    if (value.workboardCardId !== null) {
        boundedString(value.workboardCardId, CARD_ID_PATTERN, "workboardCardId", 160);
    }
    if (value.workboardCardStatus !== null
        && value.workboardCardStatus !== "review") {
        fail("WORK_RUNTIME_STATE_INVALID", "workboardCardStatus is invalid.");
    }
    if (value.activeToolCallId !== null) {
        boundedString(
            value.activeToolCallId,
            TOOL_CALL_ID_PATTERN,
            "activeToolCallId",
            200,
        );
    }
    requiredInteger(value.createdAtMs, "createdAtMs");
    requiredInteger(value.updatedAtMs, "updatedAtMs");
    if (value.updatedAtMs < value.createdAtMs) {
        fail("WORK_RUNTIME_STATE_INVALID", "runtime binding timestamps are inconsistent.");
    }
    if (value.uncertainReason !== null) {
        boundedString(value.uncertainReason, undefined, "uncertainReason", 240);
    }
    if (value.state !== "creating_flow"
        && value.state !== "reconcile_required"
        && (value.taskFlowId === null || value.taskFlowRevision === null)) {
        fail(
            "WORK_RUNTIME_STATE_INVALID",
            "A prepared runtime binding must retain its managed Task Flow reference.",
        );
    }
    if (value.state === "bound"
        && (value.workboardCardId === null
            || value.workboardCardStatus !== "review")) {
        fail(
            "WORK_RUNTIME_STATE_INVALID",
            "A bound runtime record must retain its exact review card reference.",
        );
    }
    return value;
}

function cloneRecord(record) {
    return structuredClone(record);
}

function safeReason(value, fallback) {
    if (typeof value !== "string" || value.trim().length === 0) {
        return fallback;
    }
    return value.trim().slice(0, 240);
}

function bindingMatchesRuntime(record, context) {
    return record.agentId === context.agentId
        && record.sessionFingerprintSha256 === context.sessionFingerprintSha256;
}

function bindingMatchesContext(record, context) {
    return bindingMatchesRuntime(record, context)
        && record.requesterOriginFingerprintSha256
            === context.requesterOriginFingerprintSha256;
}

function cardFromToolResult(result) {
    if (!isRecord(result)) {
        return undefined;
    }
    if (isRecord(result.card)) {
        return result.card;
    }
    if (isRecord(result.details) && isRecord(result.details.card)) {
        return result.details.card;
    }
    if (Array.isArray(result.content)) {
        for (const item of result.content) {
            if (!isRecord(item)
                || item.type !== "text"
                || typeof item.text !== "string"
                || item.text.length > 65_536) {
                continue;
            }
            try {
                const parsed = JSON.parse(item.text);
                if (isRecord(parsed) && isRecord(parsed.card)) {
                    return parsed.card;
                }
            }
            catch {
                // An opaque or non-JSON tool result is reconciled as uncertain.
            }
        }
    }
    return undefined;
}

function validateReturnedCard(card, expected) {
    const automation = isRecord(card.metadata)
        && isRecord(card.metadata.automation)
        ? card.metadata.automation
        : undefined;
    if (!CARD_ID_PATTERN.test(card.id ?? "")
        || card.title !== expected.title
        || card.status !== "review"
        || card.priority !== expected.priority
        || card.agentId !== expected.agentId
        || !automation
        || automation.tenant !== expected.tenant
        || automation.boardId !== expected.boardId
        || automation.idempotencyKey !== expected.idempotencyKey
        || isRecord(card.metadata?.claim)) {
        fail(
            "WORK_RUNTIME_WORKBOARD_RESULT_INVALID",
            "The Workboard result did not match the exact unclaimed review-card reservation.",
        );
    }
    return {
        cardId: card.id,
        status: card.status,
    };
}

export function normalizeSafeWorkRuntimeConfig(pluginConfig) {
    const raw = isRecord(pluginConfig?.workRuntime)
        ? pluginConfig.workRuntime
        : {};
    const armedActivationBlocked = raw.mode === "armed";
    const mode = raw.mode === "shadow" ? "shadow" : "off";
    const boardId = typeof raw.boardId === "string"
        && BOARD_ID_PATTERN.test(raw.boardId.trim().toLowerCase())
        ? raw.boardId.trim().toLowerCase()
        : "noderooms-workdesk";
    const maxEntries = Number.isSafeInteger(raw.maxEntries)
        ? Math.max(1, Math.min(512, raw.maxEntries))
        : DEFAULT_MAX_ENTRIES;
    return Object.freeze({
        mode,
        boardId,
        maxEntries,
        armedActivationAllowed: LIVE_WORK_RUNTIME_ARMED_ALLOWED,
        armedActivationBlocked,
        automaticDispatchAllowed: false,
        automaticExternalWriteAllowed: false,
        automaticRetryAllowed: false,
    });
}

export function runtimeContextFingerprints({
    agentId,
    sessionKey,
    channel,
    requesterSenderId: senderId,
}) {
    if (!CONTEXT_ID_PATTERN.test(agentId)
        || typeof sessionKey !== "string"
        || sessionKey.length < 1
        || typeof channel !== "string"
        || channel.length < 1
        || typeof senderId !== "string"
        || senderId.length < 1) {
        fail(
            "WORK_RUNTIME_CONTEXT_REQUIRED",
            "The runtime context is incomplete.",
        );
    }
    return Object.freeze({
        sessionFingerprintSha256: sha256Fingerprint({
            contract_version: "noderooms-openclaw-session-context-v1",
            agent_id: agentId,
            session_key: sessionKey,
        }),
        requesterOriginFingerprintSha256: sha256Fingerprint({
            contract_version: "noderooms-openclaw-requester-origin-v1",
            channel,
            requester_sender_id: senderId,
        }),
    });
}

export function workboardCreateParamsFingerprint(params) {
    return sha256Fingerprint(params);
}

class SafeWorkRuntimeBindingStore {
    constructor({ stateFilePath, maxEntries, now }) {
        if (!path.isAbsolute(stateFilePath)) {
            fail(
                "WORK_RUNTIME_STATE_PATH_INVALID",
                "The safe work runtime state path must be absolute.",
            );
        }
        this.stateFilePath = stateFilePath;
        this.lockFilePath = `${stateFilePath}.lock`;
        this.maxEntries = maxEntries;
        this.now = now;
    }

    async reserve(input) {
        return this.withLock(async () => {
            const store = await this.loadStore();
            const existing = store.bindings.find(
                (candidate) => candidate.bindingId === input.bindingId,
            );
            if (existing) {
                if (existing.workItemFingerprintSha256
                        !== input.workItemFingerprintSha256
                    || existing.expectedWorkboardParamsFingerprintSha256
                        !== input.expectedWorkboardParamsFingerprintSha256
                    || !bindingMatchesContext(existing, input)) {
                    fail(
                        "WORK_RUNTIME_BINDING_CONFLICT",
                        "The deterministic runtime binding id already exists with different authority or parameters.",
                    );
                }
                return { created: false, record: cloneRecord(existing) };
            }
            this.enforceCapacity(store);
            const now = this.now();
            const record = validateStoredRecord({
                ...input,
                state: "creating_flow",
                taskFlowId: null,
                taskFlowRevision: null,
                workboardCardId: null,
                workboardCardStatus: null,
                activeToolCallId: null,
                createdAtMs: now,
                updatedAtMs: now,
                uncertainReason: null,
            });
            store.bindings.push(record);
            await this.saveStore(store);
            return { created: true, record: cloneRecord(record) };
        });
    }

    async completeFlow(bindingId, flow) {
        return this.mutate(bindingId, (record) => {
            if (record.state !== "creating_flow") {
                fail(
                    "WORK_RUNTIME_STATE_CONFLICT",
                    "The runtime binding flow reservation is no longer active.",
                );
            }
            if (!isRecord(flow)
                || !FLOW_ID_PATTERN.test(flow.flowId ?? "")
                || !Number.isSafeInteger(flow.revision)
                || flow.revision < 0
                || flow.status !== "waiting"
                || flow.controllerId !== CONTROLLER_ID
                || flow.currentStep !== record.ownerReviewStepId) {
                fail(
                    "WORK_RUNTIME_TASK_FLOW_INVALID",
                    "OpenClaw returned an unexpected managed Task Flow record.",
                );
            }
            record.taskFlowId = flow.flowId;
            record.taskFlowRevision = flow.revision;
            record.state = "prepared";
            record.updatedAtMs = this.now();
            return record;
        });
    }

    async markUncertain(bindingId, reason) {
        return this.mutate(bindingId, (record) => {
            if (record.state === "bound" || record.state === "cancelled") {
                return record;
            }
            record.state = "reconcile_required";
            record.activeToolCallId = null;
            record.uncertainReason = safeReason(
                reason,
                "The local runtime outcome is uncertain; automatic retry is blocked.",
            );
            record.updatedAtMs = this.now();
            return record;
        });
    }

    async claimCardCreate({
        idempotencyKey,
        params,
        paramsFingerprintSha256,
        context,
        toolCallId,
    }) {
        return this.withLock(async () => {
            const store = await this.loadStore();
            const record = store.bindings.find(
                (candidate) =>
                    candidate.expectedWorkboardParams.idempotencyKey
                        === idempotencyKey,
            );
            if (!record) {
                fail(
                    "WORK_RUNTIME_RESERVATION_NOT_FOUND",
                    "No exact NodeRooms shadow Workboard reservation exists for this call.",
                );
            }
            if (record.state !== "prepared") {
                fail(
                    "WORK_RUNTIME_REPLAY_BLOCKED",
                    `The Workboard reservation is ${record.state}; duplicate or uncertain create is blocked.`,
                );
            }
            if (!bindingMatchesRuntime(record, context)
                || paramsFingerprintSha256
                    !== record.expectedWorkboardParamsFingerprintSha256
                || !sameJson(params, record.expectedWorkboardParams)) {
                fail(
                    "WORK_RUNTIME_WORKBOARD_DRIFT",
                    "The Workboard create call drifted from the exact Owner-bound shadow reservation.",
                );
            }
            boundedString(
                toolCallId,
                TOOL_CALL_ID_PATTERN,
                "Workboard tool call id",
                200,
            );
            record.state = "creating_card";
            record.activeToolCallId = toolCallId;
            record.updatedAtMs = this.now();
            await this.saveStore(store);
            return cloneRecord(record);
        });
    }

    async completeCardCreate({
        toolCallId,
        params,
        cardId,
        cardStatus,
    }) {
        return this.withLock(async () => {
            const store = await this.loadStore();
            const record = store.bindings.find(
                (candidate) =>
                    candidate.state === "creating_card"
                    && candidate.activeToolCallId === toolCallId,
            );
            if (!record) {
                return undefined;
            }
            if (!sameJson(params, record.expectedWorkboardParams)) {
                record.state = "reconcile_required";
                record.activeToolCallId = null;
                record.uncertainReason =
                    "The completed Workboard call parameters drifted; automatic retry is blocked.";
                record.updatedAtMs = this.now();
                await this.saveStore(store);
                return cloneRecord(record);
            }
            boundedString(cardId, CARD_ID_PATTERN, "Workboard card id", 160);
            if (cardStatus !== "review") {
                fail(
                    "WORK_RUNTIME_WORKBOARD_RESULT_INVALID",
                    "The Workboard card is not waiting in review.",
                );
            }
            record.state = "bound";
            record.workboardCardId = cardId;
            record.workboardCardStatus = "review";
            record.activeToolCallId = null;
            record.uncertainReason = null;
            record.updatedAtMs = this.now();
            await this.saveStore(store);
            return cloneRecord(record);
        });
    }

    async markToolCallUncertain(toolCallId, reason) {
        return this.withLock(async () => {
            const store = await this.loadStore();
            const record = store.bindings.find(
                (candidate) =>
                    candidate.state === "creating_card"
                    && candidate.activeToolCallId === toolCallId,
            );
            if (!record) {
                return undefined;
            }
            record.state = "reconcile_required";
            record.activeToolCallId = null;
            record.uncertainReason = safeReason(
                reason,
                "The Workboard create outcome is uncertain; automatic retry is blocked.",
            );
            record.updatedAtMs = this.now();
            await this.saveStore(store);
            return cloneRecord(record);
        });
    }

    async markCancelled(bindingId, context, flowRevision) {
        return this.mutate(bindingId, (record) => {
            if (!bindingMatchesContext(record, context)) {
                fail(
                    "WORK_RUNTIME_CONTEXT_MISMATCH",
                    "The runtime binding belongs to another Owner-bound OpenClaw context.",
                );
            }
            record.state = "cancelled";
            record.taskFlowRevision = flowRevision;
            record.activeToolCallId = null;
            record.uncertainReason = null;
            record.updatedAtMs = this.now();
            return record;
        });
    }

    async get(bindingId, context) {
        const store = await this.loadStore();
        const record = store.bindings.find(
            (candidate) => candidate.bindingId === bindingId,
        );
        if (!record) {
            fail(
                "WORK_RUNTIME_BINDING_NOT_FOUND",
                "The safe work runtime binding was not found.",
            );
        }
        if (!bindingMatchesContext(record, context)) {
            fail(
                "WORK_RUNTIME_CONTEXT_MISMATCH",
                "The runtime binding belongs to another Owner-bound OpenClaw context.",
            );
        }
        return cloneRecord(record);
    }

    async list(context) {
        const store = await this.loadStore();
        return store.bindings
            .filter((record) => bindingMatchesContext(record, context))
            .map(cloneRecord);
    }

    async mutate(bindingId, update) {
        return this.withLock(async () => {
            const store = await this.loadStore();
            const record = store.bindings.find(
                (candidate) => candidate.bindingId === bindingId,
            );
            if (!record) {
                fail(
                    "WORK_RUNTIME_BINDING_NOT_FOUND",
                    "The safe work runtime binding was not found.",
                );
            }
            const updated = update(record);
            validateStoredRecord(updated);
            await this.saveStore(store);
            return cloneRecord(updated);
        });
    }

    enforceCapacity(store) {
        if (store.bindings.length < this.maxEntries) {
            return;
        }
        const removable = store.bindings
            .filter((record) =>
                record.state === "bound" || record.state === "cancelled")
            .sort((left, right) => left.updatedAtMs - right.updatedAtMs);
        for (const record of removable) {
            const index = store.bindings.findIndex(
                (candidate) => candidate.bindingId === record.bindingId,
            );
            if (index >= 0) {
                store.bindings.splice(index, 1);
            }
            if (store.bindings.length < this.maxEntries) {
                return;
            }
        }
        fail(
            "WORK_RUNTIME_CAPACITY_REACHED",
            "Too many safe runtime bindings remain unresolved.",
        );
    }

    async withLock(operation) {
        await mkdir(path.dirname(this.stateFilePath), {
            recursive: true,
            mode: 0o700,
        });
        await this.tryChmod(path.dirname(this.stateFilePath), 0o700);
        let handle;
        for (let attempt = 0; attempt < LOCK_RETRY_COUNT; attempt += 1) {
            try {
                handle = await open(this.lockFilePath, "wx", 0o600);
                break;
            }
            catch (error) {
                if (error?.code !== "EEXIST") {
                    throw error;
                }
                try {
                    const info = await stat(this.lockFilePath);
                    if (this.now() - info.mtimeMs > LOCK_STALE_MS) {
                        await rm(this.lockFilePath, { force: true });
                        continue;
                    }
                }
                catch (statError) {
                    if (statError?.code !== "ENOENT") {
                        throw statError;
                    }
                }
                await sleep(LOCK_RETRY_DELAY_MS);
            }
        }
        if (!handle) {
            fail(
                "WORK_RUNTIME_STORE_BUSY",
                "The safe work runtime store is busy; no runtime mutation was attempted.",
            );
        }
        try {
            await handle.writeFile(`${process.pid}:${this.now()}\n`, {
                encoding: "utf8",
            });
            await handle.sync();
            return await operation();
        }
        finally {
            await handle.close().catch(() => undefined);
            await rm(this.lockFilePath, { force: true }).catch(() => undefined);
        }
    }

    async loadStore() {
        try {
            const info = await lstat(this.stateFilePath);
            if (!info.isFile()
                || info.isSymbolicLink()
                || info.size > STORE_MAX_FILE_BYTES) {
                fail(
                    "WORK_RUNTIME_STATE_INVALID",
                    "The safe work runtime state file is unsafe or too large.",
                );
            }
            const parsed = JSON.parse(await readFile(this.stateFilePath, "utf8"));
            assertExactKeys(
                parsed,
                ["version", "bindings"],
                [],
                "runtime binding store",
            );
            if (parsed.version !== STORE_VERSION
                || !Array.isArray(parsed.bindings)
                || parsed.bindings.length > this.maxEntries) {
                fail(
                    "WORK_RUNTIME_STATE_INVALID",
                    "The safe work runtime state schema is invalid.",
                );
            }
            return {
                version: STORE_VERSION,
                bindings: parsed.bindings.map(validateStoredRecord),
            };
        }
        catch (error) {
            if (error?.code === "ENOENT") {
                return { version: STORE_VERSION, bindings: [] };
            }
            if (error instanceof NodeRoomsError) {
                throw error;
            }
            fail(
                "WORK_RUNTIME_STATE_INVALID",
                "The safe work runtime state could not be read safely.",
            );
        }
    }

    async saveStore(store) {
        const encoded = `${JSON.stringify(store, null, 2)}\n`;
        if (Buffer.byteLength(encoded, "utf8") > STORE_MAX_FILE_BYTES) {
            fail(
                "WORK_RUNTIME_STATE_TOO_LARGE",
                "The safe work runtime state exceeded its size limit.",
            );
        }
        const temporary =
            `${this.stateFilePath}.${process.pid}.${randomUUID()}.tmp`;
        try {
            await writeFile(temporary, encoded, {
                encoding: "utf8",
                mode: 0o600,
                flag: "wx",
            });
            const handle = await open(temporary, "r+");
            try {
                await handle.sync();
            }
            finally {
                await handle.close();
            }
            await rename(temporary, this.stateFilePath);
            await this.tryChmod(this.stateFilePath, 0o600);
        }
        finally {
            await rm(temporary, { force: true }).catch(() => undefined);
        }
    }

    async tryChmod(target, mode) {
        try {
            await chmod(target, mode);
        }
        catch (error) {
            if (process.platform !== "win32") {
                throw error;
            }
        }
    }
}

function publicSummary(record, activeFlowBindings, activeCardCalls) {
    const state = publicState(record, activeFlowBindings, activeCardCalls);
    return {
        contract_version: SAFE_WORK_RUNTIME_CONTRACT_VERSION,
        binding_id: record.bindingId,
        activation_state: "shadow",
        state,
        live_dispatch_allowed: false,
        armed_activation_allowed: false,
        work_item_binding: {
            work_item_id: record.workItemId,
            mission_id: record.missionId,
            revision: record.workItemRevision,
            fingerprint_sha256: record.workItemFingerprintSha256,
        },
        runtime_binding: {
            openclaw_agent_id: record.agentId,
            session_key_fingerprint_sha256: record.sessionFingerprintSha256,
            requester_origin_fingerprint_sha256:
                record.requesterOriginFingerprintSha256,
        },
        task_flow: {
            flow_id: record.taskFlowId,
            revision: record.taskFlowRevision,
            controller_id: CONTROLLER_ID,
            current_step_id: record.ownerReviewStepId,
            status: record.state === "cancelled" ? "cancel_requested" : "waiting",
            child_task_started: false,
            automatic_resume_allowed: false,
        },
        workboard: {
            tool_name: WORKBOARD_TOOL_NAME,
            board_id: record.boardId,
            card_id: record.workboardCardId,
            status: record.workboardCardStatus,
            create_params_fingerprint_sha256:
                record.expectedWorkboardParamsFingerprintSha256,
            create_attempted: [
                "creating_card",
                "bound",
                "reconcile_required",
                "cancelled",
            ].includes(record.state),
            claim_created: false,
            dispatch_attempted: false,
        },
        safety: {
            node_rooms_workdesk_is_canonical: true,
            workboard_card_can_grant_authority: false,
            owner_review_decision_automated: false,
            task_run_started: false,
            subagent_started: false,
            connector_called: false,
            external_write_attempted: false,
            automatic_retry_allowed: false,
            uncertain_outcome_requires_read_only_reconcile: true,
            raw_work_content_persisted: false,
            provider_credentials_persisted: false,
            claim_token_persisted: false,
        },
        uncertain_reason:
            state === "reconcile_required"
                ? record.uncertainReason
                    ?? "An interrupted local mutation requires read-only reconciliation."
                : null,
        created_at: new Date(record.createdAtMs).toISOString(),
        updated_at: new Date(record.updatedAtMs).toISOString(),
    };
}

export class SafeWorkRuntimeBindingController {
    constructor({
        config,
        stateFilePath,
        taskRuntime,
        now = Date.now,
    }) {
        this.config = config;
        this.taskRuntime = taskRuntime;
        this.now = now;
        this.activeFlowBindings = new Set();
        this.activeCardCalls = new Set();
        this.store = new SafeWorkRuntimeBindingStore({
            stateFilePath,
            maxEntries: config.maxEntries,
            now,
        });
    }

    preflight() {
        const managed = this.taskRuntime;
        const managedApiAvailable = Boolean(
            managed
            && typeof managed.fromToolContext === "function"
            && typeof managed.bindSession === "function",
        );
        return {
            ok: this.config.mode === "shadow" && managedApiAvailable,
            contract_version: SAFE_WORK_RUNTIME_CONTRACT_VERSION,
            configured_mode: this.config.mode,
            effective_mode: this.config.mode,
            shadow_binding_enabled: this.config.mode === "shadow",
            armed_activation_allowed: false,
            armed_activation_blocked: this.config.armedActivationBlocked,
            managed_task_flow_api_available: managedApiAvailable,
            workboard_transport: "guarded_agent_tool",
            workboard_tool_name: WORKBOARD_TOOL_NAME,
            workboard_tool_availability:
                "verified_only_on_exact_guarded_call",
            private_state_store: "atomic_file_no_secrets",
            automatic_dispatch_allowed: false,
            automatic_external_write_allowed: false,
            automatic_retry_allowed: false,
            gateway_rpc_used: false,
            production_modified: false,
        };
    }

    async prepare(ctx, workItemJson) {
        if (this.config.mode !== "shadow") {
            fail(
                "WORK_RUNTIME_SHADOW_DISABLED",
                "Safe work runtime binding is disabled. Enable only workRuntime.mode=shadow after Owner review.",
            );
        }
        const preflight = this.preflight();
        if (!preflight.managed_task_flow_api_available) {
            fail(
                "WORK_RUNTIME_TASK_FLOW_UNAVAILABLE",
                "The required OpenClaw managed Task Flow API is unavailable.",
            );
        }
        const ownerContext = requireOwnerContext(ctx);
        const workItem = validateShadowWorkItem(
            parseWorkItemJson(workItemJson),
            ownerContext,
            this.now(),
        );
        const expectedWorkboardParams =
            buildWorkboardParams(workItem, this.config);
        const expectedWorkboardParamsFingerprintSha256 =
            workboardCreateParamsFingerprint(expectedWorkboardParams);
        const bindingId = `nrrtb_${digest32({
            contract_version: SAFE_WORK_RUNTIME_CONTRACT_VERSION,
            work_item_id: workItem.work_item_id,
            work_item_revision: workItem.revision,
            work_item_fingerprint_sha256:
                workItem.work_item_fingerprint_sha256,
            agent_id: ownerContext.agentId,
            session_fingerprint_sha256:
                ownerContext.sessionFingerprintSha256,
        })}`;
        const reservation = await this.store.reserve({
            bindingId,
            workItemId: workItem.work_item_id,
            missionId: workItem.mission_id,
            workItemRevision: workItem.revision,
            workItemFingerprintSha256:
                workItem.work_item_fingerprint_sha256,
            ownerBindingId: workItem.owner_policy.owner_binding_id,
            ownerReviewStepId:
                workItem.owner_policy.owner_review_step_id,
            agentId: ownerContext.agentId,
            sessionFingerprintSha256:
                ownerContext.sessionFingerprintSha256,
            requesterOriginFingerprintSha256:
                ownerContext.requesterOriginFingerprintSha256,
            boardId: this.config.boardId,
            expectedWorkboardParams,
            expectedWorkboardParamsFingerprintSha256,
        });
        if (!reservation.created) {
            return {
                ok: reservation.record.state === "prepared"
                    || reservation.record.state === "bound",
                duplicate_binding_reused: true,
                ...publicSummary(
                    reservation.record,
                    this.activeFlowBindings,
                    this.activeCardCalls,
                ),
                workboard_create_params:
                    reservation.record.state === "prepared"
                        ? reservation.record.expectedWorkboardParams
                        : null,
                next_step:
                    reservation.record.state === "prepared"
                        ? "Call workboard_create exactly once with the unchanged parameters. Do not claim or dispatch the card."
                        : "Do not retry any write. Use the Owner-only /noderooms work reconcile command if reconciliation is required.",
            };
        }

        this.activeFlowBindings.add(bindingId);
        try {
            const flowRuntime =
                this.taskRuntime.fromToolContext(ctx);
            if (!flowRuntime
                || typeof flowRuntime.createManaged !== "function") {
                fail(
                    "WORK_RUNTIME_TASK_FLOW_UNAVAILABLE",
                    "The bound managed Task Flow API is unavailable.",
                );
            }
            const flow = flowRuntime.createManaged({
                controllerId: CONTROLLER_ID,
                goal: `NodeRooms Owner review: ${workItem.objective.title}`,
                status: "waiting",
                notifyPolicy: "silent",
                currentStep: workItem.owner_policy.owner_review_step_id,
                stateJson: {
                    contract_version: SAFE_WORK_RUNTIME_CONTRACT_VERSION,
                    activation_state: "shadow",
                    binding_id: bindingId,
                    work_item_id: workItem.work_item_id,
                    mission_id: workItem.mission_id,
                    work_item_revision: workItem.revision,
                    work_item_fingerprint_sha256:
                        workItem.work_item_fingerprint_sha256,
                    live_dispatch_allowed: false,
                    external_write_allowed: false,
                    child_task_start_allowed: false,
                },
                waitJson: {
                    kind: "owner_review",
                    step_id: workItem.owner_policy.owner_review_step_id,
                    owner_binding_id:
                        workItem.owner_policy.owner_binding_id,
                    automatic_owner_decision_allowed: false,
                },
            });
            const completed = await this.store.completeFlow(bindingId, flow);
            return {
                ok: true,
                shadow_binding_prepared: true,
                ...publicSummary(
                    completed,
                    this.activeFlowBindings,
                    this.activeCardCalls,
                ),
                workboard_create_params: completed.expectedWorkboardParams,
                next_step:
                    "Call workboard_create exactly once with the unchanged parameters. Do not claim or dispatch the card.",
            };
        }
        catch {
            await this.store.markUncertain(
                bindingId,
                "Managed Task Flow creation did not complete locally; automatic retry is blocked.",
            ).catch(() => undefined);
            fail(
                "WORK_RUNTIME_TASK_FLOW_UNCERTAIN",
                "Managed Task Flow creation became uncertain. Do not retry automatically; use read-only reconciliation.",
            );
        }
        finally {
            this.activeFlowBindings.delete(bindingId);
        }
    }

    async beforeToolCall(event, ctx = {}) {
        if (event?.toolName !== WORKBOARD_TOOL_NAME) {
            return undefined;
        }
        const params = isRecord(event.params) ? event.params : {};
        const idempotencyKey =
            typeof params.idempotencyKey === "string"
                ? params.idempotencyKey
                : "";
        const looksNodeRooms = idempotencyKey.startsWith(IDEMPOTENCY_PREFIX)
            || params.tenant === NODEROOMS_TENANT
            || (Array.isArray(params.labels)
                && params.labels.includes("noderooms"));
        if (!looksNodeRooms) {
            return undefined;
        }
        if (this.config.mode !== "shadow") {
            return {
                block: true,
                blockReason:
                    "NodeRooms safe Workboard binding is disabled or not in shadow mode.",
            };
        }
        try {
            const agentId =
                typeof ctx.agentId === "string" ? ctx.agentId.trim() : "";
            const sessionKey =
                typeof ctx.sessionKey === "string" ? ctx.sessionKey.trim() : "";
            if (!CONTEXT_ID_PATTERN.test(agentId) || !sessionKey) {
                fail(
                    "WORK_RUNTIME_CONTEXT_REQUIRED",
                    "The trusted hook Agent and session context are required.",
                );
            }
            const context = {
                agentId,
                sessionFingerprintSha256: sha256Fingerprint({
                    contract_version:
                        "noderooms-openclaw-session-context-v1",
                    agent_id: agentId,
                    session_key: sessionKey,
                }),
            };
            const toolCallId =
                typeof event.toolCallId === "string"
                    ? event.toolCallId
                    : typeof ctx.toolCallId === "string"
                        ? ctx.toolCallId
                        : "";
            const record = await this.store.claimCardCreate({
                idempotencyKey,
                params,
                paramsFingerprintSha256:
                    workboardCreateParamsFingerprint(params),
                context,
                toolCallId,
            });
            this.activeCardCalls.add(record.activeToolCallId);
            return {
                params: record.expectedWorkboardParams,
            };
        }
        catch {
            return {
                block: true,
                blockReason:
                    "NodeRooms blocked a Workboard create call that did not match one exact Owner-bound shadow reservation.",
            };
        }
    }

    async afterToolCall(event) {
        if (event?.toolName !== WORKBOARD_TOOL_NAME) {
            return;
        }
        const toolCallId =
            typeof event.toolCallId === "string" ? event.toolCallId : "";
        if (!toolCallId || !this.activeCardCalls.has(toolCallId)) {
            return;
        }
        try {
            if (typeof event.error === "string" && event.error.trim()) {
                await this.store.markToolCallUncertain(
                    toolCallId,
                    "The Workboard create call returned an error after dispatch; its local outcome must be reconciled without retry.",
                );
                return;
            }
            const card = cardFromToolResult(event.result);
            if (!card) {
                await this.store.markToolCallUncertain(
                    toolCallId,
                    "The Workboard create result was missing or opaque; automatic retry is blocked.",
                );
                return;
            }
            const params = isRecord(event.params) ? event.params : {};
            const expected = validateExpectedParams(params);
            const validated = validateReturnedCard(card, expected);
            await this.store.completeCardCreate({
                toolCallId,
                params,
                cardId: validated.cardId,
                cardStatus: validated.status,
            });
        }
        catch {
            await this.store.markToolCallUncertain(
                toolCallId,
                "The Workboard create result failed exact validation; automatic retry is blocked.",
            ).catch(() => undefined);
        }
        finally {
            this.activeCardCalls.delete(toolCallId);
        }
    }

    async list(ctx) {
        const ownerContext = requireOwnerContext(ctx, true);
        const records = await this.store.list(ownerContext);
        return {
            ok: true,
            count: records.length,
            bindings: records.map((record) =>
                publicSummary(
                    record,
                    this.activeFlowBindings,
                    this.activeCardCalls,
                )),
        };
    }

    async reconcile(bindingId, ctx) {
        const ownerContext = requireOwnerContext(ctx, true);
        boundedString(bindingId, BINDING_ID_PATTERN, "binding id", 64);
        const record = await this.store.get(bindingId, ownerContext);
        const flowRuntime = this.taskRuntime.bindSession({
            sessionKey: ownerContext.sessionKey,
            requesterOrigin: { channel: ownerContext.channel },
        });
        const flow = typeof flowRuntime?.get === "function"
            && record.taskFlowId
            ? flowRuntime.get(record.taskFlowId)
            : undefined;
        return {
            ok: Boolean(flow),
            reconciliation_mode: "read_only",
            local_state_mutated: false,
            automatic_retry_attempted: false,
            binding: publicSummary(
                record,
                this.activeFlowBindings,
                this.activeCardCalls,
            ),
            managed_task_flow: flow
                ? {
                    flow_id: flow.flowId,
                    revision: flow.revision,
                    status: flow.status,
                    current_step: flow.currentStep ?? null,
                    cancel_requested:
                        Number.isFinite(flow.cancelRequestedAt),
                }
                : null,
            workboard_followup:
                publicState(
                    record,
                    this.activeFlowBindings,
                    this.activeCardCalls,
                ) === "reconcile_required"
                    ? "Use the read-only workboard_list/workboard_read surface to find the exact idempotency key. Do not repeat workboard_create."
                    : null,
        };
    }

    async cancel(bindingId, ctx) {
        const ownerContext = requireOwnerContext(ctx, true);
        boundedString(bindingId, BINDING_ID_PATTERN, "binding id", 64);
        const record = await this.store.get(bindingId, ownerContext);
        if (!record.taskFlowId) {
            fail(
                "WORK_RUNTIME_CANCEL_RECONCILE_REQUIRED",
                "The Task Flow reference is uncertain. Reconcile before any cancellation mutation.",
            );
        }
        const flowRuntime = this.taskRuntime.bindSession({
            sessionKey: ownerContext.sessionKey,
            requesterOrigin: { channel: ownerContext.channel },
        });
        if (!flowRuntime
            || typeof flowRuntime.get !== "function"
            || typeof flowRuntime.requestCancel !== "function") {
            fail(
                "WORK_RUNTIME_TASK_FLOW_UNAVAILABLE",
                "The bound managed Task Flow cancellation API is unavailable.",
            );
        }
        const current = flowRuntime.get(record.taskFlowId);
        if (!current || !Number.isSafeInteger(current.revision)) {
            fail(
                "WORK_RUNTIME_TASK_FLOW_NOT_FOUND",
                "The managed Task Flow was not found. No cancellation mutation was attempted.",
            );
        }
        const result = flowRuntime.requestCancel({
            flowId: record.taskFlowId,
            expectedRevision: current.revision,
            cancelRequestedAt: this.now(),
        });
        if (!isRecord(result) || result.applied !== true
            || !isRecord(result.flow)
            || !Number.isSafeInteger(result.flow.revision)) {
            fail(
                "WORK_RUNTIME_CANCEL_CONFLICT",
                "The managed Task Flow cancellation hit a revision conflict. Re-read before retrying.",
            );
        }
        const cancelled = await this.store.markCancelled(
            bindingId,
            ownerContext,
            result.flow.revision,
        );
        return {
            ok: true,
            owner_command_required: true,
            cancel_requested: true,
            no_new_tasks_allowed: true,
            workboard_dispatch_attempted: false,
            external_write_attempted: false,
            binding: publicSummary(
                cancelled,
                this.activeFlowBindings,
                this.activeCardCalls,
            ),
        };
    }

    clearRuntimeCache() {
        this.activeFlowBindings.clear();
        this.activeCardCalls.clear();
    }
}
