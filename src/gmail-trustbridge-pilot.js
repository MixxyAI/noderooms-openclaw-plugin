import { randomUUID } from "node:crypto";
import {
    chmod,
    lstat,
    mkdir,
    readFile,
    rename,
    rm,
    writeFile,
} from "node:fs/promises";
import path from "node:path";

import {
    buildGmailTrustBridgeReceipt,
    GMAIL_TRUSTBRIDGE_DEVELOPMENT_IDENTITY,
    validateGmailTrustBridgeReceipt,
    validateGmailTrustBridgeTrustAnchor,
} from "./gmail-trustbridge-receipt.js";
import {
    sha256Fingerprint,
} from "./passport-runtime-binding.js";

export const GMAIL_TRUSTBRIDGE_PILOT_CONTRACT_VERSION =
    "noderooms-gmail-trustbridge-pilot.v1";
export const GMAIL_TRUSTBRIDGE_DEFAULT_MODE = "off";
export const GMAIL_TRUSTBRIDGE_DELETE_ALLOWED = false;

const STORE_VERSION = 1;
const MAX_STORE_BYTES = 2_097_152;
const DEFAULT_MAX_ENTRIES = 256;
const MAX_ENTRIES = 1_000;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const AGENT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const MESSAGE_ID_PATTERN = /^[A-Za-z0-9_-]{1,256}$/;
const EMAIL_PATTERN =
    /^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/i;

const DEFAULT_PASSPORT_AGENT_ID = "noderooms-passport-agent";

const TOOL_PROFILES = Object.freeze({
    gmail_search_emails: Object.freeze({
        operation: "search",
        scope: "connector.gmail.message.search",
        actorRole: "passport_bound_gmail_agent",
        approvalPolicy: "none",
        sideEffectClass: "read",
    }),
    gmail_read_email_thread: Object.freeze({
        operation: "read",
        scope: "connector.gmail.thread.read",
        actorRole: "passport_bound_gmail_agent",
        approvalPolicy: "none",
        sideEffectClass: "read",
    }),
    gmail_create_draft: Object.freeze({
        operation: "draft",
        scope: "connector.gmail.message.draft",
        actorRole: "passport_bound_gmail_agent",
        approvalPolicy: "none",
        sideEffectClass: "write",
    }),
    gmail_send_email: Object.freeze({
        operation: "send",
        scope: "connector.gmail.message.send",
        actorRole: "passport_bound_gmail_agent",
        approvalPolicy: "allow_once",
        sideEffectClass: "write",
    }),
});

const HARD_DENY_TOOL_NAMES = new Set([
    "gmail_delete_emails",
    "gmail_forward_emails",
    "gmail_archive_emails",
    "gmail_apply_labels_to_emails",
]);

const TERMINAL_STATES = new Set([
    "committed",
    "failed",
    "unknown",
    "denied",
]);

export class GmailTrustBridgePilotError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "GmailTrustBridgePilotError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new GmailTrustBridgePilotError(code, message);
}

function isRecord(value) {
    return Boolean(value)
        && typeof value === "object"
        && !Array.isArray(value);
}

function normalizeAgentId(value, fallback) {
    const candidate = typeof value === "string" ? value.trim() : fallback;
    return AGENT_ID_PATTERN.test(candidate) ? candidate : fallback;
}

function normalizeFingerprint(value) {
    return typeof value === "string" && SHA256_PATTERN.test(value)
        ? value
        : null;
}

function canonicalTime(value = Date.now()) {
    const milliseconds = value instanceof Date
        ? value.getTime()
        : Number(value);
    if (!Number.isFinite(milliseconds)) {
        fail("GMAIL_PILOT_TIME_INVALID", "The pilot clock is invalid.");
    }
    return new Date(milliseconds).toISOString();
}

function normalizeAddress(value) {
    if (typeof value !== "string") {
        fail(
            "GMAIL_PILOT_RECIPIENT_INVALID",
            "Every Gmail recipient must be an exact bare email address.",
        );
    }
    const normalized = value.trim().toLowerCase();
    if (!EMAIL_PATTERN.test(normalized)) {
        fail(
            "GMAIL_PILOT_RECIPIENT_INVALID",
            "Every Gmail recipient must be an exact bare email address.",
        );
    }
    return normalized;
}

function normalizeOptionalAddress(value) {
    if (typeof value !== "string") {
        return null;
    }
    try {
        return normalizeAddress(value);
    }
    catch {
        return null;
    }
}

export function gmailAddressFingerprint(value) {
    return sha256Fingerprint({
        normalized_email: normalizeAddress(value),
    });
}

export function normalizeGmailTrustBridgeConfig(pluginConfig) {
    const raw = isRecord(pluginConfig?.gmailTrustBridge)
        ? pluginConfig.gmailTrustBridge
        : {};
    const requestedMode = typeof raw.mode === "string"
        ? raw.mode.trim()
        : GMAIL_TRUSTBRIDGE_DEFAULT_MODE;
    const mode = requestedMode === "pilot" ? "pilot" : "off";
    const passportAgentId = normalizeAgentId(
        raw.passportAgentId,
        DEFAULT_PASSPORT_AGENT_ID,
    );
    const accountBindingFingerprint = normalizeFingerprint(
        raw.accountBindingFingerprintSha256,
    );
    const recipientFingerprints = Array.isArray(
        raw.allowedRecipientFingerprintsSha256,
    )
        ? [...new Set(
            raw.allowedRecipientFingerprintsSha256
                .map(normalizeFingerprint)
                .filter(Boolean),
        )].toSorted()
        : [];
    const maxEntries = Number.isSafeInteger(raw.receiptLedgerMaxEntries)
        ? Math.max(1, Math.min(MAX_ENTRIES, raw.receiptLedgerMaxEntries))
        : DEFAULT_MAX_ENTRIES;
    const rawGog = isRecord(raw.gog) ? raw.gog : {};
    const gogAccount = normalizeOptionalAddress(rawGog.account);
    const gogHomePath = typeof rawGog.homePath === "string"
        && path.isAbsolute(rawGog.homePath)
        && rawGog.homePath.length <= 1_024
        ? rawGog.homePath
        : null;
    const gogClient = typeof rawGog.client === "string"
        && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(rawGog.client)
        ? rawGog.client
        : null;
    const gogExecutablePath = typeof rawGog.executablePath === "string"
        && path.isAbsolute(rawGog.executablePath)
        && rawGog.executablePath.length <= 1_024
        ? rawGog.executablePath
        : null;
    const gogExecutableSha256 = normalizeFingerprint(
        rawGog.executableSha256,
    );
    const gogAccountMatchesBinding = Boolean(
        gogAccount
        && accountBindingFingerprint
        && gmailAddressFingerprint(gogAccount)
            === accountBindingFingerprint,
    );
    const gogReady = Boolean(
        gogHomePath
        && gogClient
        && gogExecutablePath
        && gogExecutableSha256
        && gogAccountMatchesBinding,
    );
    const activationBlocked = mode === "pilot"
        && (!accountBindingFingerprint
            || recipientFingerprints.length !== 2
            || !gogReady);
    return Object.freeze({
        contractVersion: GMAIL_TRUSTBRIDGE_PILOT_CONTRACT_VERSION,
        developmentIdentity: GMAIL_TRUSTBRIDGE_DEVELOPMENT_IDENTITY,
        mode,
        requestedMode,
        passportAgentId,
        accountBindingFingerprintSha256:
            accountBindingFingerprint,
        allowedRecipientFingerprintsSha256:
            Object.freeze(recipientFingerprints),
        receiptLedgerMaxEntries: maxEntries,
        gog: Object.freeze({
            kind: "gog",
            account: gogAccount,
            homePath: gogHomePath,
            client: gogClient,
            executablePath: gogExecutablePath,
            executableSha256: gogExecutableSha256,
            accountMatchesBinding: gogAccountMatchesBinding,
            ready: gogReady,
        }),
        activationBlocked,
        deleteAllowed: GMAIL_TRUSTBRIDGE_DELETE_ALLOWED,
        defaultOff: true,
    });
}

function canonicalGmailToolName(value) {
    if (typeof value !== "string" || value.length > 256) {
        return null;
    }
    const candidate = value.split("__").at(-1);
    return /^gmail_[a-z0-9_]{3,96}$/.test(candidate)
        ? candidate
        : null;
}

function recipientFingerprints(message, allowedFingerprints) {
    if (!isRecord(message)) {
        fail(
            "GMAIL_PILOT_RECIPIENT_INVALID",
            "The Gmail message envelope is missing.",
        );
    }
    const rawRecipients = [];
    for (const key of ["to", "cc", "bcc"]) {
        const raw = message[key];
        if (raw === undefined || raw === null || raw === "") {
            continue;
        }
        if (typeof raw !== "string") {
            fail(
                "GMAIL_PILOT_RECIPIENT_INVALID",
                `message.${key} must contain exact bare email addresses.`,
            );
        }
        rawRecipients.push(
            ...raw.split(",").map((entry) => entry.trim()).filter(Boolean),
        );
    }
    if (rawRecipients.length !== 1) {
        fail(
            "GMAIL_PILOT_RECIPIENT_SET_INVALID",
            "The Alpha5 pilot permits exactly one recipient and no CC/BCC.",
        );
    }
    const fingerprints = rawRecipients
        .map(gmailAddressFingerprint)
        .toSorted();
    if (!fingerprints.every((entry) =>
        allowedFingerprints.includes(entry))) {
        fail(
            "GMAIL_PILOT_RECIPIENT_NOT_ALLOWED",
            "The Gmail recipient is outside the exact Alpha5 allowlist.",
        );
    }
    return fingerprints;
}

function messageEnvelope(toolName, params) {
    if (typeof params?.to === "string") {
        return params;
    }
    if (toolName === "gmail_create_draft") {
        return params.body?.message;
    }
    return params.message;
}

function actionProjection(toolName, params, config) {
    if (!isRecord(params)) {
        fail(
            "GMAIL_PILOT_PARAMS_INVALID",
            "The Gmail tool parameters are invalid.",
        );
    }
    const profile = TOOL_PROFILES[toolName];
    let operation = profile.operation;
    let targetProjection;
    if (["gmail_create_draft", "gmail_send_email"].includes(toolName)) {
        const message = messageEnvelope(toolName, params);
        const recipients = recipientFingerprints(
            message,
            config.allowedRecipientFingerprintsSha256,
        );
        if (toolName === "gmail_send_email"
            && typeof message.reply_message_id === "string"
            && message.reply_message_id.trim()) {
            operation = "reply";
        }
        targetProjection = {
            recipient_fingerprints_sha256: recipients,
        };
    }
    else {
        targetProjection = {
            read_selector_fingerprint_sha256:
                sha256Fingerprint(params),
        };
    }
    return Object.freeze({
        ...profile,
        operation,
        scope: operation === "reply"
            ? "connector.gmail.message.reply"
            : profile.scope,
        payloadFingerprintSha256: sha256Fingerprint(params),
        targetFingerprintSha256:
            sha256Fingerprint(targetProjection),
    });
}

function reservationId(event, ctx, action) {
    const toolCallId = typeof event.toolCallId === "string"
        ? event.toolCallId.trim()
        : "";
    const runId = typeof event.runId === "string"
        ? event.runId.trim()
        : (typeof ctx?.runId === "string" ? ctx.runId.trim() : "");
    if (!toolCallId || !runId) {
        fail(
            "GMAIL_PILOT_CALL_ID_REQUIRED",
            "Exact OpenClaw run and tool-call identifiers are required.",
        );
    }
    return `nrgmailres_${
        sha256Fingerprint({
            run_id: runId,
            tool_call_id: toolCallId,
            payload_fingerprint_sha256:
                action.payloadFingerprintSha256,
        }).slice(7, 39)
    }`;
}

function validateStoredReservation(value) {
    if (!isRecord(value)
        || typeof value.reservation_id !== "string"
        || !/^nrgmailres_[a-f0-9]{32}$/.test(value.reservation_id)
        || typeof value.operation !== "string"
        || typeof value.scope !== "string"
        || typeof value.tool_name !== "string"
        || typeof value.actor_role !== "string"
        || !SHA256_PATTERN.test(value.agent_id_fingerprint_sha256)
        || !SHA256_PATTERN.test(
            value.account_binding_fingerprint_sha256,
        )
        || !SHA256_PATTERN.test(value.target_fingerprint_sha256)
        || !SHA256_PATTERN.test(value.payload_fingerprint_sha256)
        || !["none", "allow_once"].includes(value.approval_policy)
        || typeof value.approval_consumed !== "boolean"
        || !Number.isSafeInteger(value.provider_attempt_count)
        || value.provider_attempt_count < 0
        || value.provider_attempt_count > 1
        || ![
            "awaiting_approval",
            "dispatching",
            "committed",
            "failed",
            "unknown",
            "denied",
        ].includes(value.state)
        || !Number.isFinite(Date.parse(value.created_at))
        || !Number.isFinite(Date.parse(value.updated_at))
        || !Number.isFinite(Date.parse(value.started_at))) {
        fail(
            "GMAIL_PILOT_STORE_INVALID",
            "The persisted Gmail pilot reservation is invalid.",
        );
    }
    const hasReceipt = value.receipt !== null
        && value.receipt !== undefined;
    const hasTrustAnchor = value.receipt_trust_anchor !== null
        && value.receipt_trust_anchor !== undefined;
    if (hasReceipt !== hasTrustAnchor
        || (hasReceipt && !isRecord(value.receipt))
        || (hasTrustAnchor && !isRecord(value.receipt_trust_anchor))) {
        fail(
            "GMAIL_PILOT_STORE_INVALID",
            "The persisted Gmail receipt and trust anchor are incomplete.",
        );
    }
    if (hasReceipt) {
        const trustAnchor = validateGmailTrustBridgeTrustAnchor(
            value.receipt_trust_anchor,
        );
        validateGmailTrustBridgeReceipt(value.receipt, {
            trustedReceiptAnchor: trustAnchor,
        });
    }
    return structuredClone(value);
}

export class GmailTrustBridgePilotStore {
    constructor(options) {
        if (!path.isAbsolute(options?.filePath ?? "")) {
            fail(
                "GMAIL_PILOT_STORE_PATH_INVALID",
                "The Gmail pilot store path must be absolute.",
            );
        }
        this.filePath = options.filePath;
        this.maxEntries = Number.isSafeInteger(options.maxEntries)
            ? Math.max(1, Math.min(MAX_ENTRIES, options.maxEntries))
            : DEFAULT_MAX_ENTRIES;
        this.queue = Promise.resolve();
    }

    async transact(operation) {
        const pending = this.queue.then(async () => {
            const store = await this.load();
            const result = await operation(store);
            await this.save(store);
            return result;
        });
        this.queue = pending.catch(() => undefined);
        return pending;
    }

    async createReservation(reservation) {
        return this.transact((store) => {
            if (store.reservations.some((entry) =>
                entry.reservation_id === reservation.reservation_id)) {
                fail(
                    "GMAIL_PILOT_REPLAY_BLOCKED",
                    "This exact Gmail tool call is already reserved.",
                );
            }
            if (store.reservations.length >= this.maxEntries) {
                const terminalIndex = store.reservations.findIndex((entry) =>
                    TERMINAL_STATES.has(entry.state));
                if (terminalIndex < 0) {
                    fail(
                        "GMAIL_PILOT_STORE_FULL",
                        "The Gmail pilot has too many unresolved actions.",
                    );
                }
                store.reservations.splice(terminalIndex, 1);
            }
            const validated = validateStoredReservation(reservation);
            store.reservations.push(validated);
            return structuredClone(validated);
        });
    }

    async resolveApproval(reservationIdValue, resolution, resolvedAt) {
        return this.transact((store) => {
            const reservation = store.reservations.find((entry) =>
                entry.reservation_id === reservationIdValue);
            if (!reservation
                || reservation.state !== "awaiting_approval") {
                fail(
                    "GMAIL_PILOT_APPROVAL_STATE_INVALID",
                    "The Gmail allow-once reservation is unavailable.",
                );
            }
            reservation.updated_at = resolvedAt;
            if (resolution !== "allow-once") {
                reservation.state = "denied";
                reservation.approval_consumed = false;
                return structuredClone(reservation);
            }
            reservation.state = "dispatching";
            reservation.started_at = resolvedAt;
            reservation.approval_consumed = true;
            reservation.provider_attempt_count = 1;
            return structuredClone(reservation);
        });
    }

    async complete(
        reservationIdValue,
        receipt,
        trustAnchor,
        outcomeStatus,
        completedAt,
    ) {
        return this.transact((store) => {
            const reservation = store.reservations.find((entry) =>
                entry.reservation_id === reservationIdValue);
            if (!reservation || reservation.state !== "dispatching") {
                fail(
                    "GMAIL_PILOT_RESULT_STATE_INVALID",
                    "No dispatching Gmail reservation matches this result.",
                );
            }
            reservation.state = outcomeStatus;
            reservation.updated_at = completedAt;
            const validatedAnchor =
                validateGmailTrustBridgeTrustAnchor(trustAnchor);
            validateGmailTrustBridgeReceipt(receipt, {
                trustedReceiptAnchor: validatedAnchor,
            });
            reservation.receipt = structuredClone(receipt);
            reservation.receipt_trust_anchor =
                structuredClone(validatedAnchor);
            return structuredClone(reservation);
        });
    }

    async find(reservationIdValue) {
        await this.queue;
        const store = await this.load();
        const reservation = store.reservations.find((entry) =>
            entry.reservation_id === reservationIdValue);
        return reservation ? structuredClone(reservation) : null;
    }

    async summary() {
        await this.queue;
        const store = await this.load();
        const counts = {};
        for (const reservation of store.reservations) {
            counts[reservation.state] =
                (counts[reservation.state] ?? 0) + 1;
        }
        const receiptRecords = store.reservations
            .filter((entry) => entry.receipt)
            .map((entry) => ({
                receipt: entry.receipt,
                trust_anchor: entry.receipt_trust_anchor,
            }))
            .slice(-20);
        return {
            store_version: STORE_VERSION,
            reservation_count: store.reservations.length,
            state_counts: counts,
            receipts: receiptRecords.map((entry) => entry.receipt),
            receipt_records: receiptRecords,
            raw_parameters_persisted: false,
            raw_results_persisted: false,
            raw_recipient_values_persisted: false,
            provider_credentials_persisted: false,
        };
    }

    clearRuntimeCache() {
        this.queue = Promise.resolve();
    }

    async load() {
        try {
            const info = await lstat(this.filePath);
            if (!info.isFile()
                || info.isSymbolicLink()
                || info.size > MAX_STORE_BYTES) {
                fail(
                    "GMAIL_PILOT_STORE_INVALID",
                    "The Gmail pilot state file is unsafe.",
                );
            }
            const parsed = JSON.parse(await readFile(this.filePath, "utf8"));
            if (!isRecord(parsed)
                || parsed.version !== STORE_VERSION
                || !Array.isArray(parsed.reservations)
                || parsed.reservations.length > this.maxEntries) {
                fail(
                    "GMAIL_PILOT_STORE_INVALID",
                    "The Gmail pilot state schema is invalid.",
                );
            }
            return {
                version: STORE_VERSION,
                reservations:
                    parsed.reservations.map(validateStoredReservation),
            };
        }
        catch (error) {
            if (error?.code === "ENOENT") {
                return {
                    version: STORE_VERSION,
                    reservations: [],
                };
            }
            if (error instanceof GmailTrustBridgePilotError) {
                throw error;
            }
            fail(
                "GMAIL_PILOT_STORE_INVALID",
                "The Gmail pilot state could not be read safely.",
            );
        }
    }

    async save(store) {
        const directory = path.dirname(this.filePath);
        await mkdir(directory, { recursive: true, mode: 0o700 });
        await chmod(directory, 0o700).catch(() => undefined);
        const serialized = `${JSON.stringify(store, null, 2)}\n`;
        if (Buffer.byteLength(serialized, "utf8") > MAX_STORE_BYTES) {
            fail(
                "GMAIL_PILOT_STORE_TOO_LARGE",
                "The Gmail pilot state exceeded its bounded size.",
            );
        }
        const temporary =
            `${this.filePath}.${process.pid}.${randomUUID()}.tmp`;
        try {
            await writeFile(temporary, serialized, {
                encoding: "utf8",
                mode: 0o600,
                flag: "wx",
            });
            await rename(temporary, this.filePath);
            await chmod(this.filePath, 0o600).catch(() => undefined);
        }
        finally {
            await rm(temporary, { force: true }).catch(() => undefined);
        }
    }
}

function approvalSeverity(operation) {
    return ["send", "reply", "forward"].includes(operation)
        ? "critical"
        : "warning";
}

function blockReason(error) {
    if (error instanceof GmailTrustBridgePilotError) {
        return `${error.code}: ${error.message}`;
    }
    return "GMAIL_PILOT_POLICY_ERROR: Gmail TrustBridge stopped safely.";
}

export class GmailTrustBridgePilotController {
    constructor(options) {
        if (!options?.config
            || !options.store
            || !options.receiptSigner
            || typeof options.receiptSigner.signReceiptFingerprint
                !== "function") {
            fail(
                "GMAIL_PILOT_CONTROLLER_INVALID",
                "The Gmail pilot controller dependencies are incomplete.",
            );
        }
        this.config = options.config;
        this.store = options.store;
        this.receiptSigner = options.receiptSigner;
        this.now = options.now ?? Date.now;
    }

    async beforeToolCall(event, ctx = {}) {
        const toolName = canonicalGmailToolName(event?.toolName);
        if (!toolName) {
            return undefined;
        }
        if (HARD_DENY_TOOL_NAMES.has(toolName)) {
            return {
                block: true,
                blockReason:
                    "NodeRooms Alpha5 permanently prohibits Gmail delete.",
            };
        }
        if (this.config.mode === "off") {
            return undefined;
        }
        if (this.config.activationBlocked) {
            return {
                block: true,
                blockReason:
                    "Gmail TrustBridge pilot activation is incomplete.",
            };
        }
        const profile = TOOL_PROFILES[toolName];
        if (!profile) {
            return {
                block: true,
                blockReason:
                    "This Gmail tool is outside the exact Alpha5 pilot profile.",
            };
        }
        try {
            if (ctx.agentId !== this.config.passportAgentId) {
                fail(
                    "GMAIL_PILOT_AGENT_MISMATCH",
                    "The Gmail capability belongs to another Passport-bound Agent.",
                );
            }
            const action = actionProjection(
                toolName,
                event.params,
                this.config,
            );
            const now = canonicalTime(this.now());
            const id = reservationId(event, ctx, action);
            const reservation = {
                reservation_id: id,
                operation: action.operation,
                scope: action.scope,
                tool_name: toolName,
                actor_role: action.actorRole,
                agent_id_fingerprint_sha256: sha256Fingerprint({
                    openclaw_agent_id: ctx.agentId,
                }),
                account_binding_fingerprint_sha256:
                    this.config.accountBindingFingerprintSha256,
                target_fingerprint_sha256:
                    action.targetFingerprintSha256,
                payload_fingerprint_sha256:
                    action.payloadFingerprintSha256,
                approval_policy: action.approvalPolicy,
                approval_consumed: false,
                provider_attempt_count:
                    action.approvalPolicy === "none" ? 1 : 0,
                state: action.approvalPolicy === "none"
                    ? "dispatching"
                    : "awaiting_approval",
                created_at: now,
                started_at: now,
                updated_at: now,
                receipt: null,
                receipt_trust_anchor: null,
            };
            await this.store.createReservation(reservation);
            if (action.approvalPolicy === "none") {
                return undefined;
            }
            return {
                requireApproval: {
                    title: `Approve Gmail ${action.operation}`.slice(0, 80),
                    description:
                        `Allow one exact ${action.operation} action under ${action.scope}.`,
                    severity: approvalSeverity(action.operation),
                    timeoutMs: 120_000,
                    timeoutBehavior: "deny",
                    timeoutReason:
                        "The one-action Gmail approval expired.",
                    allowedDecisions: ["allow-once", "deny"],
                    pluginId: "noderooms",
                    onResolution: async (resolution) => {
                        await this.store.resolveApproval(
                            id,
                            resolution,
                            canonicalTime(this.now()),
                        );
                    },
                },
            };
        }
        catch (error) {
            return {
                block: true,
                blockReason: blockReason(error),
            };
        }
    }

    async afterToolCall(event, ctx = {}) {
        const toolName = canonicalGmailToolName(event?.toolName);
        if (!toolName
            || HARD_DENY_TOOL_NAMES.has(toolName)
            || this.config.mode !== "pilot"
            || !TOOL_PROFILES[toolName]) {
            return;
        }
        const action = actionProjection(
            toolName,
            event.params,
            this.config,
        );
        const id = reservationId(event, ctx, action);
        const reservation = await this.store.find(id);
        if (!reservation || reservation.state !== "dispatching") {
            fail(
                "GMAIL_PILOT_RESULT_STATE_INVALID",
                "The Gmail provider result has no active one-action reservation.",
            );
        }
        const completedAt = canonicalTime(this.now());
        const mutation = action.sideEffectClass === "write";
        const outcomeStatus = event.error
            ? (mutation ? "unknown" : "failed")
            : "committed";
        const providerObservationFingerprint = sha256Fingerprint({
            result: event.result ?? null,
            error: event.error ?? null,
            duration_ms:
                Number.isFinite(event.durationMs)
                    ? Math.round(event.durationMs)
                    : null,
        });
        const receipt = buildGmailTrustBridgeReceipt({
            reservation_id: reservation.reservation_id,
            operation: reservation.operation,
            scope: reservation.scope,
            tool_name: reservation.tool_name,
            actor_role: reservation.actor_role,
            agent_id_fingerprint_sha256:
                reservation.agent_id_fingerprint_sha256,
            account_binding_fingerprint_sha256:
                reservation.account_binding_fingerprint_sha256,
            target_fingerprint_sha256:
                reservation.target_fingerprint_sha256,
            payload_fingerprint_sha256:
                reservation.payload_fingerprint_sha256,
            approval_policy: reservation.approval_policy,
            approval_consumed: reservation.approval_consumed,
            provider_attempt_count:
                reservation.provider_attempt_count,
            provider_observation_fingerprint_sha256:
                providerObservationFingerprint,
            outcome_status: outcomeStatus,
            started_at: reservation.started_at,
            completed_at: completedAt,
        }, {
            receiptSigner: this.receiptSigner,
        });
        validateGmailTrustBridgeReceipt(receipt, {
            trustedReceiptAnchor:
                this.receiptSigner.trust_anchor,
        });
        await this.store.complete(
            id,
            receipt,
            this.receiptSigner.trust_anchor,
            outcomeStatus,
            completedAt,
        );
    }

    async status() {
        return {
            contract_version:
                GMAIL_TRUSTBRIDGE_PILOT_CONTRACT_VERSION,
            development_identity:
                GMAIL_TRUSTBRIDGE_DEVELOPMENT_IDENTITY,
            mode: this.config.mode,
            default_off: true,
            activation_blocked: this.config.activationBlocked,
            passport_agent_bound: Boolean(this.config.passportAgentId),
            passport_agent_id_included: false,
            account_binding_present:
                Boolean(this.config.accountBindingFingerprintSha256),
            allowed_recipient_fingerprint_count:
                this.config.allowedRecipientFingerprintsSha256.length,
            provider: {
                kind: "gog",
                ready: this.config.gog.ready,
                account_binding_matches:
                    this.config.gog.accountMatchesBinding,
                executable_binding_present: Boolean(
                    this.config.gog.executablePath
                    && this.config.gog.executableSha256,
                ),
                credential_store_binding_present: Boolean(
                    this.config.gog.homePath
                    && this.config.gog.client,
                ),
                raw_account_included: false,
                raw_home_path_included: false,
                raw_client_name_included: false,
                raw_executable_path_included: false,
            },
            supported_tools: Object.keys(TOOL_PROFILES).toSorted(),
            delete_allowed: false,
            delete_hard_denied: true,
            unknown_gmail_tools_fail_closed_in_pilot: true,
            receipt_trust_anchor:
                structuredClone(this.receiptSigner.trust_anchor),
            ledger: await this.store.summary(),
        };
    }

    clearRuntimeCache() {
        this.store.clearRuntimeCache();
    }
}
