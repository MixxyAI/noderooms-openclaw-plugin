import { createHash, randomBytes, randomUUID } from "node:crypto";
import { chmod, lstat, mkdir, open, readFile, rename, rm, stat, writeFile, } from "node:fs/promises";
import path from "node:path";
import { ALL_SCOPES, ARRIVAL_ID_PATTERN, NodeRoomsError, POLICY_ID_PATTERN, REQUEST_ID_PATTERN, } from "./contracts.js";
import { boundedString, positiveInteger, requestedScopes } from "./sdk/validation.js";
import { validateCanonicalReceipt } from "./sdk/action-protocol.js";
export const ACTION_INTENT_TTL_MS = 2 * 60 * 60_000;
export const ACTION_INTENT_RETENTION_MS = 24 * 60 * 60_000;
export const ACTION_INTENT_COMMIT_STALE_MS = 10 * 60_000;
export const ACTION_INTENT_MAX_ENTRIES = 128;
export const ACTION_INTENT_MAX_FILE_BYTES = 1_048_576;
export const ACTION_INTENT_ID_PATTERN = /^nrwi_[a-f0-9]{32}$/;
const STORE_VERSION = 1;
const RESULT_FORMAT_CANONICAL = "canonical-v1";
const RESULT_FORMAT_LEGACY = "legacy-v1";
const RESULT_FORMAT_OPAQUE = "opaque-v1";
const LOCK_STALE_MS = 30_000;
const LOCK_RETRY_COUNT = 100;
const LOCK_RETRY_DELAY_MS = 10;
function iso(ms) {
    return new Date(ms).toISOString();
}
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
function canonicalJson(value) {
    if (Array.isArray(value)) {
        return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
    }
    if (value && typeof value === "object") {
        const record = value;
        return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}
function stableFingerprint(payload) {
    return createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex");
}
function assertIntentId(intentId) {
    if (!ACTION_INTENT_ID_PATTERN.test(intentId)) {
        throw new NodeRoomsError("INVALID_ACTION_INTENT_ID", "The NodeRooms action intent id is invalid.");
    }
}
function assertCommandOwner(owner) {
    if (owner.senderIsOwner !== true || owner.isAuthorizedSender !== true) {
        throw new NodeRoomsError("OWNER_COMMAND_REQUIRED", "Only an authenticated OpenClaw Owner may commit or deny a NodeRooms action intent.");
    }
    if (typeof owner.agentId !== "string"
        || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(owner.agentId)) {
        throw new NodeRoomsError(
            "OPENCLAW_AGENT_CONTEXT_REQUIRED",
            "A trusted canonical OpenClaw Agent id is required to resolve NodeRooms action intents.",
        );
    }
    if (!owner.channel.trim()) {
        throw new NodeRoomsError("OWNER_CHANNEL_REQUIRED", "The owner command channel is unavailable.");
    }
}
function assertSameOwner(intent, owner) {
    assertCommandOwner(owner);
    if (owner.agentId !== intent.owner.agentId) {
        throw new NodeRoomsError("ACTION_INTENT_AGENT_MISMATCH", "The NodeRooms action intent belongs to another OpenClaw Agent.");
    }
    if (owner.channel !== intent.owner.channel || owner.senderId !== intent.owner.requesterSenderId) {
        throw new NodeRoomsError("ACTION_INTENT_OWNER_MISMATCH", "The NodeRooms action intent must be resolved by the same verified Owner on the same channel.");
    }
}
function publicSummary(intent) {
    return {
        intent_id: intent.id,
        action: intent.kind,
        state: intent.state,
        fingerprint_sha256: intent.fingerprint,
        created_at: iso(intent.createdAtMs),
        expires_at: iso(intent.expiresAtMs),
        public_write_attempted: intent.result?.public_write_attempted === true
            || intent.state === "committing" || intent.state === "committed" || intent.state === "failed" || intent.state === "unknown",
        replay_blocked: intent.state !== "prepared",
    };
}
function asRecord(value, code) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new NodeRoomsError(code, "The NodeRooms action intent state is invalid.");
    }
    return value;
}
function requiredString(record, key, max = 512) {
    const value = record[key];
    if (typeof value !== "string" || value.length < 1 || value.length > max) {
        throw new NodeRoomsError("ACTION_INTENT_STORE_INVALID", `The persisted NodeRooms action intent field ${key} is invalid.`);
    }
    return value;
}
function requiredNumber(record, key) {
    const value = record[key];
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new NodeRoomsError("ACTION_INTENT_STORE_INVALID", `The persisted NodeRooms action intent field ${key} is invalid.`);
    }
    return value;
}
function validatePayload(value) {
    const record = asRecord(value, "ACTION_INTENT_PAYLOAD_INVALID");
    const kind = requiredString(record, "kind", 64);
    switch (kind) {
        case "guest_post": {
            const roomSlug = requiredString(record, "roomSlug", 80);
            if (roomSlug !== "playground" && roomSlug !== "builders-lab") {
                throw new NodeRoomsError("ACTION_INTENT_PAYLOAD_INVALID", "The persisted Guest post room is invalid.");
            }
            return { kind, roomSlug, body: boundedString(record.body, "body", 2, 600) };
        }
        case "guest_comment":
            return {
                kind,
                postId: positiveInteger(record.postId, "post_id"),
                body: boundedString(record.body, "body", 2, 400),
            };
        case "passport_request": {
            const reason = record.reason;
            if (reason === undefined)
                return { kind };
            if (typeof reason !== "string" || reason.length > 280) {
                throw new NodeRoomsError("ACTION_INTENT_PAYLOAD_INVALID", "The persisted Passport reason is invalid.");
            }
            return { kind, reason };
        }
        case "claim_invite": {
            const agentName = boundedString(record.agentName, "agent_name", 1, 80).trim();
            const description = record.agentDescription;
            if (description === undefined)
                return { kind, agentName };
            if (typeof description !== "string" || description.length > 280) {
                throw new NodeRoomsError("ACTION_INTENT_PAYLOAD_INVALID", "The persisted Agent description is invalid.");
            }
            return { kind, agentName, agentDescription: description };
        }
        case "capability_request": {
            const scopes = requestedScopes(record.requestedScopes);
            if (scopes.length > ALL_SCOPES.length) {
                throw new NodeRoomsError("ACTION_INTENT_PAYLOAD_INVALID", "The persisted capability request is invalid.");
            }
            return { kind, requestedScopes: scopes };
        }
        case "run_lease_claim": {
            const arrivalId = requiredString(record, "arrivalId", 128);
            const requestId = requiredString(record, "requestId", 128);
            const leasePolicyId = requiredString(record, "leasePolicyId", 128);
            if (!ARRIVAL_ID_PATTERN.test(arrivalId) || !REQUEST_ID_PATTERN.test(requestId) || !POLICY_ID_PATTERN.test(leasePolicyId)) {
                throw new NodeRoomsError("ACTION_INTENT_PAYLOAD_INVALID", "The persisted run lease identifiers are invalid.");
            }
            return { kind, arrivalId, requestId, leasePolicyId };
        }
        default:
            throw new NodeRoomsError("ACTION_INTENT_PAYLOAD_INVALID", "The persisted NodeRooms action kind is invalid.");
    }
}
function validateIntent(value) {
    const record = asRecord(value, "ACTION_INTENT_STORE_INVALID");
    const id = requiredString(record, "id", 64);
    assertIntentId(id);
    const payload = validatePayload(record.payload);
    const ownerRecord = asRecord(record.owner, "ACTION_INTENT_STORE_INVALID");
    const owner = {
        agentId: requiredString(ownerRecord, "agentId", 128),
        channel: requiredString(ownerRecord, "channel", 128),
        requesterSenderId: requiredString(ownerRecord, "requesterSenderId", 256),
    };
    const state = requiredString(record, "state", 32);
    if (!["prepared", "committing", "committed", "failed", "denied", "expired", "unknown"].includes(state)) {
        throw new NodeRoomsError("ACTION_INTENT_STORE_INVALID", "The persisted NodeRooms action state is invalid.");
    }
    const fingerprint = requiredString(record, "fingerprint", 64);
    if (!/^[a-f0-9]{64}$/.test(fingerprint) || fingerprint !== stableFingerprint(payload)) {
        throw new NodeRoomsError("ACTION_INTENT_FINGERPRINT_MISMATCH", "The persisted NodeRooms action payload failed its consistency check.");
    }
    const intent = {
        id,
        kind: payload.kind,
        payload,
        owner,
        state,
        fingerprint,
        createdAtMs: requiredNumber(record, "createdAtMs"),
        expiresAtMs: requiredNumber(record, "expiresAtMs"),
    };
    if (record.commitStartedAtMs !== undefined) {
        intent.commitStartedAtMs = requiredNumber(record, "commitStartedAtMs");
    }
    if (record.result !== undefined) {
        const storedResult = asRecord(record.result, "ACTION_INTENT_STORE_INVALID");
        let resultFormat = typeof record.resultFormat === "string" ? record.resultFormat : undefined;
        if (resultFormat === undefined) {
            const looksCanonical = storedResult.protocol_version === "noderooms-action-idempotency-v1"
                || typeof storedResult.receipt_id === "string"
                || storedResult.server_idempotency_enforced !== undefined;
            resultFormat = looksCanonical ? RESULT_FORMAT_CANONICAL
                : (payload.kind === "guest_post" || payload.kind === "guest_comment" ? RESULT_FORMAT_LEGACY : RESULT_FORMAT_OPAQUE);
        }
        if (![RESULT_FORMAT_CANONICAL, RESULT_FORMAT_LEGACY, RESULT_FORMAT_OPAQUE].includes(resultFormat)) {
            throw new NodeRoomsError("ACTION_INTENT_RESULT_FORMAT_INVALID", "The persisted NodeRooms action result format is invalid.");
        }
        if (payload.kind === "guest_post" || payload.kind === "guest_comment") {
            if (resultFormat === RESULT_FORMAT_CANONICAL) {
                const canonical = validateCanonicalReceipt(storedResult, {
                    actionId: id,
                    fingerprintSha256: fingerprint,
                    actionType: payload.kind,
                });
                if (state === "committed" && canonical.action_status !== "committed") {
                    throw new NodeRoomsError("ACTION_INTENT_RESULT_STATE_MISMATCH", "The persisted committed intent does not contain a committed canonical receipt.");
                }
                if (state === "failed" && canonical.action_status !== "failed") {
                    throw new NodeRoomsError("ACTION_INTENT_RESULT_STATE_MISMATCH", "The persisted failed intent does not contain a failed canonical receipt.");
                }
                if (state === "unknown" && canonical.action_status !== "processing" && canonical.action_status !== "unknown") {
                    throw new NodeRoomsError("ACTION_INTENT_RESULT_STATE_MISMATCH", "The persisted uncertain intent contains an incompatible canonical receipt.");
                }
                intent.result = canonical;
            }
            else if (resultFormat === RESULT_FORMAT_LEGACY) {
                intent.result = storedResult;
            }
            else {
                throw new NodeRoomsError("ACTION_INTENT_RESULT_FORMAT_INVALID", "A Guest post or comment intent cannot contain an opaque persisted result.");
            }
        }
        else {
            if (resultFormat !== RESULT_FORMAT_OPAQUE) {
                throw new NodeRoomsError("ACTION_INTENT_RESULT_FORMAT_INVALID", "A non-social NodeRooms intent must use the opaque result format.");
            }
            intent.result = storedResult;
        }
        intent.resultFormat = resultFormat;
    }
    if (record.terminalMessage !== undefined) {
        intent.terminalMessage = requiredString(record, "terminalMessage", 1024);
    }
    if (intent.kind !== payload.kind || intent.expiresAtMs < intent.createdAtMs) {
        throw new NodeRoomsError("ACTION_INTENT_STORE_INVALID", "The persisted NodeRooms action intent is inconsistent.");
    }
    return intent;
}
function cloneIntent(intent) {
    return structuredClone(intent);
}
export class ActionIntentStore {
    now;
    stateFilePath;
    lockFilePath;
    constructor(options) {
        if (!path.isAbsolute(options.stateFilePath)) {
            throw new NodeRoomsError("ACTION_INTENT_STATE_PATH_INVALID", "The NodeRooms action intent state path must be absolute.");
        }
        this.stateFilePath = options.stateFilePath;
        this.lockFilePath = `${options.stateFilePath}.lock`;
        this.now = options.now ?? Date.now;
    }
    async prepare(payloadInput, owner) {
        const payload = validatePayload(payloadInput);
        if (!owner.agentId.trim() || !owner.channel.trim() || !owner.requesterSenderId.trim()) {
            throw new NodeRoomsError("OWNER_CONTEXT_REQUIRED", "A trusted OpenClaw Owner, channel, sender, and Agent context are required to prepare a NodeRooms action intent.");
        }
        return this.withLock(async () => {
            const store = await this.loadStore();
            const changed = this.normalizeStore(store);
            this.enforceCapacity(store);
            const fingerprint = stableFingerprint(payload);
            const existing = store.intents.find((intent) => intent.state === "prepared"
                && intent.fingerprint === fingerprint
                && intent.owner.agentId === owner.agentId
                && intent.owner.channel === owner.channel
                && intent.owner.requesterSenderId === owner.requesterSenderId);
            if (existing) {
                if (changed)
                    await this.saveStore(store);
                return {
                    ok: true,
                    write_intent_prepared: true,
                    duplicate_prepared_intent_reused: true,
                    ...publicSummary(existing),
                    owner_confirmation_required: true,
                    commit_command: `/noderooms commit ${existing.id}`,
                    deny_command: `/noderooms deny ${existing.id}`,
                    intent_storage: "openclaw_private_state_non_secret",
                    intent_restart_safe: true,
                    intent_ttl_seconds: ACTION_INTENT_TTL_MS / 1000,
                };
            }
            const createdAtMs = this.now();
            const intent = {
                id: `nrwi_${randomBytes(16).toString("hex")}`,
                kind: payload.kind,
                payload,
                owner: { ...owner },
                state: "prepared",
                fingerprint,
                createdAtMs,
                expiresAtMs: createdAtMs + ACTION_INTENT_TTL_MS,
            };
            store.intents.push(intent);
            await this.saveStore(store);
            return {
                ok: true,
                write_intent_prepared: true,
                ...publicSummary(intent),
                owner_confirmation_required: true,
                commit_command: `/noderooms commit ${intent.id}`,
                deny_command: `/noderooms deny ${intent.id}`,
                intent_storage: "openclaw_private_state_non_secret",
                intent_restart_safe: true,
                intent_ttl_seconds: ACTION_INTENT_TTL_MS / 1000,
            };
        });
    }
    async list(owner) {
        assertCommandOwner(owner);
        return this.withLock(async () => {
            const store = await this.loadStore();
            if (this.normalizeStore(store))
                await this.saveStore(store);
            const intents = store.intents
                .filter((intent) => intent.owner.channel === owner.channel
                && intent.owner.requesterSenderId === owner.senderId
                && intent.owner.agentId === owner.agentId)
                .map((intent) => publicSummary(intent));
            return { ok: true, count: intents.length, intents };
        });
    }
    async deny(intentId, owner) {
        return this.withLock(async () => {
            const store = await this.loadStore();
            this.normalizeStore(store);
            const intent = this.requireIntent(store, intentId);
            assertSameOwner(intent, owner);
            this.expireIfNeeded(intent);
            if (intent.state === "denied") {
                await this.saveStore(store);
                return { ok: true, already_denied: true, ...publicSummary(intent) };
            }
            if (intent.state !== "prepared") {
                throw new NodeRoomsError("ACTION_INTENT_NOT_DENIABLE", `The NodeRooms action intent is ${intent.state} and cannot be denied now.`);
            }
            intent.state = "denied";
            intent.terminalMessage = "Denied explicitly by the verified OpenClaw Owner.";
            await this.saveStore(store);
            return { ok: true, denied: true, ...publicSummary(intent) };
        });
    }

    async commit(intentId, owner, executor) {
        const prepared = await this.withLock(async () => {
            const store = await this.loadStore();
            this.normalizeStore(store);
            const intent = this.requireIntent(store, intentId);
            assertSameOwner(intent, owner);
            this.expireIfNeeded(intent);
            if (intent.state === "committed" && intent.result) {
                await this.saveStore(store);
                return { terminal: "committed", intent: cloneIntent(intent) };
            }
            if (intent.state === "failed" && intent.result) {
                await this.saveStore(store);
                return { terminal: "failed", intent: cloneIntent(intent) };
            }
            if (intent.state !== "prepared") {
                throw new NodeRoomsError("ACTION_INTENT_NOT_COMMITTABLE", `The NodeRooms action intent is ${intent.state} and cannot be committed.`);
            }
            intent.state = "committing";
            intent.commitStartedAtMs = this.now();
            intent.terminalMessage = "Commit started by an authenticated OpenClaw Owner command; local replay is blocked.";
            await this.saveStore(store);
            return { terminal: null, intent: cloneIntent(intent) };
        });
        if (prepared.terminal === "committed") {
            return {
                ok: true,
                already_committed: true,
                duplicate_write_prevented: true,
                ...publicSummary(prepared.intent),
                result: prepared.intent.result ?? {},
            };
        }
        if (prepared.terminal === "failed") {
            return {
                ok: false,
                already_failed: true,
                duplicate_write_prevented: true,
                ...publicSummary(prepared.intent),
                result: prepared.intent.result ?? {},
            };
        }
        try {
            const result = asRecord(await executor(Object.freeze(prepared.intent)), "ACTION_INTENT_RESULT_INVALID");
            return await this.withLock(async () => {
                const store = await this.loadStore();
                this.normalizeStore(store);
                const intent = this.requireIntent(store, intentId);
                assertSameOwner(intent, owner);
                if (intent.state !== "committing" || intent.fingerprint !== prepared.intent.fingerprint) {
                    throw new NodeRoomsError("ACTION_INTENT_STATE_CONFLICT", "The NodeRooms action intent changed while its commit was running. Replay remains blocked.");
                }
                let normalizedResult = result;
                if (intent.kind === "guest_post" || intent.kind === "guest_comment") {
                    normalizedResult = validateCanonicalReceipt(result, {
                        actionId: intent.id,
                        fingerprintSha256: intent.fingerprint,
                        actionType: intent.kind,
                    });
                    intent.resultFormat = RESULT_FORMAT_CANONICAL;
                }
                else {
                    intent.resultFormat = RESULT_FORMAT_OPAQUE;
                }
                const receiptStatus = typeof normalizedResult.action_status === "string" ? normalizedResult.action_status : undefined;
                intent.result = normalizedResult;
                if (receiptStatus === "committed") {
                    intent.state = "committed";
                    intent.terminalMessage = "Committed through NodeRooms server-side idempotency and sealed by a canonical receipt.";
                }
                else if (receiptStatus === "failed") {
                    intent.state = "failed";
                    intent.terminalMessage = "NodeRooms returned a canonical failed receipt. Replay remains blocked.";
                }
                else if (receiptStatus === "processing" || receiptStatus === "unknown") {
                    intent.state = "unknown";
                    intent.terminalMessage = "NodeRooms returned a non-terminal or uncertain canonical receipt. Use /noderooms reconcile; write replay is blocked.";
                }
                else {
                    intent.state = "committed";
                    intent.terminalMessage = "Committed exactly once by an authenticated OpenClaw Owner command.";
                }
                await this.saveStore(store);
                return {
                    ok: intent.state === "committed",
                    committed: intent.state === "committed",
                    failed: intent.state === "failed",
                    reconciliation_required: intent.state === "unknown",
                    duplicate_write_prevented: true,
                    ...publicSummary(intent),
                    result: intent.result,
                };
            });
        }
        catch (error) {
            const noWrite = error && typeof error === "object" && error.publicWriteAttempted === false;
            try {
                await this.withLock(async () => {
                    const store = await this.loadStore();
                    this.normalizeStore(store);
                    const intent = this.requireIntent(store, intentId);
                    if (intent.state === "committing" && intent.fingerprint === prepared.intent.fingerprint) {
                        if (noWrite) {
                            intent.state = "prepared";
                            delete intent.commitStartedAtMs;
                            intent.terminalMessage = "Commit stopped before any public write was attempted. The verified Owner may retry after fixing the reported issue.";
                        }
                        else {
                            intent.state = "unknown";
                            intent.terminalMessage = "Commit outcome is uncertain; write replay is blocked. Use /noderooms reconcile.";
                        }
                        await this.saveStore(store);
                    }
                });
            }
            catch {
                // Never turn persistence failure into a write retry signal.
            }
            if (noWrite) {
                const known = error instanceof NodeRoomsError ? error : new NodeRoomsError("ACTION_NOT_ATTEMPTED", "The NodeRooms action stopped before public dispatch.");
                throw new NodeRoomsError(known.code, `${known.message} No public write was attempted; the intent remains prepared.`);
            }
            const message = error instanceof Error ? error.message : "The NodeRooms action stopped safely.";
            throw new NodeRoomsError("ACTION_INTENT_COMMIT_UNCERTAIN", `${message} The intent is sealed; use /noderooms reconcile and do not retry the write.`);
        }
    }
    async reconcile(intentId, owner, resolver) {
        const snapshot = await this.withLock(async () => {
            const store = await this.loadStore();
            this.normalizeStore(store);
            const intent = this.requireIntent(store, intentId);
            assertSameOwner(intent, owner);
            if (intent.kind !== "guest_post" && intent.kind !== "guest_comment") {
                throw new NodeRoomsError("ACTION_INTENT_NOT_RECONCILABLE", "Only server-idempotent Guest post and comment intents can be reconciled.");
            }
            if (intent.state === "prepared") {
                throw new NodeRoomsError("ACTION_INTENT_NOT_RECONCILABLE", "The action has not been dispatched. Commit it instead of reconciling it.");
            }
            return cloneIntent(intent);
        });
        const rawReceipt = asRecord(await resolver(Object.freeze(snapshot)), "ACTION_RECEIPT_INVALID");
        const receipt = validateCanonicalReceipt(rawReceipt, {
            actionId: snapshot.id,
            fingerprintSha256: snapshot.fingerprint,
            actionType: snapshot.kind,
        });
        return this.withLock(async () => {
            const store = await this.loadStore();
            this.normalizeStore(store);
            const intent = this.requireIntent(store, intentId);
            assertSameOwner(intent, owner);
            if (intent.fingerprint !== snapshot.fingerprint) {
                throw new NodeRoomsError("ACTION_INTENT_STATE_CONFLICT", "The intent changed during reconciliation.");
            }
            intent.result = receipt;
            intent.resultFormat = RESULT_FORMAT_CANONICAL;
            if (receipt.action_status === "committed") {
                intent.state = "committed";
                intent.terminalMessage = "Canonical committed receipt recovered by read-only reconciliation.";
            }
            else if (receipt.action_status === "failed") {
                intent.state = "failed";
                intent.terminalMessage = "Canonical failed receipt recovered by read-only reconciliation.";
            }
            else {
                intent.state = "unknown";
                intent.terminalMessage = "The canonical action remains processing or unknown. Write replay remains blocked.";
            }
            await this.saveStore(store);
            return {
                ok: intent.state === "committed",
                reconciled: true,
                duplicate_write_prevented: true,
                ...publicSummary(intent),
                result: receipt,
            };
        });
    }
    clearRuntimeCache() {
        // Intents are intentionally persisted as non-secret private state. Runtime
        // credential cleanup is handled separately by NodeRoomsSdk.clearSecrets().
    }
    async withLock(operation) {
        await mkdir(path.dirname(this.stateFilePath), { recursive: true, mode: 0o700 });
        await this.tryChmod(path.dirname(this.stateFilePath), 0o700);
        let handle;
        for (let attempt = 0; attempt < LOCK_RETRY_COUNT; attempt += 1) {
            try {
                handle = await open(this.lockFilePath, "wx", 0o600);
                break;
            }
            catch (error) {
                const code = error.code;
                if (code !== "EEXIST")
                    throw error;
                try {
                    const info = await stat(this.lockFilePath);
                    if (this.now() - info.mtimeMs > LOCK_STALE_MS) {
                        await rm(this.lockFilePath, { force: true });
                        continue;
                    }
                }
                catch (statError) {
                    if (statError.code !== "ENOENT")
                        throw statError;
                }
                await sleep(LOCK_RETRY_DELAY_MS);
            }
        }
        if (!handle) {
            throw new NodeRoomsError("ACTION_INTENT_STORE_BUSY", "The NodeRooms action intent store is busy. No public action was attempted.");
        }
        try {
            await handle.writeFile(`${process.pid}:${this.now()}\n`, { encoding: "utf8" });
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
            if (!info.isFile() || info.isSymbolicLink() || info.size > ACTION_INTENT_MAX_FILE_BYTES) {
                throw new NodeRoomsError("ACTION_INTENT_STORE_INVALID", "The NodeRooms action intent state file is unsafe or too large.");
            }
            const raw = await readFile(this.stateFilePath, "utf8");
            const parsed = JSON.parse(raw);
            const record = asRecord(parsed, "ACTION_INTENT_STORE_INVALID");
            if (record.version !== STORE_VERSION || !Array.isArray(record.intents) || record.intents.length > ACTION_INTENT_MAX_ENTRIES) {
                throw new NodeRoomsError("ACTION_INTENT_STORE_INVALID", "The NodeRooms action intent state schema is invalid.");
            }
            return { version: STORE_VERSION, intents: record.intents.map((intent) => validateIntent(intent)) };
        }
        catch (error) {
            if (error.code === "ENOENT") {
                return { version: STORE_VERSION, intents: [] };
            }
            if (error instanceof NodeRoomsError)
                throw error;
            throw new NodeRoomsError("ACTION_INTENT_STORE_INVALID", "The NodeRooms action intent state could not be read safely.");
        }
    }
    async saveStore(store) {
        const encoded = `${JSON.stringify(store, null, 2)}\n`;
        if (Buffer.byteLength(encoded, "utf8") > ACTION_INTENT_MAX_FILE_BYTES) {
            throw new NodeRoomsError("ACTION_INTENT_STORE_TOO_LARGE", "The NodeRooms action intent state exceeded its safe size limit.");
        }
        const temporary = `${this.stateFilePath}.${process.pid}.${randomUUID()}.tmp`;
        try {
            await writeFile(temporary, encoded, { encoding: "utf8", mode: 0o600, flag: "wx" });
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
    normalizeStore(store) {
        const now = this.now();
        let changed = false;
        if (store.version !== STORE_VERSION) {
            throw new NodeRoomsError("ACTION_INTENT_STORE_INVALID", "The NodeRooms action intent state version is unsupported.");
        }
        for (const intent of store.intents) {
            if (intent.state === "prepared" && now >= intent.expiresAtMs) {
                intent.state = "expired";
                intent.terminalMessage = "Expired before Owner confirmation; no public action was attempted.";
                changed = true;
            }
            if (intent.state === "committing" && intent.commitStartedAtMs !== undefined
                && now >= intent.commitStartedAtMs + ACTION_INTENT_COMMIT_STALE_MS) {
                intent.state = "unknown";
                intent.terminalMessage = "A previously started commit did not finish locally; replay is blocked because the remote outcome may be uncertain.";
                changed = true;
            }
        }
        const retained = store.intents.filter((intent) => {
            if (intent.state === "prepared" || intent.state === "committing")
                return true;
            return now < intent.expiresAtMs + ACTION_INTENT_RETENTION_MS;
        });
        if (retained.length !== store.intents.length) {
            store.intents = retained;
            changed = true;
        }
        return changed;
    }
    requireIntent(store, intentId) {
        assertIntentId(intentId);
        const intent = store.intents.find((candidate) => candidate.id === intentId);
        if (!intent) {
            throw new NodeRoomsError("ACTION_INTENT_NOT_FOUND", "The NodeRooms action intent was not found in private state. It may have been pruned after its retention window.");
        }
        return intent;
    }
    expireIfNeeded(intent) {
        if (intent.state === "prepared" && this.now() >= intent.expiresAtMs) {
            intent.state = "expired";
            intent.terminalMessage = "Expired before Owner confirmation; no public action was attempted.";
        }
        if (intent.state === "expired") {
            throw new NodeRoomsError("ACTION_INTENT_EXPIRED", "The NodeRooms action intent expired. No public action was attempted.");
        }
    }
    enforceCapacity(store) {
        if (store.intents.length < ACTION_INTENT_MAX_ENTRIES)
            return;
        const terminal = store.intents
            .filter((intent) => intent.state !== "prepared" && intent.state !== "committing")
            .sort((left, right) => left.createdAtMs - right.createdAtMs);
        for (const intent of terminal) {
            const index = store.intents.findIndex((candidate) => candidate.id === intent.id);
            if (index >= 0)
                store.intents.splice(index, 1);
            if (store.intents.length < ACTION_INTENT_MAX_ENTRIES)
                return;
        }
        throw new NodeRoomsError("ACTION_INTENT_CAPACITY_REACHED", "Too many NodeRooms action intents are pending. Resolve or let them expire before preparing another action.");
    }
    async tryChmod(target, mode) {
        try {
            await chmod(target, mode);
        }
        catch (error) {
            if (process.platform !== "win32")
                throw error;
        }
    }
}
