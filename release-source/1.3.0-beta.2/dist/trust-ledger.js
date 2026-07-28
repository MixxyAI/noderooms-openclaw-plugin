import { randomBytes } from "node:crypto";
import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import path from "node:path";

const SCHEMA_VERSION = 1;
const DEFAULT_MAX_ENTRIES = 256;
const MAX_LEDGER_BYTES = 1_048_576;
const SAFE_TEXT_PATTERN = /^[A-Za-z0-9._:@/-]{1,160}$/;

function safeText(value, maxLength = 160) {
    if (typeof value !== "string") {
        return undefined;
    }
    const trimmed = value.trim();
    if (!trimmed || trimmed.length > maxLength || !SAFE_TEXT_PATTERN.test(trimmed)) {
        return undefined;
    }
    return trimmed;
}

function safeDuration(value) {
    return Number.isFinite(value) && value >= 0 && value <= 86_400_000
        ? Math.round(value)
        : undefined;
}

function safeParameterKeys(params) {
    if (!params || typeof params !== "object" || Array.isArray(params)) {
        return [];
    }
    return Object.keys(params)
        .filter((key) => SAFE_TEXT_PATTERN.test(key) && key.length <= 80)
        .sort()
        .slice(0, 32);
}

function normalizeEntry(input) {
    const entry = {
        event_id: `nrte_${randomBytes(16).toString("hex")}`,
        occurred_at: new Date().toISOString(),
        phase: input.phase,
        mode: input.mode,
        decision: input.decision,
        tool_name: input.toolName,
        parameter_names: safeParameterKeys(input.params),
    };
    const optional = {
        required_scope: safeText(input.requiredScope, 128),
        risk: safeText(input.risk, 16),
        approval: safeText(input.approval, 32),
        agent_id: safeText(input.agentId, 160),
        channel: safeText(input.channel, 80),
        run_id: safeText(input.runId, 160),
        tool_call_id: safeText(input.toolCallId, 160),
        outcome: safeText(input.outcome, 32),
        error_category: safeText(input.errorCategory, 80),
    };
    for (const [key, value] of Object.entries(optional)) {
        if (value !== undefined) {
            entry[key] = value;
        }
    }
    const duration = safeDuration(input.durationMs);
    if (duration !== undefined) {
        entry.duration_ms = duration;
    }
    return entry;
}

function normalizeStore(value, maxEntries) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return { schema_version: SCHEMA_VERSION, entries: [] };
    }
    const entries = Array.isArray(value.entries)
        ? value.entries.filter((entry) => entry && typeof entry === "object" && !Array.isArray(entry))
        : [];
    return {
        schema_version: SCHEMA_VERSION,
        entries: entries.slice(-maxEntries),
    };
}

export class TrustEventLedger {
    constructor(options) {
        this.filePath = options.filePath;
        this.maxEntries = Number.isSafeInteger(options.maxEntries)
            ? Math.max(1, Math.min(1000, options.maxEntries))
            : DEFAULT_MAX_ENTRIES;
        this.queue = Promise.resolve();
    }

    async append(input) {
        const operation = this.queue.then(() => this.appendInternal(input));
        this.queue = operation.catch(() => undefined);
        return operation;
    }

    async appendInternal(input) {
        const directory = path.dirname(this.filePath);
        await mkdir(directory, { recursive: true, mode: 0o700 });
        let store = { schema_version: SCHEMA_VERSION, entries: [] };
        try {
            const currentStat = await stat(this.filePath);
            if (currentStat.size > MAX_LEDGER_BYTES) {
                store = { schema_version: SCHEMA_VERSION, entries: [] };
            } else {
                store = normalizeStore(JSON.parse(await readFile(this.filePath, "utf8")), this.maxEntries);
            }
        } catch (error) {
            if (error?.code !== "ENOENT") {
                store = { schema_version: SCHEMA_VERSION, entries: [] };
            }
        }
        store.entries.push(normalizeEntry(input));
        store.entries = store.entries.slice(-this.maxEntries);
        store.updated_at = new Date().toISOString();
        const serialized = JSON.stringify(store, null, 2);
        if (Buffer.byteLength(serialized, "utf8") > MAX_LEDGER_BYTES) {
            throw new Error("NodeRooms trust ledger exceeded its bounded size.");
        }
        const temporaryPath = `${this.filePath}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
        await writeFile(temporaryPath, serialized, { encoding: "utf8", mode: 0o600, flag: "wx" });
        await rename(temporaryPath, this.filePath);
    }

    async summary() {
        await this.queue;
        try {
            const currentStat = await stat(this.filePath);
            if (currentStat.size > MAX_LEDGER_BYTES) {
                return { schema_version: SCHEMA_VERSION, entry_count: 0, ledger_reset_required: true };
            }
            const store = normalizeStore(JSON.parse(await readFile(this.filePath, "utf8")), this.maxEntries);
            return {
                schema_version: SCHEMA_VERSION,
                entry_count: store.entries.length,
                updated_at: typeof store.updated_at === "string" ? store.updated_at : null,
                stores_raw_parameters: false,
                stores_raw_results: false,
                stores_secrets: false,
            };
        } catch (error) {
            if (error?.code === "ENOENT") {
                return {
                    schema_version: SCHEMA_VERSION,
                    entry_count: 0,
                    updated_at: null,
                    stores_raw_parameters: false,
                    stores_raw_results: false,
                    stores_secrets: false,
                };
            }
            throw error;
        }
    }

    clearRuntimeCache() {
        this.queue = Promise.resolve();
    }
}
