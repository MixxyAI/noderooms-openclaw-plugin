import { spawn } from "node:child_process";
import {
    createHash,
    createPrivateKey,
    createPublicKey,
    generateKeyPairSync,
    randomBytes,
    sign,
} from "node:crypto";
import {
    chmod,
    lstat,
    mkdir,
    readFile,
    rename,
    unlink,
    writeFile,
} from "node:fs/promises";
import http from "node:http";
import path from "node:path";

import {
    GMAIL_GOG_TOOL_NAMES,
    buildGogInvocation,
    verifyGogExecutableBinding,
} from "./gmail-gog-provider.js";
import {
    NODEROOMS_CONNECTOR_JOB_SCOPES,
    NodeRoomsConnectorAuthorityError,
    validateNodeRoomsConnectorJobAuthority,
} from "./noderooms-connector-authority.js";

export const GMAIL_TRUSTBRIDGE_WORKER_CONTRACT_VERSION =
    "noderooms-trustbridge-worker.v2";
export const GMAIL_TRUSTBRIDGE_JOB_CONTRACT_VERSION =
    "noderooms-trustbridge-job.v2";
export const GMAIL_TRUSTBRIDGE_PAIR_CONTRACT_VERSION =
    "noderooms-gmail-worker-pair.v1";
export const GMAIL_TRUSTBRIDGE_WORKER_VERSION =
    "1.4.0-alpha.6-dev.2";

export const GMAIL_TRUSTBRIDGE_SUPPORTED_JOB_TYPES = Object.freeze([
    "gmail_oauth_start",
    "gmail_oauth_complete",
    "gmail_search",
    "gmail_thread_read",
    "gmail_draft_create",
    "gmail_send_approved_draft",
    "gmail_disconnect",
]);

const DEFAULT_BASE_URL = "https://noderooms.com";
const DEFAULT_PAIRING_PORT = 45_832;
const DEFAULT_POLL_INTERVAL_MS = 3_000;
const MAX_POLL_INTERVAL_MS = 60_000;
const MAX_HTTP_RESPONSE_BYTES = 393_216;
const MAX_LOCAL_PAIRING_BODY_BYTES = 16_384;
const SEARCH_RESULT_MAX_BYTES = 98_304;
const THREAD_RESULT_MAX_BYTES = 262_144;
const DRAFT_RESULT_MAX_BYTES = 32_768;
const SEND_RESULT_MAX_BYTES = 32_768;
const GOG_PROCESS_TIMEOUT_MS = 60_000;
const GOG_OUTPUT_MAX_BYTES = 262_144;
const GMAIL_READONLY_SCOPE =
    "https://www.googleapis.com/auth/gmail.readonly";
const GMAIL_COMPOSE_SCOPE =
    "https://www.googleapis.com/auth/gmail.compose";
const CALLBACK_PATH =
    "/wp-json/agent-guild-os/v1/trustbridge/gmail/oauth/callback";
const PAIRING_CALLBACK_PATH =
    "/wp-json/agent-guild-os/v1/trustbridge/worker/pairing/complete";
const CLAIM_PATH =
    "/wp-json/agent-guild-os/v1/trustbridge/worker/jobs/claim";
const COMPLETE_PATH_PREFIX =
    "/wp-json/agent-guild-os/v1/trustbridge/worker/jobs/";

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const WORKER_ID_PATTERN = /^nrtbw_[a-f0-9]{32}$/;
const PAIRING_ID_PATTERN = /^nrtbp_[a-f0-9]{32}$/;
const JOB_ID_PATTERN = /^nrtbj_[a-f0-9]{32}$/;
const AGENT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const PASSPORT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;
const BINDING_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,159}$/;
const PROVIDER_ID_PATTERN = /^[A-Za-z0-9_-]{1,256}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const SECRET_FIELD_PATTERN = /(?:^|_)(?:access|refresh|id)?_?token$|client_secret|authorization_code|code_verifier|password|cookie|lease_token/i;

export class GmailTrustBridgeWorkerError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = "GmailTrustBridgeWorkerError";
        this.code = code;
        this.details = details;
    }
}

function fail(code, message, details) {
    throw new GmailTrustBridgeWorkerError(code, message, details);
}

function isRecord(value) {
    return Boolean(value)
        && typeof value === "object"
        && !Array.isArray(value);
}

function boundedString(value, label, minimum, maximum) {
    if (typeof value !== "string"
        || value.length < minimum
        || value.length > maximum) {
        fail("GMAIL_TRUSTBRIDGE_INPUT_INVALID", `${label} is invalid.`);
    }
    return value;
}

function normalizeEmail(value) {
    const email = typeof value === "string" ? value.trim().toLowerCase() : "";
    if (email.length < 3
        || email.length > 254
        || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        fail(
            "GMAIL_TRUSTBRIDGE_ACCOUNT_INVALID",
            "The exact Gmail account binding is invalid.",
        );
    }
    return email;
}

function exactPayloadKeys(payload, required, optional = []) {
    if (!isRecord(payload)) {
        fail("GMAIL_TRUSTBRIDGE_JOB_INVALID", "The Gmail job payload is invalid.");
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(payload)) {
        if (!allowed.has(key)) {
            fail(
                "GMAIL_TRUSTBRIDGE_JOB_INVALID",
                `The Gmail job payload contains unsupported field ${key}.`,
            );
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(payload, key)) {
            fail(
                "GMAIL_TRUSTBRIDGE_JOB_INVALID",
                `The Gmail job payload is missing ${key}.`,
            );
        }
    }
}

function exactProviderId(value, label) {
    const candidate = boundedString(value, label, 1, 256);
    if (!PROVIDER_ID_PATTERN.test(candidate)) {
        fail("GMAIL_TRUSTBRIDGE_JOB_INVALID", `${label} is invalid.`);
    }
    return candidate;
}

function sha256(value) {
    return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function base64url(value) {
    return Buffer.from(value).toString("base64url");
}

function decodeBase64url(value, label, minimum = 1, maximum = 16_384) {
    boundedString(value, label, 1, Math.ceil(maximum * 4 / 3) + 8);
    if (!BASE64URL_PATTERN.test(value)) {
        fail("GMAIL_TRUSTBRIDGE_PAIRING_INVALID", `${label} is invalid.`);
    }
    const decoded = Buffer.from(value, "base64url");
    if (decoded.length < minimum || decoded.length > maximum) {
        fail("GMAIL_TRUSTBRIDGE_PAIRING_INVALID", `${label} is invalid.`);
    }
    return decoded;
}

function exactOrigin(value, label) {
    let url;
    try {
        url = new URL(value);
    }
    catch {
        fail("GMAIL_TRUSTBRIDGE_CONFIG_INVALID", `${label} is invalid.`);
    }
    if (url.protocol !== "https:"
        || url.username
        || url.password
        || url.pathname !== "/"
        || url.search
        || url.hash) {
        fail("GMAIL_TRUSTBRIDGE_CONFIG_INVALID", `${label} is invalid.`);
    }
    return url.origin;
}

function exactAbsolutePath(value, label) {
    const candidate = boundedString(value, label, 1, 1_024);
    if (!path.isAbsolute(candidate)) {
        fail("GMAIL_TRUSTBRIDGE_CONFIG_INVALID", `${label} must be absolute.`);
    }
    return path.resolve(candidate);
}

function exactInteger(value, fallback, minimum, maximum, label) {
    const candidate = value === undefined ? fallback : value;
    if (!Number.isSafeInteger(candidate)
        || candidate < minimum
        || candidate > maximum) {
        fail("GMAIL_TRUSTBRIDGE_CONFIG_INVALID", `${label} is invalid.`);
    }
    return candidate;
}

export function normalizeGmailTrustBridgeWorkerConfig(pluginConfig) {
    const raw = isRecord(pluginConfig?.gmailTrustBridge)
        ? pluginConfig.gmailTrustBridge
        : {};
    const mode = raw.mode === "worker" ? "worker" : "off";
    const baseUrl = exactOrigin(raw.baseUrl ?? DEFAULT_BASE_URL, "baseUrl");
    const openclawAgentId = boundedString(
        raw.openclawAgentId ?? "main",
        "openclawAgentId",
        1,
        64,
    );
    if (!AGENT_ID_PATTERN.test(openclawAgentId)) {
        fail(
            "GMAIL_TRUSTBRIDGE_CONFIG_INVALID",
            "openclawAgentId is invalid.",
        );
    }
    const config = {
        mode,
        baseUrl,
        openclawAgentId,
        localPairingPort: exactInteger(
            raw.localPairingPort,
            DEFAULT_PAIRING_PORT,
            1_024,
            65_535,
            "localPairingPort",
        ),
        pollIntervalMs: exactInteger(
            raw.pollIntervalMs,
            DEFAULT_POLL_INTERVAL_MS,
            1_000,
            MAX_POLL_INTERVAL_MS,
            "pollIntervalMs",
        ),
        gog: null,
    };
    if (mode === "off") {
        return Object.freeze(config);
    }
    if (!isRecord(raw.gog)) {
        fail(
            "GMAIL_TRUSTBRIDGE_CONFIG_INVALID",
            "The exact gog worker binding is required.",
        );
    }
    const executableSha256 = boundedString(
        raw.gog.executableSha256,
        "gog.executableSha256",
        71,
        71,
    );
    if (!SHA256_PATTERN.test(executableSha256)) {
        fail(
            "GMAIL_TRUSTBRIDGE_CONFIG_INVALID",
            "gog.executableSha256 is invalid.",
        );
    }
    config.gog = Object.freeze({
        account: normalizeEmail(raw.gog.account),
        homePath: exactAbsolutePath(raw.gog.homePath, "gog.homePath"),
        client: boundedString(raw.gog.client, "gog.client", 1, 64),
        executablePath: exactAbsolutePath(
            raw.gog.executablePath,
            "gog.executablePath",
        ),
        executableSha256,
    });
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(config.gog.client)) {
        fail("GMAIL_TRUSTBRIDGE_CONFIG_INVALID", "gog.client is invalid.");
    }
    return Object.freeze(config);
}

function safeGogEnvironment() {
    const names = [
        "SystemRoot",
        "WINDIR",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LC_ALL",
        "GOG_KEYRING_BACKEND",
        "GOG_KEYRING_PASSWORD",
        "GOG_KEYRING_OPEN_TIMEOUT",
    ];
    return Object.fromEntries(
        names
            .filter((name) => typeof process.env[name] === "string")
            .map((name) => [name, process.env[name]]),
    );
}

function appendBounded(chunks, chunk, state, child) {
    const buffer = Buffer.from(chunk);
    state.bytes += buffer.length;
    if (state.bytes > GOG_OUTPUT_MAX_BYTES) {
        state.exceeded = true;
        child.kill();
        return;
    }
    chunks.push(buffer);
}

export function spawnGogWorkerOnce(executablePath, invocation) {
    return new Promise((resolve, reject) => {
        const child = spawn(executablePath, invocation.args, {
            env: safeGogEnvironment(),
            shell: false,
            windowsHide: true,
            stdio: ["pipe", "pipe", "pipe"],
        });
        const stdout = [];
        const stderr = [];
        const stdoutState = { bytes: 0, exceeded: false };
        const stderrState = { bytes: 0, exceeded: false };
        let settled = false;
        let timedOut = false;
        const timer = setTimeout(() => {
            if (!settled) {
                timedOut = true;
                child.kill();
            }
        }, GOG_PROCESS_TIMEOUT_MS);
        child.stdout.on("data", (chunk) =>
            appendBounded(stdout, chunk, stdoutState, child));
        child.stderr.on("data", (chunk) =>
            appendBounded(stderr, chunk, stderrState, child));
        child.once("error", (error) => {
            settled = true;
            clearTimeout(timer);
            reject(new GmailTrustBridgeWorkerError(
                "GMAIL_GOG_PROCESS_START_FAILED",
                "The bound Gmail provider could not start.",
                { cause_code: error?.code ?? null },
            ));
        });
        child.once("close", (code, signalName) => {
            if (settled) {
                return;
            }
            settled = true;
            clearTimeout(timer);
            const stdoutBytes = Buffer.concat(stdout);
            const stderrBytes = Buffer.concat(stderr);
            if (timedOut) {
                reject(new GmailTrustBridgeWorkerError(
                    "GMAIL_GOG_PROCESS_TIMEOUT",
                    "The Gmail provider exceeded its fixed deadline.",
                ));
                return;
            }
            if (stdoutState.exceeded || stderrState.exceeded) {
                reject(new GmailTrustBridgeWorkerError(
                    "GMAIL_GOG_OUTPUT_LIMIT",
                    "The Gmail provider output exceeded the fixed limit.",
                ));
                return;
            }
            if (code !== 0) {
                reject(new GmailTrustBridgeWorkerError(
                    "GMAIL_GOG_PROVIDER_FAILED",
                    "The Gmail provider returned a non-success result.",
                    {
                        exit_code: code,
                        signal: signalName ?? null,
                        stderr_sha256: sha256(stderrBytes),
                    },
                ));
                return;
            }
            try {
                const text = stdoutBytes.toString("utf8").trim();
                resolve(text ? JSON.parse(text) : {});
            }
            catch {
                reject(new GmailTrustBridgeWorkerError(
                    "GMAIL_GOG_OUTPUT_INVALID",
                    "The Gmail provider returned invalid JSON.",
                ));
            }
        });
        if (invocation.stdin === null) {
            child.stdin.end();
        }
        else {
            child.stdin.end(invocation.stdin, "utf8");
        }
    });
}

function authRootArgs(config, command) {
    return [
        "--home", config.gog.homePath,
        "--account", config.gog.account,
        "--client", config.gog.client,
        "--enable-commands-exact", command,
        "--no-input",
        "--json",
        "--color=never",
    ];
}

function requireExactAccount(payload, config) {
    const account = normalizeEmail(payload.account_email);
    if (account !== config.gog.account) {
        fail(
            "GMAIL_TRUSTBRIDGE_ACCOUNT_DRIFT",
            "The claimed Gmail job belongs to another exact account.",
        );
    }
    return account;
}

function requireExactCallback(payload, config) {
    const expected = `${config.baseUrl}${CALLBACK_PATH}`;
    if (payload.callback_uri !== expected) {
        fail(
            "GMAIL_TRUSTBRIDGE_CALLBACK_DRIFT",
            "The Gmail OAuth callback binding changed.",
        );
    }
    const scopes = Array.isArray(payload.oauth_scopes)
        ? [...payload.oauth_scopes].toSorted()
        : [];
    const expectedScopes = [
        GMAIL_COMPOSE_SCOPE,
        GMAIL_READONLY_SCOPE,
    ].toSorted();
    if (scopes.length !== expectedScopes.length
        || scopes.some((scope, index) => scope !== expectedScopes[index])) {
        fail(
            "GMAIL_TRUSTBRIDGE_SCOPE_DRIFT",
            "Only the exact Gmail read plus compose OAuth scopes are allowed.",
        );
    }
    return expected;
}

export function gmailTrustBridgeJobTargetFingerprint(
    jobType,
    payload,
    config,
) {
    const account = requireExactAccount(payload, config);
    if ([
        "gmail_oauth_start",
        "gmail_oauth_complete",
        "gmail_disconnect",
    ].includes(jobType)) {
        return sha256(`gmail\naccount\n${account}`);
    }
    if (jobType === "gmail_search") {
        return sha256(
            `gmail\nsearch\n${account}\n${boundedString(
                payload.query,
                "query",
                1,
                500,
            )}`,
        );
    }
    if (jobType === "gmail_thread_read") {
        return sha256(
            `gmail\nthread\n${account}\n${exactProviderId(
                payload.thread_id,
                "thread_id",
            )}`,
        );
    }
    if (jobType === "gmail_draft_create") {
        return sha256(
            `gmail\nrecipient\n${account}\n${normalizeEmail(payload.to)}`,
        );
    }
    if (jobType === "gmail_send_approved_draft") {
        return sha256(
            `gmail\ndraft\n${account}\n${exactProviderId(
                payload.draft_id,
                "draft_id",
            )}`,
        );
    }
    fail(
        "GMAIL_TRUSTBRIDGE_JOB_UNSUPPORTED",
        "The claimed Gmail job type is not supported.",
    );
}

export function buildGmailTrustBridgeGogInvocation(jobType, payload, config) {
    if (!isRecord(payload) || !config?.gog) {
        fail("GMAIL_TRUSTBRIDGE_JOB_INVALID", "The Gmail job is invalid.");
    }
    const account = requireExactAccount(payload, config);
    if (jobType === "gmail_oauth_start") {
        exactPayloadKeys(payload, [
            "account_email",
            "callback_uri",
            "oauth_scopes",
        ]);
        const callback = requireExactCallback(payload, config);
        return Object.freeze({
            args: [
                ...authRootArgs(config, "auth.add"),
                "--gmail-no-send",
                "auth", "add", account,
                "--services", "gmail",
                "--gmail-scope", "readonly",
                "--extra-scopes", GMAIL_COMPOSE_SCOPE,
                "--remote",
                "--step", "1",
                "--redirect-uri", callback,
                "--force-consent",
            ],
            stdin: null,
            readOnly: false,
        });
    }
    if (jobType === "gmail_oauth_complete") {
        exactPayloadKeys(payload, [
            "account_email",
            "callback_uri",
            "callback_url",
            "oauth_scopes",
        ]);
        const callback = requireExactCallback(payload, config);
        const callbackUrl = boundedString(
            payload.callback_url,
            "callback_url",
            callback.length + 8,
            8_192,
        );
        let parsed;
        try {
            parsed = new URL(callbackUrl);
        }
        catch {
            fail(
                "GMAIL_TRUSTBRIDGE_CALLBACK_INVALID",
                "The one-time Gmail callback is invalid.",
            );
        }
        if (`${parsed.origin}${parsed.pathname}` !== callback
            || !parsed.searchParams.has("code")
            || !parsed.searchParams.has("state")
            || parsed.hash
            || parsed.username
            || parsed.password) {
            fail(
                "GMAIL_TRUSTBRIDGE_CALLBACK_INVALID",
                "The one-time Gmail callback is invalid.",
            );
        }
        return Object.freeze({
            args: [
                ...authRootArgs(config, "auth.add"),
                "--gmail-no-send",
                "auth", "add", account,
                "--services", "gmail",
                "--gmail-scope", "readonly",
                "--extra-scopes", GMAIL_COMPOSE_SCOPE,
                "--remote",
                "--step", "2",
                "--redirect-uri", callback,
                "--auth-url", callbackUrl,
            ],
            stdin: null,
            readOnly: false,
        });
    }
    if (jobType === "gmail_search") {
        exactPayloadKeys(payload, ["account_email", "query"], [
            "max_results",
        ]);
        return buildGogInvocation(
            GMAIL_GOG_TOOL_NAMES.search,
            {
                query: boundedString(payload.query, "query", 1, 500),
                max_results: Number.isSafeInteger(payload.max_results)
                    ? payload.max_results
                    : 10,
            },
            config,
        );
    }
    if (jobType === "gmail_thread_read") {
        exactPayloadKeys(payload, ["account_email", "thread_id"]);
        return buildGogInvocation(
            GMAIL_GOG_TOOL_NAMES.readThread,
            {
                thread_id: boundedString(
                    payload.thread_id,
                    "thread_id",
                    1,
                    256,
                ),
            },
            config,
        );
    }
    if (jobType === "gmail_draft_create") {
        exactPayloadKeys(
            payload,
            ["account_email", "to", "subject", "body"],
            ["reply_message_id"],
        );
        const subject = boundedString(payload.subject, "subject", 1, 998);
        const body = boundedString(payload.body, "body", 1, 50_000);
        if (/[\r\n\0]/.test(subject) || body.includes("\0")) {
            fail(
                "GMAIL_TRUSTBRIDGE_JOB_INVALID",
                "The Gmail draft content is invalid.",
            );
        }
        const args = [
            ...authRootArgs(config, "gmail.drafts.create"),
            "--gmail-no-send",
            "gmail", "drafts", "create",
            "--to", normalizeEmail(payload.to),
            "--subject", subject,
            "--body-file", "-",
        ];
        if (payload.reply_message_id !== undefined) {
            args.push(
                "--reply-to-message-id",
                exactProviderId(
                    payload.reply_message_id,
                    "reply_message_id",
                ),
            );
        }
        return Object.freeze({
            args,
            stdin: body,
            readOnly: false,
            writeKind: "draft",
            providerAttemptMax: 1,
            automaticRetryAllowed: false,
        });
    }
    if (jobType === "gmail_send_approved_draft") {
        exactPayloadKeys(payload, ["account_email", "draft_id"]);
        return Object.freeze({
            args: [
                ...authRootArgs(config, "gmail.drafts.send"),
                "gmail", "drafts", "send",
                exactProviderId(payload.draft_id, "draft_id"),
            ],
            stdin: null,
            readOnly: false,
            writeKind: "send",
            providerAttemptMax: 1,
            automaticRetryAllowed: false,
        });
    }
    if (jobType === "gmail_disconnect") {
        exactPayloadKeys(payload, ["account_email"]);
        return Object.freeze({
            args: [
                ...authRootArgs(config, "auth.remove"),
                "--gmail-no-send",
                "auth", "remove", account,
            ],
            stdin: null,
            readOnly: false,
        });
    }
    fail(
        "GMAIL_TRUSTBRIDGE_JOB_UNSUPPORTED",
        "The claimed Gmail job type is not supported.",
    );
}

function findAuthUrl(value, depth = 0) {
    if (depth > 12) {
        return "";
    }
    if (typeof value === "string"
        && value.startsWith("https://accounts.google.com/")) {
        return value;
    }
    if (Array.isArray(value)) {
        for (const entry of value) {
            const found = findAuthUrl(entry, depth + 1);
            if (found) {
                return found;
            }
        }
    }
    else if (isRecord(value)) {
        for (const entry of Object.values(value)) {
            const found = findAuthUrl(entry, depth + 1);
            if (found) {
                return found;
            }
        }
    }
    return "";
}

function findProviderId(value, keys, depth = 0) {
    if (depth > 12) {
        return "";
    }
    if (isRecord(value)) {
        for (const key of keys) {
            const candidate = value[key];
            if (typeof candidate === "string"
                && PROVIDER_ID_PATTERN.test(candidate)) {
                return candidate;
            }
        }
        for (const entry of Object.values(value)) {
            const found = findProviderId(entry, keys, depth + 1);
            if (found) {
                return found;
            }
        }
    }
    else if (Array.isArray(value)) {
        for (const entry of value) {
            const found = findProviderId(entry, keys, depth + 1);
            if (found) {
                return found;
            }
        }
    }
    return "";
}

function assertPublicResult(value, maximumBytes) {
    const state = { nodes: 0 };
    function visit(entry, depth) {
        state.nodes += 1;
        if (depth > 24 || state.nodes > 10_000) {
            fail(
                "GMAIL_TRUSTBRIDGE_RESULT_COMPLEXITY",
                "The Gmail result exceeded the fixed complexity bound.",
            );
        }
        if (typeof entry === "string" && entry.length > 100_000) {
            fail(
                "GMAIL_TRUSTBRIDGE_RESULT_STRING_LIMIT",
                "The Gmail result contained an oversized field.",
            );
        }
        if (Array.isArray(entry)) {
            entry.forEach((child) => visit(child, depth + 1));
        }
        else if (isRecord(entry)) {
            for (const [key, child] of Object.entries(entry)) {
                if (SECRET_FIELD_PATTERN.test(key)) {
                    fail(
                        "GMAIL_TRUSTBRIDGE_RESULT_SECRET_REJECTED",
                        "The Gmail result contained a prohibited secret field.",
                    );
                }
                visit(child, depth + 1);
            }
        }
    }
    visit(value, 0);
    const json = JSON.stringify(value);
    if (Buffer.byteLength(json, "utf8") > maximumBytes) {
        fail(
            "GMAIL_TRUSTBRIDGE_RESULT_TOO_LARGE",
            "The Gmail result exceeded its fixed byte limit.",
        );
    }
    return value;
}

export function normalizeGmailTrustBridgeJobResult(
    jobType,
    payload,
    providerResult,
    config,
) {
    const account = requireExactAccount(payload, config);
    const accountFingerprint = sha256(account);
    if (jobType === "gmail_oauth_start") {
        const callback = requireExactCallback(payload, config);
        const authUrl = findAuthUrl(providerResult);
        let parsed;
        try {
            parsed = new URL(authUrl);
        }
        catch {
            fail(
                "GMAIL_TRUSTBRIDGE_AUTH_URL_INVALID",
                "The provider did not return a valid Google consent URL.",
            );
        }
        if (parsed.protocol !== "https:"
            || parsed.hostname !== "accounts.google.com"
            || parsed.searchParams.get("redirect_uri") !== callback
            || parsed.searchParams.get("code_challenge_method") !== "S256"
            || !/^[A-Za-z0-9._~-]{43,128}$/.test(
                parsed.searchParams.get("code_challenge") ?? "",
            )
            || (parsed.searchParams.get("state") ?? "").length < 16) {
            fail(
                "GMAIL_TRUSTBRIDGE_AUTH_URL_INVALID",
                "The provider consent URL failed its callback and PKCE checks.",
            );
        }
        return {
            status: "awaiting_owner_consent",
            account_email: account,
            auth_url: authUrl,
            auth_url_sha256: sha256(authUrl),
            provider_token_exposed: false,
            write_enabled: false,
        };
    }
    if (jobType === "gmail_oauth_complete") {
        return {
            status: "connected_read_compose",
            account_email: account,
            account_fingerprint_sha256: accountFingerprint,
            token_stored_in_agent_keyring: true,
            provider_token_exposed: false,
            draft_enabled: true,
            owner_approved_send_enabled: true,
            mailbox_delete_enabled: false,
        };
    }
    if (jobType === "gmail_search") {
        return {
            status: "completed",
            operation: "gmail_search",
            account_fingerprint_sha256: accountFingerprint,
            result: assertPublicResult(
                providerResult,
                SEARCH_RESULT_MAX_BYTES,
            ),
            remote_content_untrusted: true,
            remote_content_executed: false,
            write_enabled: false,
        };
    }
    if (jobType === "gmail_thread_read") {
        return {
            status: "completed",
            operation: "gmail_thread_read",
            account_fingerprint_sha256: accountFingerprint,
            result: assertPublicResult(
                providerResult,
                THREAD_RESULT_MAX_BYTES,
            ),
            remote_content_untrusted: true,
            remote_content_executed: false,
            attachments_downloaded: false,
            write_enabled: false,
        };
    }
    if (jobType === "gmail_draft_create") {
        const safeResult = assertPublicResult(
            providerResult,
            DRAFT_RESULT_MAX_BYTES,
        );
        const draftId = findProviderId(
            safeResult,
            ["draft_id", "draftId", "id"],
        );
        if (!draftId) {
            fail(
                "GMAIL_TRUSTBRIDGE_DRAFT_RESULT_INVALID",
                "The Gmail provider did not return an exact draft id.",
            );
        }
        return {
            status: "draft_created",
            operation: "gmail_draft_create",
            account_fingerprint_sha256: accountFingerprint,
            draft_id: draftId,
            draft_id_sha256: sha256(draftId),
            provider_response_exposed: false,
            sent: false,
            mailbox_delete_enabled: false,
        };
    }
    if (jobType === "gmail_send_approved_draft") {
        const safeResult = assertPublicResult(
            providerResult,
            SEND_RESULT_MAX_BYTES,
        );
        const messageId = findProviderId(
            safeResult,
            ["message_id", "messageId", "id"],
        );
        if (!messageId) {
            fail(
                "GMAIL_TRUSTBRIDGE_SEND_RESULT_INVALID",
                "The Gmail provider did not return an exact sent message id.",
            );
        }
        const draftId = exactProviderId(payload.draft_id, "draft_id");
        return {
            status: "sent",
            operation: "gmail_send_approved_draft",
            account_fingerprint_sha256: accountFingerprint,
            draft_id_sha256: sha256(draftId),
            message_id: messageId,
            message_id_sha256: sha256(messageId),
            provider_response_exposed: false,
            owner_approval_consumed: true,
            provider_attempt_count: 1,
            automatic_retry_attempted: false,
            exactly_once_effect_claimed: false,
            mailbox_delete_enabled: false,
        };
    }
    if (jobType === "gmail_disconnect") {
        return {
            status: "disconnected",
            account_fingerprint_sha256: accountFingerprint,
            token_removed_from_agent_keyring: true,
            provider_token_exposed: false,
            write_enabled: false,
        };
    }
    fail(
        "GMAIL_TRUSTBRIDGE_JOB_UNSUPPORTED",
        "The claimed Gmail job type is not supported.",
    );
}

export function gmailTrustBridgePairCanonical(input) {
    const supported = [...input.supported_job_types].toSorted();
    return [
        GMAIL_TRUSTBRIDGE_PAIR_CONTRACT_VERSION,
        input.challenge_id,
        input.challenge,
        input.worker_id,
        input.public_key_b64url,
        input.openclaw_agent_id,
        input.worker_version,
        supported.join(","),
        String(input.issued_at),
    ].join("\n");
}

export function gmailTrustBridgeRequestCanonical(
    method,
    requestPath,
    timestamp,
    nonce,
    body,
) {
    return [
        method.toUpperCase(),
        requestPath,
        String(timestamp),
        nonce,
        createHash("sha256").update(body).digest("hex"),
    ].join("\n");
}

function validatePairingPayload(encoded, config) {
    const decoded = decodeBase64url(
        encoded,
        "pairing_payload_b64url",
        2,
        12_288,
    );
    let payload;
    try {
        payload = JSON.parse(decoded.toString("utf8"));
    }
    catch {
        fail(
            "GMAIL_TRUSTBRIDGE_PAIRING_INVALID",
            "The NodeRooms pairing payload is invalid.",
        );
    }
    if (!isRecord(payload)
        || payload.contract_version
            !== GMAIL_TRUSTBRIDGE_PAIR_CONTRACT_VERSION
        || !PAIRING_ID_PATTERN.test(payload.challenge_id ?? "")
        || !BASE64URL_PATTERN.test(payload.challenge ?? "")
        || decodeBase64url(payload.challenge, "challenge", 32, 32).length !== 32
        || payload.callback_url !== `${config.baseUrl}${PAIRING_CALLBACK_PATH}`
        || payload.site_origin !== config.baseUrl
        || !AGENT_ID_PATTERN.test(payload.agent_slug ?? "")
        || !PASSPORT_ID_PATTERN.test(payload.passport_public_id ?? "")) {
        fail(
            "GMAIL_TRUSTBRIDGE_PAIRING_INVALID",
            "The NodeRooms pairing payload binding is invalid.",
        );
    }
    const expiresAt = Date.parse(payload.expires_at ?? "");
    if (!Number.isFinite(expiresAt)
        || expiresAt <= Date.now()
        || expiresAt > Date.now() + 15 * 60_000) {
        fail(
            "GMAIL_TRUSTBRIDGE_PAIRING_EXPIRED",
            "The NodeRooms pairing payload expired or has an invalid lifetime.",
        );
    }
    let returnTo;
    try {
        returnTo = new URL(payload.return_to);
    }
    catch {
        fail(
            "GMAIL_TRUSTBRIDGE_PAIRING_INVALID",
            "The NodeRooms pairing return URL is invalid.",
        );
    }
    if (returnTo.origin !== config.baseUrl
        || returnTo.username
        || returnTo.password) {
        fail(
            "GMAIL_TRUSTBRIDGE_PAIRING_INVALID",
            "The NodeRooms pairing return URL is invalid.",
        );
    }
    return Object.freeze({ ...payload, return_to: returnTo.href });
}

function privateRecordPaths(agentDir) {
    const directory = path.join(
        path.resolve(agentDir),
        "noderooms",
        "gmail-trustbridge-worker-v2",
    );
    return Object.freeze({
        directory,
        record: path.join(directory, "worker-private.json"),
    });
}

async function writePrivateRecord(paths, record) {
    await mkdir(paths.directory, { recursive: true, mode: 0o700 });
    await chmod(paths.directory, 0o700).catch(() => {});
    const temporary = path.join(
        paths.directory,
        `.worker-private-${process.pid}-${randomBytes(8).toString("hex")}.tmp`,
    );
    const bytes = `${JSON.stringify(record, null, 2)}\n`;
    await writeFile(temporary, bytes, { encoding: "utf8", mode: 0o600, flag: "wx" });
    try {
        await chmod(temporary, 0o600).catch(() => {});
        await rename(temporary, paths.record);
    }
    catch (error) {
        await unlink(temporary).catch(() => {});
        throw error;
    }
}

function validatePrivateRecord(record, config) {
    if (!isRecord(record)
        || record.contract_version !== GMAIL_TRUSTBRIDGE_PAIR_CONTRACT_VERSION
        || !WORKER_ID_PATTERN.test(record.worker_id ?? "")
        || !BASE64URL_PATTERN.test(record.public_key_b64url ?? "")
        || decodeBase64url(
            record.public_key_b64url,
            "public_key_b64url",
            32,
            32,
        ).length !== 32
        || record.openclaw_agent_id !== config.openclawAgentId
        || record.site_origin !== config.baseUrl
        || !["PAIRING_PENDING", "ACTIVE"].includes(record.status)
        || typeof record.private_key_pkcs8_pem !== "string") {
        fail(
            "GMAIL_TRUSTBRIDGE_PRIVATE_BINDING_INVALID",
            "The Agent-isolated Gmail worker binding is invalid.",
        );
    }
    if (record.status === "ACTIVE"
        && (typeof record.worker_binding_id !== "string"
            || !record.worker_binding_id.startsWith("nrtbwb_")
            || !BINDING_ID_PATTERN.test(record.worker_binding_id)
            || !AGENT_ID_PATTERN.test(record.agent_slug ?? "")
            || !BINDING_ID_PATTERN.test(record.owner_binding_id ?? "")
            || record.owner_binding_status !== "verified"
            || !PASSPORT_ID_PATTERN.test(record.passport_public_id ?? "")
            || record.passport_status !== "active")) {
        fail(
            "GMAIL_TRUSTBRIDGE_PRIVATE_BINDING_INVALID",
            "The active worker lacks an exact Owner, Agent, and Passport binding.",
        );
    }
    let privateKey;
    try {
        privateKey = createPrivateKey(record.private_key_pkcs8_pem);
        const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
        if (publicJwk.kty !== "OKP"
            || publicJwk.crv !== "Ed25519"
            || publicJwk.x !== record.public_key_b64url) {
            throw new Error("public key mismatch");
        }
    }
    catch {
        fail(
            "GMAIL_TRUSTBRIDGE_PRIVATE_BINDING_INVALID",
            "The Agent-isolated Gmail worker key is invalid.",
        );
    }
    return { record, privateKey };
}

async function readPrivateRecord(paths, config) {
    let stat;
    try {
        stat = await lstat(paths.record);
    }
    catch (error) {
        if (error?.code === "ENOENT") {
            return null;
        }
        throw error;
    }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 64_000) {
        fail(
            "GMAIL_TRUSTBRIDGE_PRIVATE_BINDING_INVALID",
            "The Agent-isolated Gmail worker record is invalid.",
        );
    }
    if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
        fail(
            "GMAIL_TRUSTBRIDGE_PRIVATE_BINDING_PERMISSIONS",
            "The Gmail worker private record permissions are too broad.",
        );
    }
    let record;
    try {
        record = JSON.parse(await readFile(paths.record, "utf8"));
    }
    catch {
        fail(
            "GMAIL_TRUSTBRIDGE_PRIVATE_BINDING_INVALID",
            "The Agent-isolated Gmail worker record is invalid.",
        );
    }
    return validatePrivateRecord(record, config);
}

async function readBoundedJsonResponse(response) {
    const declared = Number(response.headers.get("content-length") ?? "0");
    if (declared > MAX_HTTP_RESPONSE_BYTES) {
        fail(
            "GMAIL_TRUSTBRIDGE_HTTP_RESPONSE_TOO_LARGE",
            "The NodeRooms response exceeded its fixed byte limit.",
        );
    }
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > MAX_HTTP_RESPONSE_BYTES) {
        fail(
            "GMAIL_TRUSTBRIDGE_HTTP_RESPONSE_TOO_LARGE",
            "The NodeRooms response exceeded its fixed byte limit.",
        );
    }
    try {
        return bytes.length ? JSON.parse(bytes.toString("utf8")) : {};
    }
    catch {
        fail(
            "GMAIL_TRUSTBRIDGE_HTTP_RESPONSE_INVALID",
            "NodeRooms returned invalid JSON.",
        );
    }
}

async function fetchJson(fetchImpl, url, options) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20_000);
    try {
        const response = await fetchImpl(url, {
            ...options,
            redirect: "error",
            cache: "no-store",
            signal: controller.signal,
        });
        const body = await readBoundedJsonResponse(response);
        if (!response.ok || body?.ok !== true) {
            fail(
                typeof body?.reason === "string"
                    ? body.reason
                    : "GMAIL_TRUSTBRIDGE_HTTP_REJECTED",
                "NodeRooms rejected the TrustBridge request.",
                { http_status: response.status },
            );
        }
        return body;
    }
    finally {
        clearTimeout(timer);
    }
}

function pairingHtml(csrfToken, port) {
    const nonce = base64url(randomBytes(18));
    const safeToken = JSON.stringify(csrfToken);
    const script = `
(function () {
  "use strict";
  var status = document.getElementById("status");
  var payload = window.location.hash.slice(1);
  window.history.replaceState(null, "", "/pair");
  if (!payload) {
    status.textContent = "The NodeRooms pairing payload is missing.";
    return;
  }
  fetch("/pair/complete", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-NodeRooms-Local-CSRF": ${safeToken} },
    body: JSON.stringify({ pairing_payload_b64url: payload })
  }).then(function (response) {
    return response.json().then(function (body) {
      if (!response.ok || body.ok !== true) throw new Error(body.reason || "PAIRING_FAILED");
      status.textContent = "Secure NodeRooms background connection ready. Returning to NodeRooms…";
      window.setTimeout(function () { window.location.replace(body.return_to); }, 350);
    });
  }).catch(function (error) {
    status.textContent = "Pairing stopped safely: " + error.message;
  });
}());`;
    return {
        nonce,
        body: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NodeRooms secure connection</title></head><body><main><h1>NodeRooms secure background connection</h1><p id="status">Verifying the one-use Agent–Passport binding…</p></main><script nonce="${nonce}">${script}</script></body></html>`,
        origin: `http://127.0.0.1:${port}`,
    };
}

function localJson(response, status, body, headers = {}) {
    const bytes = Buffer.from(JSON.stringify(body));
    response.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": String(bytes.length),
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        ...headers,
    });
    response.end(bytes);
}

export class GmailTrustBridgeWorkerService {
    constructor(options) {
        if (!options?.config
            || typeof options.agentDir !== "string"
            || !path.isAbsolute(options.agentDir)) {
            fail(
                "GMAIL_TRUSTBRIDGE_SERVICE_INVALID",
                "The Gmail TrustBridge worker service is invalid.",
            );
        }
        this.config = options.config;
        this.agentDir = path.resolve(options.agentDir);
        this.paths = privateRecordPaths(this.agentDir);
        this.fetch = options.fetch ?? globalThis.fetch;
        this.verifyExecutable = options.verifyExecutable
            ?? verifyGogExecutableBinding;
        this.runCommand = options.runCommand ?? spawnGogWorkerOnce;
        this.logger = options.logger ?? {
            info() {},
            warn() {},
            error() {},
        };
        this.server = null;
        this.privateBinding = null;
        this.pollTimer = null;
        this.inFlight = false;
        this.stopping = false;
        this.failureCount = 0;
        this.csrfSessions = new Map();
        this.claimedJobIds = new Set();
    }

    async start() {
        if (this.config.mode !== "worker") {
            return;
        }
        if (typeof this.fetch !== "function") {
            fail(
                "GMAIL_TRUSTBRIDGE_FETCH_UNAVAILABLE",
                "The NodeRooms HTTPS client is unavailable.",
            );
        }
        await this.verifyExecutable(this.config);
        this.privateBinding = await readPrivateRecord(this.paths, this.config);
        await this.startPairingServer();
        if (this.privateBinding?.record?.status === "ACTIVE") {
            this.schedulePoll(0);
        }
        this.logger.info(
            "NodeRooms Gmail TrustBridge infrastructure worker started.",
        );
    }

    async stop() {
        this.stopping = true;
        if (this.pollTimer) {
            clearTimeout(this.pollTimer);
            this.pollTimer = null;
        }
        const server = this.server;
        this.server = null;
        if (server) {
            await new Promise((resolve) => server.close(resolve));
        }
        this.csrfSessions.clear();
        this.claimedJobIds.clear();
        this.privateBinding = null;
    }

    async startPairingServer() {
        if (this.server) {
            return;
        }
        this.server = http.createServer((request, response) => {
            this.handleLocalRequest(request, response).catch(() => {
                if (!response.headersSent) {
                    localJson(response, 500, {
                        ok: false,
                        reason: "PAIRING_STOPPED_SAFELY",
                    });
                }
                else {
                    response.destroy();
                }
            });
        });
        this.server.on("clientError", (_error, socket) => socket.destroy());
        await new Promise((resolve, reject) => {
            this.server.once("error", reject);
            this.server.listen(
                this.config.localPairingPort,
                "127.0.0.1",
                () => {
                    this.server.off("error", reject);
                    resolve();
                },
            );
        });
    }

    async handleLocalRequest(request, response) {
        const port = this.config.localPairingPort;
        if (request.headers.host !== `127.0.0.1:${port}`) {
            localJson(response, 421, { ok: false, reason: "LOCAL_HOST_INVALID" });
            return;
        }
        if (request.method === "GET" && request.url === "/pair") {
            const csrf = base64url(randomBytes(32));
            this.csrfSessions.set(csrf, Date.now() + 5 * 60_000);
            const page = pairingHtml(csrf, port);
            const bytes = Buffer.from(page.body);
            response.writeHead(200, {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": String(bytes.length),
                "Cache-Control": "no-store",
                "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${page.nonce}'; connect-src 'self'; style-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            });
            response.end(bytes);
            return;
        }
        if (request.method !== "POST" || request.url !== "/pair/complete") {
            localJson(response, 404, { ok: false, reason: "LOCAL_ROUTE_NOT_FOUND" });
            return;
        }
        const expectedOrigin = `http://127.0.0.1:${port}`;
        const csrf = request.headers["x-noderooms-local-csrf"];
        const expiresAt = typeof csrf === "string"
            ? this.csrfSessions.get(csrf)
            : undefined;
        this.csrfSessions.delete(csrf);
        if (request.headers.origin !== expectedOrigin
            || typeof csrf !== "string"
            || !Number.isFinite(expiresAt)
            || expiresAt <= Date.now()
            || request.headers["content-type"]?.split(";", 1)[0]
                !== "application/json") {
            localJson(response, 403, { ok: false, reason: "LOCAL_PAIRING_CSRF_REJECTED" });
            return;
        }
        const chunks = [];
        let bytes = 0;
        for await (const chunk of request) {
            bytes += chunk.length;
            if (bytes > MAX_LOCAL_PAIRING_BODY_BYTES) {
                localJson(response, 413, { ok: false, reason: "LOCAL_PAIRING_BODY_TOO_LARGE" });
                request.destroy();
                return;
            }
            chunks.push(chunk);
        }
        let body;
        try {
            body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        }
        catch {
            localJson(response, 400, { ok: false, reason: "LOCAL_PAIRING_BODY_INVALID" });
            return;
        }
        try {
            const paired = await this.pair(
                body?.pairing_payload_b64url,
            );
            localJson(response, 200, {
                ok: true,
                return_to: paired.return_to,
                worker_binding_id: paired.worker_binding_id,
                private_key_stored_by_noderooms: false,
            });
        }
        catch (error) {
            localJson(response, 400, {
                ok: false,
                reason: error instanceof GmailTrustBridgeWorkerError
                    ? error.code
                    : "PAIRING_STOPPED_SAFELY",
            });
        }
    }

    async pair(encodedPayload) {
        const payload = validatePairingPayload(encodedPayload, this.config);
        let binding = await readPrivateRecord(this.paths, this.config);
        if (binding?.record?.status === "ACTIVE") {
            if (binding.record.agent_slug !== payload.agent_slug
                || binding.record.passport_public_id
                    !== payload.passport_public_id) {
                fail(
                    "GMAIL_TRUSTBRIDGE_ALREADY_BOUND",
                    "This OpenClaw Agent is already paired to another NodeRooms Agent or Passport.",
                );
            }
            return {
                return_to: payload.return_to,
                worker_binding_id: binding.record.worker_binding_id,
            };
        }
        if (binding?.record?.status === "PAIRING_PENDING"
            && (binding.record.pairing_challenge_id !== payload.challenge_id
                || binding.record.pairing_challenge_sha256
                    !== sha256(payload.challenge))) {
            const renewed = {
                ...binding.record,
                pairing_challenge_id: payload.challenge_id,
                pairing_challenge_sha256: sha256(payload.challenge),
            };
            await writePrivateRecord(this.paths, renewed);
            binding = validatePrivateRecord(renewed, this.config);
        }
        if (!binding) {
            const keys = generateKeyPairSync("ed25519");
            const publicJwk = keys.publicKey.export({ format: "jwk" });
            if (publicJwk.kty !== "OKP"
                || publicJwk.crv !== "Ed25519"
                || !BASE64URL_PATTERN.test(publicJwk.x ?? "")) {
                fail(
                    "GMAIL_TRUSTBRIDGE_KEY_GENERATION_FAILED",
                    "The worker Ed25519 key could not be generated.",
                );
            }
            const pending = {
                contract_version: GMAIL_TRUSTBRIDGE_PAIR_CONTRACT_VERSION,
                status: "PAIRING_PENDING",
                worker_id: `nrtbw_${randomBytes(16).toString("hex")}`,
                public_key_b64url: publicJwk.x,
                private_key_pkcs8_pem: keys.privateKey.export({
                    format: "pem",
                    type: "pkcs8",
                }),
                openclaw_agent_id: this.config.openclawAgentId,
                site_origin: this.config.baseUrl,
                pairing_challenge_id: payload.challenge_id,
                pairing_challenge_sha256: sha256(payload.challenge),
                created_at: new Date().toISOString(),
            };
            await writePrivateRecord(this.paths, pending);
            binding = validatePrivateRecord(pending, this.config);
        }
        const issuedAt = Math.floor(Date.now() / 1_000);
        const pairInput = {
            challenge_id: payload.challenge_id,
            challenge: payload.challenge,
            worker_id: binding.record.worker_id,
            public_key_b64url: binding.record.public_key_b64url,
            openclaw_agent_id: this.config.openclawAgentId,
            worker_version: GMAIL_TRUSTBRIDGE_WORKER_VERSION,
            supported_job_types: GMAIL_TRUSTBRIDGE_SUPPORTED_JOB_TYPES,
            issued_at: issuedAt,
        };
        const signature = sign(
            null,
            Buffer.from(gmailTrustBridgePairCanonical(pairInput)),
            binding.privateKey,
        ).toString("base64url");
        const response = await fetchJson(
            this.fetch,
            payload.callback_url,
            {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    contract_version:
                        GMAIL_TRUSTBRIDGE_PAIR_CONTRACT_VERSION,
                    ...pairInput,
                    signature_b64url: signature,
                }),
            },
        );
        if (!WORKER_ID_PATTERN.test(response.worker_id ?? "")
            || response.worker_id !== binding.record.worker_id
            || typeof response.worker_binding_id !== "string"
            || !response.worker_binding_id.startsWith("nrtbwb_")
            || response.agent?.slug !== payload.agent_slug
            || response.agent?.passport_public_id
                !== payload.passport_public_id
            || !BINDING_ID_PATTERN.test(
                response.agent?.owner_binding_id ?? "",
            )
            || response.agent?.owner_binding_status !== "verified"
            || response.agent?.passport_status !== "active") {
            fail(
                "GMAIL_TRUSTBRIDGE_PAIRING_RESPONSE_DRIFT",
                "The NodeRooms pairing response did not match the requested Agent and Passport.",
            );
        }
        const active = {
            ...binding.record,
            status: "ACTIVE",
            worker_binding_id: response.worker_binding_id,
            agent_slug: payload.agent_slug,
            owner_binding_id: response.agent.owner_binding_id,
            owner_binding_status: response.agent.owner_binding_status,
            passport_public_id: payload.passport_public_id,
            passport_status: response.agent.passport_status,
            pairing_challenge_id: undefined,
            pairing_challenge_sha256: undefined,
            paired_at: new Date().toISOString(),
        };
        delete active.pairing_challenge_id;
        delete active.pairing_challenge_sha256;
        await writePrivateRecord(this.paths, active);
        this.privateBinding = validatePrivateRecord(active, this.config);
        this.failureCount = 0;
        if (this.server) {
            this.schedulePoll(0);
        }
        return {
            return_to: payload.return_to,
            worker_binding_id: response.worker_binding_id,
        };
    }

    schedulePoll(delay) {
        if (this.stopping
            || this.pollTimer
            || this.privateBinding?.record?.status !== "ACTIVE") {
            return;
        }
        this.pollTimer = setTimeout(() => {
            this.pollTimer = null;
            this.pollOnce().catch(() => {});
        }, delay);
    }

    async signedRequest(requestPath, bodyObject) {
        const binding = this.privateBinding;
        if (!binding || binding.record.status !== "ACTIVE") {
            fail(
                "GMAIL_TRUSTBRIDGE_WORKER_NOT_PAIRED",
                "The OpenClaw infrastructure worker is not paired.",
            );
        }
        const body = JSON.stringify(bodyObject);
        const timestamp = Math.floor(Date.now() / 1_000);
        const nonce = randomBytes(32).toString("hex");
        const canonical = gmailTrustBridgeRequestCanonical(
            "POST",
            requestPath,
            timestamp,
            nonce,
            body,
        );
        const signature = sign(
            null,
            Buffer.from(canonical),
            binding.privateKey,
        ).toString("base64url");
        return fetchJson(
            this.fetch,
            `${this.config.baseUrl}${requestPath}`,
            {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                    "X-NodeRooms-Worker-Id": binding.record.worker_id,
                    "X-NodeRooms-Worker-Timestamp": String(timestamp),
                    "X-NodeRooms-Worker-Nonce": nonce,
                    "X-NodeRooms-Worker-Signature": signature,
                },
                body,
            },
        );
    }

    async pollOnce() {
        if (this.stopping || this.inFlight) {
            return;
        }
        this.inFlight = true;
        try {
            const response = await this.signedRequest(CLAIM_PATH, {
                contract_version:
                    GMAIL_TRUSTBRIDGE_WORKER_CONTRACT_VERSION,
                worker_id: this.privateBinding.record.worker_id,
                worker_binding_id:
                    this.privateBinding.record.worker_binding_id,
                supported_job_types:
                    GMAIL_TRUSTBRIDGE_SUPPORTED_JOB_TYPES,
                gmail_draft_enabled: true,
                gmail_owner_approved_send_enabled: true,
                gmail_direct_send_enabled: false,
                gmail_delete_enabled: false,
                max_jobs: 1,
            });
            this.failureCount = 0;
            if (response.job) {
                await this.processClaimedJob(response.job);
            }
        }
        catch (error) {
            this.failureCount = Math.min(this.failureCount + 1, 8);
            this.logger.warn(
                `NodeRooms Gmail TrustBridge worker stopped one poll safely (${error instanceof GmailTrustBridgeWorkerError ? error.code : "UNEXPECTED_ERROR"}).`,
            );
        }
        finally {
            this.inFlight = false;
            const delay = Math.min(
                this.config.pollIntervalMs * (2 ** this.failureCount),
                MAX_POLL_INTERVAL_MS,
            );
            this.schedulePoll(delay);
        }
    }

    validateClaimedJob(job) {
        const now = Date.now();
        const jobExpiresAt = Date.parse(job?.expires_at ?? "");
        if (!isRecord(job)
            || job.contract_version
                !== GMAIL_TRUSTBRIDGE_JOB_CONTRACT_VERSION
            || !JOB_ID_PATTERN.test(job.job_id ?? "")
            || !GMAIL_TRUSTBRIDGE_SUPPORTED_JOB_TYPES.includes(job.job_type)
            || !isRecord(job.agent)
            || job.agent.slug !== this.privateBinding.record.agent_slug
            || job.agent.passport_public_id
                !== this.privateBinding.record.passport_public_id
            || typeof job.payload_json !== "string"
            || !SHA256_PATTERN.test(job.payload_sha256 ?? "")
            || sha256(job.payload_json) !== job.payload_sha256
            || typeof job.lease_token !== "string"
            || job.lease_token.length < 32
            || job.lease_token.length > 512
            || !Number.isFinite(jobExpiresAt)
            || jobExpiresAt <= now
            || jobExpiresAt > now + 15 * 60_000) {
            fail(
                "GMAIL_TRUSTBRIDGE_CLAIM_INVALID",
                "The claimed NodeRooms Gmail job failed its exact binding checks.",
            );
        }
        let payload;
        try {
            payload = JSON.parse(job.payload_json);
        }
        catch {
            fail(
                "GMAIL_TRUSTBRIDGE_CLAIM_INVALID",
                "The claimed NodeRooms Gmail job payload is invalid.",
            );
        }
        if (!isRecord(payload)) {
            fail(
                "GMAIL_TRUSTBRIDGE_CLAIM_INVALID",
                "The claimed NodeRooms Gmail job payload is invalid.",
            );
        }
        const invocation = buildGmailTrustBridgeGogInvocation(
            job.job_type,
            payload,
            this.config,
        );
        const targetFingerprintSha256 =
            gmailTrustBridgeJobTargetFingerprint(
                job.job_type,
                payload,
                this.config,
            );
        const authority = validateNodeRoomsConnectorJobAuthority(
            job.authority,
            {
                jobId: job.job_id,
                jobType: job.job_type,
                payloadSha256: job.payload_sha256,
                agentSlug: this.privateBinding.record.agent_slug,
                passportPublicId:
                    this.privateBinding.record.passport_public_id,
                ownerBindingId:
                    this.privateBinding.record.owner_binding_id,
                provider: "gmail",
                accountBindingSha256: sha256(this.config.gog.account),
                targetFingerprintSha256,
                scope: NODEROOMS_CONNECTOR_JOB_SCOPES[job.job_type],
                draftIdSha256:
                    job.job_type === "gmail_send_approved_draft"
                        ? sha256(exactProviderId(
                            payload.draft_id,
                            "draft_id",
                        ))
                        : null,
                nowMs: now,
            },
        );
        if (jobExpiresAt
            > Date.parse(job.authority.run_lease.expires_at)
            || jobExpiresAt
                > Date.parse(job.authority.capability.expires_at)) {
            fail(
                "GMAIL_TRUSTBRIDGE_CLAIM_INVALID",
                "The Gmail job outlives its connector authority.",
            );
        }
        return { payload, invocation, authority };
    }

    async completeJob(job, completion) {
        const requestPath = `${COMPLETE_PATH_PREFIX}${job.job_id}/complete`;
        let lastError;
        for (let attempt = 0; attempt < 3; attempt += 1) {
            try {
                return await this.signedRequest(requestPath, completion);
            }
            catch (error) {
                lastError = error;
                if (error instanceof GmailTrustBridgeWorkerError
                    && Number(error.details?.http_status ?? 0) > 0) {
                    throw error;
                }
            }
        }
        throw lastError;
    }

    async processClaimedJob(job) {
        let payload;
        let invocation;
        let providerAttempted = false;
        try {
            ({ payload, invocation } = this.validateClaimedJob(job));
            if (this.claimedJobIds.has(job.job_id)) {
                fail(
                    "GMAIL_TRUSTBRIDGE_JOB_REPLAY_BLOCKED",
                    "The one-use Gmail job was already claimed by this worker.",
                );
            }
            this.claimedJobIds.add(job.job_id);
            if (this.claimedJobIds.size > 1_024) {
                this.claimedJobIds.delete(
                    this.claimedJobIds.values().next().value,
                );
            }
            const binding = await this.verifyExecutable(this.config);
            providerAttempted = true;
            const providerResult = await this.runCommand(
                binding.executablePath,
                invocation,
            );
            const result = normalizeGmailTrustBridgeJobResult(
                job.job_type,
                payload,
                providerResult,
                this.config,
            );
            await this.completeJob(job, {
                contract_version:
                    GMAIL_TRUSTBRIDGE_WORKER_CONTRACT_VERSION,
                worker_id: this.privateBinding.record.worker_id,
                worker_binding_id:
                    this.privateBinding.record.worker_binding_id,
                job_id: job.job_id,
                lease_token: job.lease_token,
                payload_sha256: job.payload_sha256,
                outcome: "succeeded",
                result,
            });
        }
        catch (error) {
            const errorCode = error instanceof GmailTrustBridgeWorkerError
                || error instanceof NodeRoomsConnectorAuthorityError
                ? error.code
                : "GMAIL_TRUSTBRIDGE_WORKER_JOB_FAILED";
            const uncertainWrite = providerAttempted
                && ["draft", "send"].includes(invocation?.writeKind);
            try {
                await this.completeJob(job, {
                    contract_version:
                        GMAIL_TRUSTBRIDGE_WORKER_CONTRACT_VERSION,
                    worker_id: this.privateBinding.record.worker_id,
                    worker_binding_id:
                        this.privateBinding.record.worker_binding_id,
                    job_id: job.job_id,
                    lease_token: job.lease_token,
                    payload_sha256: job.payload_sha256,
                    outcome: uncertainWrite ? "unknown" : "failed",
                    error_code: errorCode,
                    provider_attempt_count: providerAttempted ? 1 : 0,
                    automatic_retry_attempted: false,
                    exactly_once_effect_claimed: false,
                });
            }
            catch {
                // The one-use job remains sealed. It is never reclaimed or rerun.
            }
        }
    }
}

export function registerGmailTrustBridgeWorkerService(api, options) {
    if (api.registrationMode !== "full") {
        return null;
    }
    const service = options.service ?? new GmailTrustBridgeWorkerService({
        config: options.config,
        agentDir: options.agentDir,
        logger: api.logger,
    });
    api.registerService({
        id: "noderooms-gmail-trustbridge-worker",
        start: () => service.start(),
        stop: () => service.stop(),
    });
    return service;
}
