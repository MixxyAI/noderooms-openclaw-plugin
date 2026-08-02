import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";

export const GMAIL_GOG_PROVIDER_CONTRACT_VERSION =
    "noderooms-gmail-gog-provider.v1";
export const GMAIL_GOG_MINIMUM_VERSION = "0.34.1";

// These identifiers are private worker operations. They are deliberately not
// registered as OpenClaw/model tools and cannot perform mailbox writes.
export const GMAIL_GOG_TOOL_NAMES = Object.freeze({
    search: "gmail_search_emails",
    readThread: "gmail_read_email_thread",
});

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const MESSAGE_ID_PATTERN = /^[A-Za-z0-9_-]{1,256}$/;

export class GmailGogProviderError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = "GmailGogProviderError";
        this.code = code;
        this.details = details;
    }
}

function fail(code, message, details) {
    throw new GmailGogProviderError(code, message, details);
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
        fail("GMAIL_GOG_INPUT_INVALID", `${label} is invalid.`);
    }
    return value;
}

function exactProviderId(value, label) {
    const candidate = boundedString(value, label, 1, 256);
    if (!MESSAGE_ID_PATTERN.test(candidate)) {
        fail("GMAIL_GOG_INPUT_INVALID", `${label} is invalid.`);
    }
    return candidate;
}

function readOnlyRootArgs(config, commandPolicy) {
    return [
        "--home",
        config.gog.homePath,
        "--account",
        config.gog.account,
        "--client",
        config.gog.client,
        "--enable-commands-exact",
        commandPolicy,
        "--no-input",
        "--json",
        "--color=never",
        "--wrap-untrusted",
        "--readonly",
        "--gmail-no-send",
    ];
}

/**
 * Build only the two read-only gog invocations used by the background worker.
 * Draft creation and approved-draft send are built in the authority-validated
 * worker path so this low-level adapter cannot become a generic write route.
 */
export function buildGogInvocation(operationName, params, config) {
    if (!isRecord(params)) {
        fail("GMAIL_GOG_INPUT_INVALID", "Gmail operation parameters are invalid.");
    }
    switch (operationName) {
        case GMAIL_GOG_TOOL_NAMES.search: {
            const query = boundedString(params.query, "query", 1, 512);
            const maxResults = params.max_results ?? 10;
            if (!Number.isSafeInteger(maxResults)
                || maxResults < 1
                || maxResults > 20) {
                fail("GMAIL_GOG_INPUT_INVALID", "max_results is invalid.");
            }
            const args = [
                ...readOnlyRootArgs(config, "gmail.messages.search"),
                "gmail", "messages", "search", query,
                "--max", String(maxResults),
            ];
            if (params.page_token !== undefined) {
                args.push(
                    "--page",
                    boundedString(params.page_token, "page_token", 1, 512),
                );
            }
            return Object.freeze({ args, stdin: null, readOnly: true });
        }
        case GMAIL_GOG_TOOL_NAMES.readThread:
            return Object.freeze({
                args: [
                    ...readOnlyRootArgs(config, "gmail.thread.get"),
                    "gmail", "thread", "get",
                    exactProviderId(params.thread_id, "thread_id"),
                    "--sanitize-content",
                ],
                stdin: null,
                readOnly: true,
            });
        default:
            fail(
                "GMAIL_GOG_TOOL_UNSUPPORTED",
                "This operation is outside the read-only Gmail worker adapter.",
            );
    }
}

export async function verifyGogExecutableBinding(config) {
    const executablePath = config?.gog?.executablePath;
    const expected = config?.gog?.executableSha256;
    if (typeof executablePath !== "string"
        || !path.isAbsolute(executablePath)
        || !SHA256_PATTERN.test(expected ?? "")) {
        fail(
            "GMAIL_GOG_BINDING_INCOMPLETE",
            "The exact Gmail provider binary binding is incomplete.",
        );
    }
    let stat;
    try {
        stat = await lstat(executablePath);
    }
    catch {
        fail(
            "GMAIL_GOG_BINARY_MISSING",
            "The bound Gmail provider binary is unavailable.",
        );
    }
    if (!stat.isFile()
        || stat.isSymbolicLink()
        || stat.size < 1_000_000
        || stat.size > 150_000_000) {
        fail(
            "GMAIL_GOG_BINARY_INVALID",
            "The bound Gmail provider path is not an acceptable regular file.",
        );
    }
    const bytes = await readFile(executablePath);
    const actual = `sha256:${createHash("sha256")
        .update(bytes)
        .digest("hex")}`;
    if (actual !== expected) {
        fail(
            "GMAIL_GOG_BINARY_HASH_MISMATCH",
            "The bound Gmail provider binary fingerprint changed.",
        );
    }
    return Object.freeze({
        executablePath,
        executableSha256: actual,
        sizeBytes: stat.size,
    });
}
