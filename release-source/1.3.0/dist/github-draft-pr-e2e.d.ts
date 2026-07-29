export declare const GITHUB_DRAFT_PR_E2E_CONTRACT_VERSION:
    "noderooms-github-draft-pr-e2e-v1";
export declare const GITHUB_DRAFT_PR_E2E_RECEIPT_CONTRACT_VERSION:
    "noderooms-github-draft-pr-e2e-receipt-v1";
export declare const GITHUB_DRAFT_PR_E2E_SCOPE:
    "connector.github.pull_request.draft";
export declare const GITHUB_DRAFT_PR_E2E_PROFILE_ID:
    "nrscp_github_pull_request_draft_v1";
export declare const GITHUB_DRAFT_PR_E2E_TOOL_NAME:
    "github_create_pull_request";
export declare const GITHUB_DRAFT_PR_E2E_OWNER_ID:
    "github";
export declare const GITHUB_DRAFT_PR_E2E_CANONICAL_SCHEMA_FINGERPRINT:
    "sha256:c12e12e4f6a0d03d85c46dbe4e17cfe814f7a988f56ecc4c2b40089d621f8c37";
export declare const GITHUB_DRAFT_PR_E2E_TRANSPORT_ADAPTER:
    "noderooms-github-mcp-create-pull-request-adapter-v1";
export declare const GITHUB_DRAFT_PR_E2E_MCP_SERVER_NAME:
    "github-noderooms-draft-pr";
export declare const GITHUB_DRAFT_PR_E2E_MCP_EXACT_TOOL_ID:
    "github-noderooms-draft-pr__create_pull_request";
export declare const GITHUB_DRAFT_PR_E2E_MCP_RAW_TOOL_NAME:
    "create_pull_request";
export declare const GITHUB_DRAFT_PR_E2E_MCP_RAW_SCHEMA_FINGERPRINT:
    "sha256:e249ccd5a1f2364cbfc0a5d9e11bebdc298626351cc7e43fd59b851c3d520238";
export declare const GITHUB_DRAFT_PR_E2E_DISPATCH_RESERVATION_CONTRACT_VERSION:
    "noderooms-github-draft-pr-dispatch-reservation-v1";
export declare const GITHUB_DRAFT_PR_E2E_LIVE_PLUGIN_ARMED: false;

export declare class GitHubDraftPrE2EError extends Error {
    code: string;
    constructor(code: string, message: string);
}

export type JsonObject = Record<string, unknown>;

export declare function githubDraftPrPayloadProjection(
    payload: JsonObject,
): Readonly<JsonObject>;

export declare function githubDraftPrPayloadFingerprint(
    payload: JsonObject,
): string;

export declare function githubMcpCreatePullRequestParams(
    payload: JsonObject,
): Readonly<JsonObject>;

export declare function githubMcpCreatePullRequestParamsFingerprint(
    payload: JsonObject,
): string;

export interface GitHubDraftPrE2EReceiptSigner {
    readonly trust_anchor: Readonly<JsonObject>;
    signReceiptFingerprint(receiptFingerprint: string): string;
}

export declare function createGitHubDraftPrE2EReceiptSigner():
    Readonly<GitHubDraftPrE2EReceiptSigner>;

export declare function githubDraftPrE2EPlanFingerprint(
    plan: JsonObject,
): string;

export declare function createGitHubDraftPrE2EPlan(
    input: JsonObject,
    options?: {
        now?: Date | number | string;
    },
): Readonly<JsonObject>;

export declare function validateGitHubDraftPrE2EPlan(
    plan: JsonObject,
    options?: {
        now?: Date | number | string;
    },
): Readonly<JsonObject>;

export declare function githubDraftPrE2EReceiptFingerprint(
    receipt: JsonObject,
): string;

export declare function validateGitHubDraftPrE2EReceipt(
    receipt: JsonObject,
    options?: {
        expectedTrustAnchor?: JsonObject;
    },
): Readonly<JsonObject>;

export interface GitHubDraftPrProofStore {
    load(): Promise<JsonObject | null>;
    loadDispatchReservation(): Promise<JsonObject | null>;
    reserveDispatch(reservation: JsonObject): Promise<boolean>;
    compareAndSet(
        expectedRevision: number | null,
        nextRecord: JsonObject,
    ): Promise<boolean>;
}

export declare function createInMemoryGitHubDraftPrProofStore(
    initial?: JsonObject | null,
): Readonly<GitHubDraftPrProofStore>;

export declare function createFileGitHubDraftPrProofStore(
    filePath: string,
): Readonly<GitHubDraftPrProofStore>;

export declare class GitHubDraftPrE2EController {
    constructor(options: {
        plan: JsonObject;
        receiptSigner: GitHubDraftPrE2EReceiptSigner;
        store?: GitHubDraftPrProofStore;
        now?: () => Date | number | string;
    });
    arm(): Promise<Readonly<JsonObject>>;
    beforeToolCall(
        event: JsonObject,
        context: JsonObject,
    ): Promise<Readonly<JsonObject>>;
    afterToolCall(event: JsonObject): Promise<Readonly<JsonObject>>;
    reconcileReadOnly(
        observation: JsonObject,
    ): Promise<Readonly<JsonObject>>;
    revoke(reasonCode?: string): Promise<Readonly<JsonObject>>;
    status(): Promise<Readonly<JsonObject>>;
    evaluateBeforeToolCall(
        event: JsonObject,
        context: JsonObject,
    ): Promise<Readonly<JsonObject>>;
}
