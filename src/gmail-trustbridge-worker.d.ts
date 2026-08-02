export declare const GMAIL_TRUSTBRIDGE_WORKER_CONTRACT_VERSION:
    "noderooms-trustbridge-worker.v2";
export declare const GMAIL_TRUSTBRIDGE_JOB_CONTRACT_VERSION:
    "noderooms-trustbridge-job.v2";
export declare const GMAIL_TRUSTBRIDGE_PAIR_CONTRACT_VERSION:
    "noderooms-gmail-worker-pair.v1";
export declare const GMAIL_TRUSTBRIDGE_WORKER_VERSION:
    "1.4.0-alpha.6-dev.2";
export declare const GMAIL_TRUSTBRIDGE_SUPPORTED_JOB_TYPES:
    readonly string[];

export declare class GmailTrustBridgeWorkerError extends Error {
    readonly code: string;
    readonly details: Record<string, unknown>;
}

export declare function normalizeGmailTrustBridgeWorkerConfig(
    pluginConfig: Record<string, unknown> | undefined,
): Readonly<Record<string, unknown>>;

export declare function spawnGogWorkerOnce(
    executablePath: string,
    invocation: {
        args: string[];
        stdin: string | null;
        readOnly: boolean;
    },
): Promise<unknown>;

export declare function buildGmailTrustBridgeGogInvocation(
    jobType: string,
    payload: Record<string, unknown>,
    config: Record<string, unknown>,
): Readonly<{
    args: string[];
    stdin: string | null;
    readOnly: boolean;
    writeKind?: "draft" | "send";
    providerAttemptMax?: 1;
    automaticRetryAllowed?: false;
}>;

export declare function gmailTrustBridgeJobTargetFingerprint(
    jobType: string,
    payload: Record<string, unknown>,
    config: Record<string, unknown>,
): string;

export declare function normalizeGmailTrustBridgeJobResult(
    jobType: string,
    payload: Record<string, unknown>,
    providerResult: unknown,
    config: Record<string, unknown>,
): Record<string, unknown>;

export declare function gmailTrustBridgePairCanonical(
    input: Record<string, unknown>,
): string;

export declare function gmailTrustBridgeRequestCanonical(
    method: string,
    requestPath: string,
    timestamp: string | number,
    nonce: string,
    body: string,
): string;

export declare class GmailTrustBridgeWorkerService {
    constructor(options: Record<string, unknown>);
    start(): Promise<void>;
    stop(): Promise<void>;
    pair(encodedPayload: string): Promise<Record<string, unknown>>;
    pollOnce(): Promise<void>;
}

export declare function registerGmailTrustBridgeWorkerService(
    api: Record<string, unknown>,
    options: Record<string, unknown>,
): GmailTrustBridgeWorkerService | null;
