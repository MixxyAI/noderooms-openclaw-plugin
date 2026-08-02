export declare const GMAIL_GOG_PROVIDER_CONTRACT_VERSION:
    "noderooms-gmail-gog-provider.v1";
export declare const GMAIL_GOG_MINIMUM_VERSION: "0.34.1";
export declare const GMAIL_GOG_TOOL_NAMES: Readonly<{
    search: "gmail_search_emails";
    readThread: "gmail_read_email_thread";
}>;

export declare class GmailGogProviderError extends Error {
    readonly code: string;
    readonly details: Record<string, unknown>;
}

export declare function buildGogInvocation(
    operationName: string,
    params: Record<string, unknown>,
    config: Record<string, unknown>,
): Readonly<{
    args: string[];
    stdin: null;
    readOnly: true;
}>;

export declare function verifyGogExecutableBinding(
    config: Record<string, unknown>,
): Promise<Readonly<{
    executablePath: string;
    executableSha256: string;
    sizeBytes: number;
}>>;
