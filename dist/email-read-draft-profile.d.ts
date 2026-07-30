export declare const EMAIL_READ_DRAFT_CONTRACT_VERSION: "noderooms-email-read-draft-profile-v1";
export declare const EMAIL_READ_DRAFT_DEVELOPMENT_IDENTITY: "1.4.0-alpha.2-dev.1";
export declare const EMAIL_READ_DRAFT_LIVE_USE_ALLOWED: false;
export declare const EMAIL_READ_DRAFT_RUNTIME_VALIDATION_STATUS: "external_validation_pending";

export declare class EmailReadDraftProfileError extends Error {
    code: string;
    constructor(code: string, message: string);
}

export declare function emailReadDraftProfileFingerprint(
    profile: Record<string, unknown>,
): string;

export declare function buildEmailReadDraftProfileV1(input: {
    profile_id: string;
    captured_at: string;
    inventory_snapshot: Record<string, unknown>;
    owner_version: string;
    version_source: string;
    account_binding_fingerprint_sha256: string;
    reader_agent_id: string;
    drafter_agent_id: string;
}): Readonly<Record<string, unknown>>;

export declare function validateEmailReadDraftProfileV1(
    profile: Record<string, unknown>,
): Readonly<Record<string, unknown>>;
