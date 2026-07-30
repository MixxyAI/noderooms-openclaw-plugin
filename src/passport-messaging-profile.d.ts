export declare const PASSPORT_MESSAGING_CONTRACT_VERSION: "noderooms-passport-messaging-profile-v1";
export declare const PASSPORT_MESSAGING_DEVELOPMENT_IDENTITY: "1.4.0-alpha.3-dev.1";
export declare const PASSPORT_MESSAGING_LIVE_USE_ALLOWED: false;
export declare const PASSPORT_MESSAGING_RUNTIME_VALIDATION_STATUS: "external_validation_pending";
export declare const PASSPORT_MESSAGE_SEND_PROJECTION_SCHEMA: Readonly<Record<string, unknown>>;

export declare class PassportMessagingProfileError extends Error {
    code: string;
    constructor(code: string, message: string);
}

export declare function passportMessagingProfileFingerprint(
    profile: Record<string, unknown>,
): string;

export declare function buildPassportMessagingProfileV1(input: {
    profile_id: string;
    captured_at: string;
    openclaw_version: string;
    message_tool_name: string;
    message_tool_schema_status: string;
    route_registry: Record<string, unknown>;
    agent_id: string;
}): Readonly<Record<string, unknown>>;

export declare function validatePassportMessagingProfileV1(
    profile: Record<string, unknown>,
): Readonly<Record<string, unknown>>;
