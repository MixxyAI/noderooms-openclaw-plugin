import {
    type GmailTrustBridgeReceiptSigner,
} from "./gmail-trustbridge-receipt.js";

export declare const GMAIL_TRUSTBRIDGE_PILOT_CONTRACT_VERSION:
    "noderooms-gmail-trustbridge-pilot.v1";
export declare const GMAIL_TRUSTBRIDGE_DEFAULT_MODE: "off";
export declare const GMAIL_TRUSTBRIDGE_DELETE_ALLOWED: false;

export declare class GmailTrustBridgePilotError extends Error {
    code: string;
    constructor(code: string, message: string);
}

export declare function gmailAddressFingerprint(value: string): string;
export declare function normalizeGmailTrustBridgeConfig(
    pluginConfig: unknown,
): Readonly<Record<string, unknown>>;

export declare class GmailTrustBridgePilotStore {
    constructor(options: {
        filePath: string;
        maxEntries?: number;
    });
    createReservation(
        reservation: Record<string, unknown>,
    ): Promise<Record<string, unknown>>;
    resolveApproval(
        reservationId: string,
        resolution: string,
        resolvedAt: string,
    ): Promise<Record<string, unknown>>;
    complete(
        reservationId: string,
        receipt: Record<string, unknown>,
        trustAnchor: Record<string, unknown>,
        outcomeStatus: string,
        completedAt: string,
    ): Promise<Record<string, unknown>>;
    find(reservationId: string):
        Promise<Record<string, unknown> | null>;
    summary(): Promise<Record<string, unknown>>;
    clearRuntimeCache(): void;
}

export declare class GmailTrustBridgePilotController {
    constructor(options: {
        config: Record<string, unknown>;
        store: GmailTrustBridgePilotStore;
        receiptSigner: GmailTrustBridgeReceiptSigner;
        now?: () => number;
    });
    beforeToolCall(
        event: Record<string, unknown>,
        context?: Record<string, unknown>,
    ): Promise<Record<string, unknown> | undefined>;
    afterToolCall(
        event: Record<string, unknown>,
        context?: Record<string, unknown>,
    ): Promise<void>;
    status(): Promise<Record<string, unknown>>;
    clearRuntimeCache(): void;
}
