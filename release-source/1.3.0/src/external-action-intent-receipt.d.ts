import type { JsonRecord } from "./passport-runtime-binding.js";

export declare class ExternalActionContractError extends Error {
    readonly code: string;
    constructor(code: string, message: string);
}

export type ExternalActionValidationOptions = {
    registry: JsonRecord;
    runtimeBinding?: JsonRecord;
    allowFixture?: boolean;
    allowContractOnly?: boolean;
    requireLiveIntentWindow?: boolean;
    trustedReceiptKeyThumbprint?: string;
    trustedReceiptPublicKeyJwk?: JsonRecord;
    expectedReceiptIssuer?: string;
    now?: number | Date;
};

export type ExternalActionDecision = Readonly<{
    decision: "contract_match_not_authorized" | "block_invalid_external_action";
    reason_code: string;
    receipt_id?: string;
    intent_id?: string;
    lease_id?: string;
    receipt_fingerprint_sha256?: string;
}>;

export declare function dispatchReservationProjection(intent: JsonRecord): JsonRecord;
export declare function dispatchReservationFingerprint(intent: JsonRecord): string;
export declare function externalActionIntentProjection(intent: JsonRecord): JsonRecord;
export declare function externalActionIntentFingerprint(intent: JsonRecord): string;
export declare function validateExternalActionIntentV2(
    input: {
        intent: JsonRecord;
        lease: JsonRecord;
        request: JsonRecord;
        decision: JsonRecord;
    },
    options: ExternalActionValidationOptions,
): JsonRecord;
export declare function outcomeFingerprint(receipt: JsonRecord): string;
export declare function receiptAttributionFingerprint(receipt: JsonRecord): string;
export declare function externalActionReceiptProjection(receipt: JsonRecord): JsonRecord;
export declare function externalActionReceiptFingerprint(receipt: JsonRecord): string;
export declare function receiptSignatureProjection(receipt: JsonRecord): JsonRecord;
export declare function validateExternalActionReceiptV2(
    input: {
        receipt: JsonRecord;
        intent: JsonRecord;
        lease: JsonRecord;
        request: JsonRecord;
        decision: JsonRecord;
        previousReceipt?: JsonRecord;
    },
    options: ExternalActionValidationOptions,
): JsonRecord;
export declare function evaluateExternalActionReceiptV2(
    input: {
        receipt: JsonRecord;
        intent: JsonRecord;
        lease: JsonRecord;
        request: JsonRecord;
        decision: JsonRecord;
        previousReceipt?: JsonRecord;
    },
    options: ExternalActionValidationOptions,
): ExternalActionDecision;
export declare function validateIntentReservationSet(
    records: Array<{
        intent: JsonRecord;
        lease: JsonRecord;
        request: JsonRecord;
        decision: JsonRecord;
        registry: JsonRecord;
        runtimeBinding: JsonRecord;
    }>,
    options?: Omit<ExternalActionValidationOptions, "registry" | "runtimeBinding">,
): Readonly<{
    intent_count: number;
    unique_lease_count: number;
    at_most_once_dispatch_required: true;
    automatic_write_retry_allowed: false;
    live_enforce_allowed: false;
}>;
export declare function validateReceiptChain(
    records: Array<{
        receipt: JsonRecord;
        intent: JsonRecord;
        lease: JsonRecord;
        request: JsonRecord;
        decision: JsonRecord;
        registry: JsonRecord;
        runtimeBinding: JsonRecord;
    }>,
    options: Omit<ExternalActionValidationOptions, "registry" | "runtimeBinding">,
): Readonly<{
    receipt_count: number;
    dispatch_attempt_count: 1;
    automatic_write_retry_attempted: false;
    reconciliation_mode: "read_only";
    terminal_status: string;
    exactly_once_effect_claimed: false;
}>;
