import type {
    AgentBinding,
    JsonRecord,
} from "./passport-runtime-binding.js";

export declare class OwnerCapabilityLeaseError extends Error {
    readonly code: string;
    constructor(code: string, message: string);
}

export type CapabilityLeaseDecision = Readonly<{
    decision: "contract_match_not_authorized" | "block_invalid_lease";
    reason_code: string;
    lease_id?: string;
    request_id?: string;
    decision_id?: string;
    lease_authority_fingerprint_sha256?: string;
}>;

export type CapabilityValidationOptions = {
    registry: JsonRecord;
    runtimeBinding?: JsonRecord;
    allowFixture?: boolean;
    allowContractOnly?: boolean;
    requireLiveReviewWindow?: boolean;
    requireLiveDecision?: boolean;
    now?: number | Date;
};

export declare function capabilityRequestProjection(request: JsonRecord): JsonRecord;
export declare function capabilityRequestFingerprint(request: JsonRecord): string;
export declare function validateCapabilityRequest(
    request: JsonRecord,
    options: CapabilityValidationOptions,
): JsonRecord;
export declare function ownerDecisionProjection(decision: JsonRecord): JsonRecord;
export declare function ownerDecisionFingerprint(decision: JsonRecord): string;
export declare function validateOwnerDecision(
    input: {
        request: JsonRecord;
        decision: JsonRecord;
    },
    options: CapabilityValidationOptions,
): JsonRecord;
export declare function leaseAuthorityProjection(lease: JsonRecord): JsonRecord;
export declare function leaseAuthorityFingerprint(lease: JsonRecord): string;
export declare function validateRunLeaseV2(
    input: {
        lease: JsonRecord;
        request: JsonRecord;
        decision: JsonRecord;
    },
    options: CapabilityValidationOptions,
): JsonRecord;
export declare function evaluateRunLeaseV2(
    input: {
        lease: JsonRecord;
        request: JsonRecord;
        decision: JsonRecord;
    },
    options: CapabilityValidationOptions,
): CapabilityLeaseDecision;
export declare function validateLeaseIssuanceSet(
    records: Array<{
        lease: JsonRecord;
        request: JsonRecord;
        decision: JsonRecord;
        registry: JsonRecord;
        runtimeBinding: JsonRecord;
    }>,
    options?: Omit<CapabilityValidationOptions, "registry" | "runtimeBinding">,
): Readonly<{
    lease_count: number;
    unique_request_count: number;
    unique_decision_count: number;
    owner_decision_automatable: false;
    shared_lease_allowed: false;
    shared_run_secret_allowed: false;
}>;

export type { AgentBinding };
