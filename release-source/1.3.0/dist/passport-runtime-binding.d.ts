export declare class PassportRuntimeBindingError extends Error {
    readonly code: string;
    constructor(code: string, message: string);
}

export type JsonRecord = Record<string, unknown>;

export type RuntimeIdentity = {
    platform: "openclaw";
    gateway_id: string;
    runtime_instance_id: string;
    openclaw_agent_id: string;
};

export type RuntimeBindingContext = RuntimeIdentity & {
    runtime_key_thumbprint: string;
};

export type AgentBinding = {
    noderooms_agent_id: number;
    passport_id: string;
    owner_binding_id: string;
    verified_owner_required: true;
};

export type RuntimeBindingDecision = Readonly<{
    decision:
        | "binding_match"
        | "contract_match_not_authorized"
        | "block_invalid_binding"
        | "block_inactive_binding"
        | "block_agent_binding_mismatch"
        | "block_runtime_mismatch";
    reason_code: string;
    binding_id?: string;
    noderooms_agent_id?: number;
    passport_id?: string;
    owner_binding_id?: string;
    openclaw_agent_id?: string;
    runtime_key_thumbprint?: string;
}>;

export declare function canonicalJson(value: unknown): string;
export declare function sha256Fingerprint(value: unknown): string;
export declare function runtimeKeyThumbprint(publicKeyJwk: JsonRecord): string;
export declare function pairingChallengeProjection(challenge: JsonRecord): JsonRecord;
export declare function pairingChallengeFingerprint(challenge: JsonRecord): string;
export declare function validatePairingChallenge(
    challenge: JsonRecord,
    options?: { allowFixture?: boolean; now?: number | Date },
): JsonRecord;
export declare function validatePairingAssertion(
    assertion: JsonRecord,
    options?: { allowFixture?: boolean },
): JsonRecord;
export declare function verifyPairingAssertion(input: {
    challenge: JsonRecord;
    assertion: JsonRecord;
    now?: number | Date;
    allowFixture?: boolean;
}): Readonly<{
    verified: true;
    binding_request_id: string;
    challenge_id: string;
    assertion_id: string;
    challenge_fingerprint_sha256: string;
    runtime_key_thumbprint: string;
    atomic_challenge_consumption_required: true;
}>;
export declare function validateRuntimeBindingRecord(
    binding: JsonRecord,
    options?: {
        allowFixture?: boolean;
        allowContractOnly?: boolean;
        now?: number | Date;
    },
): JsonRecord;
export declare function evaluateRuntimeBinding(input: {
    binding: JsonRecord;
    expectedAgentBinding: AgentBinding;
    runtimeContext: RuntimeBindingContext;
    now?: number | Date;
    allowFixture?: boolean;
    allowContractOnly?: boolean;
}): RuntimeBindingDecision;
export declare function validateBindingSet(
    bindings: JsonRecord[],
    options?: {
        allowFixture?: boolean;
        allowContractOnly?: boolean;
        now?: number | Date;
    },
): Readonly<{
    binding_count: number;
    gateway_count: number;
    multi_agent_gateway_safe: boolean;
    shared_run_secret_allowed: false;
    shared_lease_allowed: false;
}>;
export declare function validateRecoveryRecord(
    recovery: JsonRecord,
    options?: { allowFixture?: boolean; now?: number | Date },
): JsonRecord;
