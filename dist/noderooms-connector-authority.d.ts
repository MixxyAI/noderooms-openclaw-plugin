export declare const NODEROOMS_CONNECTOR_AUTHORITY_CONTRACT_VERSION = "noderooms-connector-job-authority.v1";
export declare const NODEROOMS_CONNECTOR_JOB_SCOPES: Readonly<Record<string, string>>;
export declare class NodeRoomsConnectorAuthorityError extends Error {
    readonly code: string;
    constructor(code: string, message: string);
}
export interface NodeRoomsConnectorAuthorityExpectation {
    jobId: string;
    jobType: string;
    payloadSha256: string;
    agentSlug: string;
    passportPublicId: string;
    ownerBindingId: string;
    provider: string;
    accountBindingSha256: string;
    targetFingerprintSha256: string;
    scope: string;
    draftIdSha256?: string | null;
    nowMs?: number;
}
export declare function noderoomsConnectorActionFingerprint(input: {
    jobId: string;
    jobType: string;
    payloadSha256: string;
    agentSlug: string;
    passportPublicId: string;
    ownerBindingId: string;
    capabilityId: string;
    runLeaseId: string;
    provider: string;
    accountBindingSha256: string;
    targetFingerprintSha256: string;
    scope: string;
    purposeId: string;
    purposeSha256: string;
    draftIdSha256?: string | null;
}): string;
export declare function validateNodeRoomsConnectorJobAuthority(
    authority: unknown,
    expected: NodeRoomsConnectorAuthorityExpectation,
): Readonly<{
    scope: string;
    ownerBindingId: string;
    capabilityId: string;
    runLeaseId: string;
    purposeId: string;
    actionApproval: Record<string, unknown> | null;
}>;
