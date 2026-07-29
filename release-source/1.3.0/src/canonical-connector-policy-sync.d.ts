export declare const CANONICAL_CONNECTOR_POLICY_BUNDLE_CONTRACT_VERSION:
    "noderooms-canonical-connector-policy-bundle-v1";
export declare const CANONICAL_POLICY_TRUST_ANCHOR_CONTRACT_VERSION:
    "noderooms-canonical-policy-trust-anchor-v1";
export declare const CANONICAL_POLICY_SYNC_CHECKPOINT_CONTRACT_VERSION:
    "noderooms-canonical-policy-sync-checkpoint-v1";
export declare const CANONICAL_POLICY_INVENTORY_BINDING_CONTRACT_VERSION:
    "noderooms-canonical-policy-inventory-binding-v1";
export declare const CANONICAL_POLICY_SYNC_LIVE_FETCH_ALLOWED: false;
export declare const CANONICAL_POLICY_SYNC_GRANTS_TOOL_AUTHORITY: false;

export declare class CanonicalConnectorPolicySyncError extends Error {
    code: string;
    constructor(code: string, message: string);
}

export declare function validateCanonicalPolicyTrustAnchorV1(
    trustAnchor: Record<string, unknown>,
    options?: {
        allowFixture?: boolean;
        now?: Date | number;
    },
): Readonly<Record<string, unknown>>;

export declare function canonicalPolicyBundleFingerprint(
    bundle: Record<string, unknown>,
): string;

export declare function canonicalPolicyBundleSignaturePayload(
    bundle: Record<string, unknown>,
): string;

export declare function validateCanonicalConnectorPolicyBundleV1(
    bundle: Record<string, unknown>,
    options: {
        trustAnchor: Record<string, unknown>;
        allowFixture?: boolean;
        now?: Date | number;
    },
): Readonly<Record<string, unknown>>;

export declare function canonicalPolicyCheckpointFingerprint(
    checkpoint: Record<string, unknown>,
): string;

export declare function createCanonicalPolicySyncCheckpointV1(
    bundle: Record<string, unknown>,
    acceptedAt: Date | number,
): Readonly<Record<string, unknown>>;

export declare function validateCanonicalPolicySyncCheckpointV1(
    checkpoint: Record<string, unknown>,
): Readonly<Record<string, unknown>>;

export declare function createInMemoryCanonicalPolicyCheckpointStore(
    initialCheckpoint?: Record<string, unknown> | null,
): Readonly<{
    load(): Promise<Record<string, unknown> | null>;
    compareAndSet(
        expectedFingerprint: string | null,
        nextCheckpoint: Record<string, unknown>,
    ): Promise<boolean>;
}>;

export declare class CanonicalConnectorPolicySyncController {
    constructor(options?: {
        source?: {
            read(request: Record<string, unknown>): Promise<unknown>;
        };
        checkpointStore?: {
            load(): Promise<Record<string, unknown> | null>;
            compareAndSet(
                expectedFingerprint: string | null,
                nextCheckpoint: Record<string, unknown>,
            ): Promise<boolean>;
        };
        trustAnchor?: Record<string, unknown>;
        allowFixture?: boolean;
        minimumSequence?: number;
        now?: () => Date | number;
    });
    sync(input?: {
        reason?: string;
    }): Promise<Readonly<Record<string, unknown>> | null>;
    bindInventory(
        inventory: Record<string, unknown>,
    ): Readonly<Record<string, unknown>>;
    verifiedRegistry(): Readonly<Record<string, unknown>> | null;
    status(): Readonly<Record<string, unknown>>;
    clearRuntimeCache(): void;
}
