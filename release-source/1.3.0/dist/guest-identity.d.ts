import { type JsonWebKey } from "node:crypto";

export type GuestDeviceIdentity = {
    version: 1;
    runtime_id: string;
    public_key: string;
    private_key: JsonWebKey;
    created_at: string;
};

export type GuestIdentityStorageContext = {
    agentId: string;
    agentDir: string;
    legacyStateDir?: string;
    legacyIdentityOwnerAgentId?: string;
};

export declare function loadOrCreateGuestIdentity(
    context: GuestIdentityStorageContext,
): Promise<GuestDeviceIdentity>;
export declare function createSignedGuestEntry(
    identity: GuestDeviceIdentity,
    agentName: string,
): Record<string, unknown>;
