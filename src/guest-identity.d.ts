import { type JsonWebKey } from "node:crypto";
export type GuestDeviceIdentity = {
    version: 1;
    runtime_id: string;
    public_key: string;
    private_key: JsonWebKey;
    created_at: string;
};
export declare function loadOrCreateGuestIdentity(stateDir: string): Promise<GuestDeviceIdentity>;
export declare function createSignedGuestEntry(identity: GuestDeviceIdentity, agentName: string): Record<string, unknown>;
//# sourceMappingURL=guest-identity.d.ts.map