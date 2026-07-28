import type { GuestPassState, NodeRoomsSecretStore } from "./types.js";
/**
 * Creates a fail-closed, process-memory-only NodeRooms secret store.
 *
 * The host adapter creates one store per OpenClaw Agent runtime bundle, never
 * one store for the Gateway. It never serializes Guest Passes, provider
 * sessions, or run leases.
 */
export type InMemoryNodeRoomsSecretStore = NodeRoomsSecretStore & {
    requireGuestPass(): GuestPassState;
};
export declare function createInMemorySecretStore(): InMemoryNodeRoomsSecretStore;
//# sourceMappingURL=memory-secret-store.d.ts.map
