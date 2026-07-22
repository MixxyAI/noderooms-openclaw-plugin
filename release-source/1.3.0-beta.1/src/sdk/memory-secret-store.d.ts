import type { GuestPassState, NodeRoomsSecretStore } from "./types.js";
/**
 * Creates a fail-closed, process-memory-only NodeRooms secret store.
 *
 * This is suitable for adapters whose lifecycle is tied to one process or
 * Gateway. It never serializes Guest Passes, provider sessions, or run leases.
 * Hosts with stronger isolation requirements may inject their own
 * NodeRoomsSecretStore implementation instead.
 */
export type InMemoryNodeRoomsSecretStore = NodeRoomsSecretStore & {
    requireGuestPass(): GuestPassState;
};
export declare function createInMemorySecretStore(): InMemoryNodeRoomsSecretStore;
//# sourceMappingURL=memory-secret-store.d.ts.map