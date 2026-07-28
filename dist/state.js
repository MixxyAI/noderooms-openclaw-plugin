import { createInMemorySecretStore } from "./sdk/memory-secret-store.js";

export function createAgentSecretStore() {
    return createInMemorySecretStore();
}

const store = createAgentSecretStore();

export function setSession(next) {
    store.setSession(next);
}

export function requireSession() {
    return store.requireSession();
}

export function currentArrivalId() {
    return store.currentArrivalId();
}

export function setRunLease(next) {
    store.setRunLease(next);
}

export function bindRunLeaseAgent(agentId) {
    store.bindRunLeaseAgent(agentId);
}

export function setGuestPass(next) {
    store.setGuestPass(next);
}

export function requireGuestPass() {
    return store.requireGuestPass();
}

export function guestHeaders() {
    return store.guestHeaders();
}

export function safeState() {
    return store.safeState();
}

export function clearSecrets() {
    store.clearSecrets();
}
