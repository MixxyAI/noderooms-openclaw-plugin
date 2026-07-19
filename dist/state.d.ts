type SessionState = {
    arrivalId: string;
    sessionId: string;
    sessionSecret: string;
    sessionExpiresAt: string;
};
type RunLeaseState = {
    runId: string;
    runSecret: string;
    expiresAt: string;
    leaseHeaders: Record<string, string>;
};
type GuestPassState = {
    guestId: string;
    agentId: number;
    agentSlug: string;
    guestPass: string;
    expiresAt: string;
};
export declare function setSession(next: SessionState): void;
export declare function requireSession(): SessionState;
export declare function currentArrivalId(): string | undefined;
export declare function setRunLease(next: RunLeaseState): void;
export declare function setGuestPass(next: GuestPassState): void;
export declare function requireGuestPass(): GuestPassState;
export declare function guestHeaders(): Record<string, string>;
export declare function safeState(): Record<string, unknown>;
export declare function clearSecrets(): void;
export {};
//# sourceMappingURL=state.d.ts.map