import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearSecrets,
  guestHeaders,
  requireGuestPass,
  requireSession,
  safeState,
  setGuestPass,
  setRunLease,
  setSession,
} from "./state.js";

beforeEach(() => {
  clearSecrets();
  vi.useRealTimers();
});

describe("memory-only secret state", () => {
  it("reports only safe metadata", () => {
    setSession({
      arrivalId: "nrea-12345678",
      sessionId: "nrps-12345678",
      sessionSecret: "do-not-return-session",
      sessionExpiresAt: "2999-01-01T00:00:00Z",
    });
    setRunLease({
      runId: "nrrun-12345678",
      runSecret: "do-not-return-run",
      expiresAt: "2999-01-01T00:00:00Z",
      leaseHeaders: { "X-NodeRooms-Lease-Test": "lease-header-sentinel" },
    });
    const serialized = JSON.stringify(safeState());
    expect(serialized).not.toContain("do-not-return");
    expect(serialized).not.toContain("lease-header-sentinel");
    expect(serialized).toContain("nrea-12345678");
  });

  it("fails closed after explicit cleanup", () => {
    setSession({
      arrivalId: "nrea-12345678",
      sessionId: "nrps-12345678",
      sessionSecret: "secret",
      sessionExpiresAt: "2999-01-01T00:00:00Z",
    });
    clearSecrets();
    expect(() => requireSession()).toThrow(/No live NodeRooms provider session/);
  });

  it("keeps the Guest Pass memory-only and clears it on shutdown", () => {
    setGuestPass({
      guestId: "nrog-1234567890abcdef1234567890abcdef",
      agentId: 41,
      agentSlug: "openclaw-guest-test",
      guestPass: `nrguest_${"a".repeat(64)}`,
      expiresAt: "2999-01-01T00:00:00Z",
    });
    expect(guestHeaders()).toEqual({ Authorization: `Bearer nrguest_${"a".repeat(64)}` });
    expect(JSON.stringify(safeState())).not.toContain(`nrguest_${"a".repeat(64)}`);
    clearSecrets();
    expect(() => requireGuestPass()).toThrow(/No live NodeRooms Guest Pass/);
  });

  it("does not discard a live Guest Pass when no verified provider session exists", () => {
    setGuestPass({
      guestId: "nrog-1234567890abcdef1234567890abcdef",
      agentId: 41,
      agentSlug: "openclaw-guest-test",
      guestPass: `nrguest_${"b".repeat(64)}`,
      expiresAt: "2999-01-01T00:00:00Z",
    });
    expect(() => requireSession()).toThrow(/No live NodeRooms provider session/);
    expect(requireGuestPass().guestId).toBe("nrog-1234567890abcdef1234567890abcdef");
  });
});
