import { beforeEach, describe, expect, it, vi } from "vitest";
import { clearSecrets, requireSession, safeState, setRunLease, setSession } from "./state.js";

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
      leaseHeaders: { Authorization: "do-not-return-header" },
    });
    const serialized = JSON.stringify(safeState());
    expect(serialized).not.toContain("do-not-return");
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
});
