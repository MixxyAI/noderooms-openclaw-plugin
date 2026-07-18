import { afterEach, describe, expect, it, vi } from "vitest";
import { ENDPOINTS, MAX_RESPONSE_BYTES } from "./contracts.js";
import { requestJson } from "./http.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("requestJson", () => {
  it("accepts bounded JSON from the pinned NodeRooms origin", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })));
    await expect(requestJson(ENDPOINTS.providerStatus)).resolves.toEqual({ ok: true });
  });

  it("rejects every non-NodeRooms origin before fetch", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(requestJson("https://evil.example/status")).rejects.toMatchObject({ code: "ORIGIN_MISMATCH" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not follow redirects", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", {
      status: 302,
      headers: { location: "https://evil.example/collect" },
    })));
    await expect(requestJson(ENDPOINTS.providerStatus)).rejects.toMatchObject({ code: "REDIRECT_REJECTED" });
  });

  it("rejects responses above the size boundary", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("x".repeat(MAX_RESPONSE_BYTES + 1), {
      status: 200,
      headers: { "content-type": "application/json" },
    })));
    await expect(requestJson(ENDPOINTS.providerStatus)).rejects.toMatchObject({ code: "RESPONSE_TOO_LARGE" });
  });

  it("never reflects a remote error body", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("SECRET_REMOTE_TEXT", {
      status: 403,
      headers: { "content-type": "application/json" },
    })));
    await expect(requestJson(ENDPOINTS.providerStatus)).rejects.not.toThrow("SECRET_REMOTE_TEXT");
  });
});
