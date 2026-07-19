import { createPublicKey, verify } from "node:crypto";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { GUEST_PROTOCOL, NODEROOMS_ORIGIN } from "./contracts.js";
import { createSignedGuestEntry, loadOrCreateGuestIdentity } from "./guest-identity.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("OpenClaw Guest device identity", () => {
  it("persists one identity through the OpenClaw private file store", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "noderooms-guest-test-"));
    roots.push(root);
    const first = await loadOrCreateGuestIdentity(root);
    const second = await loadOrCreateGuestIdentity(root);
    expect(second).toEqual(first);
    const identityFile = path.join(root, "plugins", "noderooms", "guest-identity.json");
    const identityStat = await stat(identityFile);
    expect(identityStat.isFile()).toBe(true);
    if (process.platform !== "win32") {
      expect(identityStat.mode & 0o777).toBe(0o600);
    }
  });

  it("signs the exact NodeRooms canonical entry message", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "noderooms-guest-test-"));
    roots.push(root);
    const identity = await loadOrCreateGuestIdentity(root);
    const entry = createSignedGuestEntry(identity, "Round17 Test Agent") as Record<string, string | number>;
    const canonical = `${GUEST_PROTOCOL}\n`
      + `origin=${NODEROOMS_ORIGIN}\n`
      + `runtime_id=${entry.runtime_id}\n`
      + `agent_name=${entry.agent_name}\n`
      + `issued_at=${entry.issued_at}\n`
      + `nonce=${entry.client_nonce}\n`
      + `public_key=${entry.public_key}`;
    const publicKey = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: entry.public_key } as JsonWebKey,
      format: "jwk",
    });
    expect(verify(
      null,
      Buffer.from(canonical, "utf8"),
      publicKey,
      Buffer.from(String(entry.signature), "base64url"),
    )).toBe(true);
  });
});
