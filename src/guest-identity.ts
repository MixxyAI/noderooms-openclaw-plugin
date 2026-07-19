import {
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  type JsonWebKey,
} from "node:crypto";
import path from "node:path";
import { privateFileStore } from "openclaw/plugin-sdk/security-runtime";
import {
  GUEST_PROTOCOL,
  GUEST_PUBLIC_KEY_PATTERN,
  GUEST_RUNTIME_ID_PATTERN,
  NODEROOMS_ORIGIN,
  NodeRoomsError,
} from "./contracts.js";

const IDENTITY_FILE = "guest-identity.json";
const IDENTITY_VERSION = 1;

export type GuestDeviceIdentity = {
  version: 1;
  runtime_id: string;
  public_key: string;
  private_key: JsonWebKey;
  created_at: string;
};

function validIdentity(value: unknown): value is GuestDeviceIdentity {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const item = value as Partial<GuestDeviceIdentity>;
  const key = item.private_key;
  return item.version === IDENTITY_VERSION
    && typeof item.runtime_id === "string"
    && GUEST_RUNTIME_ID_PATTERN.test(item.runtime_id)
    && typeof item.public_key === "string"
    && GUEST_PUBLIC_KEY_PATTERN.test(item.public_key)
    && Boolean(key)
    && key?.kty === "OKP"
    && key.crv === "Ed25519"
    && key.x === item.public_key
    && typeof key.d === "string"
    && /^[A-Za-z0-9_-]{43}$/.test(key.d);
}

function createIdentity(): GuestDeviceIdentity {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  if (!publicJwk.x || !GUEST_PUBLIC_KEY_PATTERN.test(publicJwk.x)) {
    throw new NodeRoomsError("GUEST_IDENTITY_CREATE_FAILED", "OpenClaw could not create a valid Ed25519 Guest identity.");
  }
  return {
    version: IDENTITY_VERSION,
    runtime_id: `openclaw-${randomUUID()}`,
    public_key: publicJwk.x,
    private_key: privateJwk,
    created_at: new Date().toISOString(),
  };
}

export async function loadOrCreateGuestIdentity(stateDir: string): Promise<GuestDeviceIdentity> {
  const store = privateFileStore(path.join(stateDir, "plugins", "noderooms"));
  const existing = await store.readJsonIfExists<unknown>(IDENTITY_FILE, { maxBytes: 16_384 });
  if (existing !== null) {
    if (!validIdentity(existing)) {
      throw new NodeRoomsError(
        "GUEST_IDENTITY_INVALID",
        "The local NodeRooms Guest identity is invalid. Remove it manually only after reviewing the file path and revoking the old Guest in NodeRooms.",
      );
    }
    return existing;
  }
  const identity = createIdentity();
  await store.writeJson(IDENTITY_FILE, identity, {
    dirMode: 0o700,
    mode: 0o600,
    maxBytes: 16_384,
    trailingNewline: true,
  });
  return identity;
}

export function createSignedGuestEntry(identity: GuestDeviceIdentity, agentName: string): Record<string, unknown> {
  const issuedAt = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(24).toString("base64url");
  const canonical = `${GUEST_PROTOCOL}\n`
    + `origin=${NODEROOMS_ORIGIN}\n`
    + `runtime_id=${identity.runtime_id}\n`
    + `agent_name=${agentName}\n`
    + `issued_at=${issuedAt}\n`
    + `nonce=${nonce}\n`
    + `public_key=${identity.public_key}`;
  const privateKey = createPrivateKey({ key: identity.private_key, format: "jwk" });
  const signature = sign(null, Buffer.from(canonical, "utf8"), privateKey).toString("base64url");
  return {
    protocol_version: GUEST_PROTOCOL,
    runtime_id: identity.runtime_id,
    agent_name: agentName,
    issued_at: issuedAt,
    client_nonce: nonce,
    public_key: identity.public_key,
    signature,
  };
}
