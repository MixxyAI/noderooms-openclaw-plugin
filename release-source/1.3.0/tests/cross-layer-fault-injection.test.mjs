import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { ActionIntentStore } from "../dist/action-intents.js";
import { NodeRoomsSdk } from "../dist/sdk/client.js";
import { createInMemorySecretStore } from "../dist/sdk/memory-secret-store.js";
import { ENDPOINTS, NodeRoomsError, actionStatusUrl } from "../dist/contracts.js";

const ownerPrepare = { agentId: "main", channel: "discord", requesterSenderId: "841060426409705475" };
const ownerCommand = { agentId: "main", channel: "discord", senderId: "841060426409705475", senderIsOwner: true, isAuthorizedSender: true };

function protocolStatus() {
  return {
    ok: true,
    gateway: "noderooms_action_idempotency",
    version: "1.3.0-alpha.1",
    protocol_version: "noderooms-action-idempotency-v1",
    protocol_ready: true,
    schema_ready: true,
    routes_ready: true,
    guest_auth_bridge_ready: true,
    write_bridge_ready: true,
    canonical_receipts_ready: true,
    server_idempotency_enforced: true,
    duplicate_write_prevented: true,
    unknown_outcome_replay_blocked: true,
    exactly_once_effect: false,
    action_types: ["guest_post", "guest_comment"],
    reservation_ttl_seconds: 7200,
    processing_stale_seconds: 120,
    idempotency_retention_days: 90,
    credentials_required_for_status: false,
    guest_pass_persisted: false,
    payload_persisted: false,
    fallback_to_legacy_direct_write: false,
  };
}
function guestEnter() {
  return {
    ok: true,
    guest_entered: true,
    guest_id: "nrog-" + "4".repeat(32),
    guest_pass: "nrguest_" + "5".repeat(64),
    guest_pass_expires_at: "2099-01-01T00:00:00Z",
    agent_id: 18,
    agent_slug: "openclaw-guest-test",
    agent_name: "OpenClaw Guest Agent",
  };
}
function canonicalReceipt(intent, overrides = {}) {
  return {
    ok: true,
    protocol_version: "noderooms-action-idempotency-v1",
    action_id: intent.id,
    receipt_id: "nrreceipt_" + "6".repeat(32),
    action_type: intent.kind,
    action_status: "committed",
    idempotency_status: "replayed",
    fingerprint_sha256: intent.fingerprint,
    server_idempotency_enforced: true,
    duplicate_write_prevented: true,
    unknown_outcome_replay_blocked: true,
    replay_blocked: true,
    public_write_attempted: true,
    dispatch_count: 1,
    exactly_once_effect: false,
    object_id: 777,
    public_url: "https://noderooms.com/noderooms-post/?post_id=777",
    error_code: null,
    error_message: null,
    created_at: "2026-07-22T00:00:00Z",
    updated_at: "2026-07-22T00:00:01Z",
    expires_at: "2026-07-22T02:00:00Z",
    committed_at: "2026-07-22T00:00:01Z",
    ...overrides,
  };
}
function sdkWithRequest(request) {
  return new NodeRoomsSdk({
    request,
    secretStore: createInMemorySecretStore(),
    guestEntrySigner: {
      storageLabel: "test",
      async createSignedEntry(agentName) { return { protocol: "test", agent_name: agentName, proof: "signed" }; },
    },
  });
}

async function fixture(t) {
  const dir = await mkdtemp(path.join(tmpdir(), "nr-cross-layer-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return new ActionIntentStore({ stateFilePath: path.join(dir, "action-intents-v1.json") });
}

test("lost response is reconciled read-only, sealed locally, and replay never posts again", async (t) => {
  const store = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "lost response" }, ownerPrepare);
  let posts = 0;
  let statusReads = 0;
  let currentIntent;
  const sdk = sdkWithRequest(async (url) => {
    if (url === ENDPOINTS.actionProtocolStatus) return protocolStatus();
    if (url === ENDPOINTS.guestEnter) return guestEnter();
    if (url === ENDPOINTS.guestActions) {
      posts++;
      throw new NodeRoomsError("NETWORK_ERROR", "response lost");
    }
    if (url === actionStatusUrl(prepared.intent_id)) {
      statusReads++;
      return canonicalReceipt(currentIntent);
    }
    throw new Error(`unexpected ${url}`);
  });
  const first = await store.commit(prepared.intent_id, ownerCommand, async (intent) => {
    currentIntent = intent;
    return sdk.createIdempotentGuestPost({
      actionId: intent.id,
      fingerprintSha256: intent.fingerprint,
      roomSlug: intent.payload.roomSlug,
      body: intent.payload.body,
    });
  });
  assert.equal(first.committed, true);
  assert.equal(first.result.idempotency_status, "replayed");
  assert.equal(posts, 1);
  assert.equal(statusReads, 1);
  const second = await store.commit(prepared.intent_id, ownerCommand, async () => {
    posts++;
    throw new Error("must not execute");
  });
  assert.equal(second.already_committed, true);
  assert.equal(posts, 1);
  assert.equal(statusReads, 1);
});

test("fingerprint conflict is confirmed pre-dispatch, restores prepared state, and allows a later safe retry", async (t) => {
  const store = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "conflict" }, ownerPrepare);
  let actionPosts = 0;
  const conflictSdk = sdkWithRequest(async (url) => {
    if (url === ENDPOINTS.actionProtocolStatus) return protocolStatus();
    if (url === ENDPOINTS.guestEnter) return guestEnter();
    if (url === ENDPOINTS.guestActions) {
      actionPosts++;
      throw new NodeRoomsError("HTTP_409", "immutable mismatch", 409);
    }
    throw new Error(`unexpected ${url}`);
  });
  await assert.rejects(() => store.commit(prepared.intent_id, ownerCommand, async (intent) => conflictSdk.createIdempotentGuestPost({
    actionId: intent.id,
    fingerprintSha256: intent.fingerprint,
    roomSlug: intent.payload.roomSlug,
    body: intent.payload.body,
  })), /remains prepared/i);
  assert.equal(actionPosts, 1);

  const successSdk = sdkWithRequest(async (url) => {
    if (url === ENDPOINTS.actionProtocolStatus) return protocolStatus();
    if (url === ENDPOINTS.guestEnter) return guestEnter();
    if (url === ENDPOINTS.guestActions) {
      actionPosts++;
      return canonicalReceipt(currentIntent, { idempotency_status: "created" });
    }
    throw new Error(`unexpected ${url}`);
  });
  let currentIntent;
  const result = await store.commit(prepared.intent_id, ownerCommand, async (intent) => {
    currentIntent = intent;
    return successSdk.createIdempotentGuestPost({
      actionId: intent.id,
      fingerprintSha256: intent.fingerprint,
      roomSlug: intent.payload.roomSlug,
      body: intent.payload.body,
    });
  });
  assert.equal(result.committed, true);
  assert.equal(actionPosts, 2);
});
