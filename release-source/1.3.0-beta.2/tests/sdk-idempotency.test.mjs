import test from "node:test";
import assert from "node:assert/strict";
import { NodeRoomsSdk } from "../dist/sdk/client.js";
import { createInMemorySecretStore } from "../dist/sdk/memory-secret-store.js";
import { ENDPOINTS, NodeRoomsError, actionStatusUrl } from "../dist/contracts.js";

const actionId = "nrwi_" + "1".repeat(32);
const fingerprint = "2".repeat(64);
const receiptId = "nrreceipt_" + "3".repeat(32);

function protocolStatus(overrides = {}) {
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
    ...overrides,
  };
}
function canonicalReceipt(overrides = {}) {
  return {
    ok: true,
    protocol_version: "noderooms-action-idempotency-v1",
    action_id: actionId,
    receipt_id: receiptId,
    action_type: "guest_post",
    action_status: "committed",
    idempotency_status: "created",
    fingerprint_sha256: fingerprint,
    server_idempotency_enforced: true,
    duplicate_write_prevented: true,
    unknown_outcome_replay_blocked: true,
    replay_blocked: true,
    public_write_attempted: true,
    dispatch_count: 1,
    exactly_once_effect: false,
    object_id: 201,
    public_url: "https://noderooms.com/noderooms-post/?post_id=201",
    error_code: null,
    error_message: null,
    created_at: "2026-07-22T00:00:00Z",
    updated_at: "2026-07-22T00:00:01Z",
    expires_at: "2026-07-22T02:00:00Z",
    committed_at: "2026-07-22T00:00:01Z",
    ...overrides,
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
function createSdk(request, signerCounter = { count: 0 }) {
  return new NodeRoomsSdk({
    request,
    secretStore: createInMemorySecretStore(),
    guestEntrySigner: {
      storageLabel: "test",
      async createSignedEntry(agentName) {
        signerCounter.count++;
        return { protocol: "test", agent_name: agentName, proof: "signed" };
      },
    },
  });
}

test("protocol preflight runs before Guest renewal", async () => {
  const calls = [];
  const signer = { count: 0 };
  const sdk = createSdk(async (url) => {
    calls.push(url);
    if (url === ENDPOINTS.actionProtocolStatus) return protocolStatus({ protocol_ready: false });
    throw new Error("unexpected");
  }, signer);
  await assert.rejects(() => sdk.createIdempotentGuestPost({
    actionId, fingerprintSha256: fingerprint, roomSlug: "playground", body: "hello"
  }), /No public write|not fully ready/i);
  assert.equal(signer.count, 0);
  assert.deepEqual(calls, [ENDPOINTS.actionProtocolStatus]);
});

test("idempotent post sends one action POST with exact headers", async () => {
  const calls = [];
  const sdk = createSdk(async (url, init = {}) => {
    calls.push({ url, init });
    if (url === ENDPOINTS.actionProtocolStatus) return protocolStatus();
    if (url === ENDPOINTS.guestEnter) return guestEnter();
    if (url === ENDPOINTS.guestActions) return canonicalReceipt();
    throw new Error(`unexpected ${url}`);
  });
  const result = await sdk.createIdempotentGuestPost({
    actionId, fingerprintSha256: fingerprint, roomSlug: "playground", body: "hello"
  });
  assert.equal(result.action_status, "committed");
  assert.equal(calls.filter((x) => x.url === ENDPOINTS.guestActions).length, 1);
  const post = calls.find((x) => x.url === ENDPOINTS.guestActions);
  assert.equal(post.init.headers["Idempotency-Key"], actionId);
  assert.equal(post.init.headers["X-NodeRooms-Action-Fingerprint"], fingerprint);
  assert.equal(JSON.parse(post.init.body).action_type, "guest_post");
});

test("idempotent comment uses guest_comment payload", async () => {
  const calls = [];
  const sdk = createSdk(async (url, init = {}) => {
    calls.push({ url, init });
    if (url === ENDPOINTS.actionProtocolStatus) return protocolStatus();
    if (url === ENDPOINTS.guestEnter) return guestEnter();
    if (url === ENDPOINTS.guestActions) return canonicalReceipt({
      action_type: "guest_comment",
      object_id: 99,
      public_url: "https://noderooms.com/noderooms-post/?post_id=201",
    });
    throw new Error(`unexpected ${url}`);
  });
  const result = await sdk.createIdempotentComment({
    actionId, fingerprintSha256: fingerprint, postId: 201, body: "comment"
  });
  assert.equal(result.action_type, "guest_comment");
  const payload = JSON.parse(calls.find((x) => x.url === ENDPOINTS.guestActions).init.body);
  assert.deepEqual(payload.payload, { post_id: 201, body: "comment" });
});

test("lost POST response performs one read-only reconciliation and no second POST", async () => {
  let posts = 0;
  let statusReads = 0;
  const sdk = createSdk(async (url) => {
    if (url === ENDPOINTS.actionProtocolStatus) return protocolStatus();
    if (url === ENDPOINTS.guestEnter) return guestEnter();
    if (url === ENDPOINTS.guestActions) {
      posts++;
      throw new NodeRoomsError("NETWORK_ERROR", "lost");
    }
    if (url === actionStatusUrl(actionId)) {
      statusReads++;
      return canonicalReceipt({ idempotency_status: "replayed" });
    }
    throw new Error(`unexpected ${url}`);
  });
  const result = await sdk.createIdempotentGuestPost({
    actionId, fingerprintSha256: fingerprint, roomSlug: "playground", body: "hello"
  });
  assert.equal(result.idempotency_status, "replayed");
  assert.equal(posts, 1);
  assert.equal(statusReads, 1);
});

test("uncertain POST with unavailable status blocks write retry", async () => {
  let posts = 0;
  const sdk = createSdk(async (url) => {
    if (url === ENDPOINTS.actionProtocolStatus) return protocolStatus();
    if (url === ENDPOINTS.guestEnter) return guestEnter();
    if (url === ENDPOINTS.guestActions) {
      posts++;
      throw new NodeRoomsError("REQUEST_TIMEOUT", "timeout");
    }
    if (url === actionStatusUrl(actionId)) throw new NodeRoomsError("HTTP_404", "not found", 404);
    throw new Error(`unexpected ${url}`);
  });
  await assert.rejects(() => sdk.createIdempotentGuestPost({
    actionId, fingerprintSha256: fingerprint, roomSlug: "playground", body: "hello"
  }), /reconcile/i);
  assert.equal(posts, 1);
});

test("confirmed 409 does not perform status read and marks no-write", async () => {
  let statusReads = 0;
  const sdk = createSdk(async (url) => {
    if (url === ENDPOINTS.actionProtocolStatus) return protocolStatus();
    if (url === ENDPOINTS.guestEnter) return guestEnter();
    if (url === ENDPOINTS.guestActions) throw new NodeRoomsError("HTTP_409", "conflict", 409);
    if (url === actionStatusUrl(actionId)) { statusReads++; return canonicalReceipt(); }
    throw new Error(`unexpected ${url}`);
  });
  try {
    await sdk.createIdempotentGuestPost({
      actionId, fingerprintSha256: fingerprint, roomSlug: "playground", body: "hello"
    });
    assert.fail("expected rejection");
  } catch (error) {
    assert.equal(error.publicWriteAttempted, false);
  }
  assert.equal(statusReads, 0);
});

test("actionStatus is read-only and validates binding", async () => {
  const calls = [];
  const sdk = createSdk(async (url, init = {}) => {
    calls.push({ url, init });
    if (url === ENDPOINTS.guestEnter) return guestEnter();
    if (url === actionStatusUrl(actionId)) return canonicalReceipt({ idempotency_status: "replayed" });
    throw new Error(`unexpected ${url}`);
  });
  const value = await sdk.actionStatus({ actionId, fingerprintSha256: fingerprint, actionType: "guest_post" });
  assert.equal(value.receipt_id, receiptId);
  assert.equal(calls.filter((x) => x.url === actionStatusUrl(actionId)).length, 1);
  assert.equal(calls.some((x) => x.init?.method === "POST"), true); // only Guest entry, never action POST
  assert.equal(calls.some((x) => x.url === ENDPOINTS.guestActions), false);
});


test("ambiguous HTTP 503 after action POST performs read-only status reconciliation", async () => {
  let posts = 0;
  let statusReads = 0;
  const sdk = createSdk(async (url) => {
    if (url === ENDPOINTS.actionProtocolStatus) return protocolStatus();
    if (url === ENDPOINTS.guestEnter) return guestEnter();
    if (url === ENDPOINTS.guestActions) {
      posts++;
      throw new NodeRoomsError("HTTP_503", "upstream unavailable", 503);
    }
    if (url === actionStatusUrl(actionId)) {
      statusReads++;
      return canonicalReceipt({ idempotency_status: "replayed" });
    }
    throw new Error(`unexpected ${url}`);
  });
  const result = await sdk.createIdempotentGuestPost({
    actionId, fingerprintSha256: fingerprint, roomSlug: "playground", body: "hello"
  });
  assert.equal(result.idempotency_status, "replayed");
  assert.equal(posts, 1);
  assert.equal(statusReads, 1);
});

test("ambiguous HTTP 503 with unavailable status becomes unknown and never retries POST", async () => {
  let posts = 0;
  let statusReads = 0;
  const sdk = createSdk(async (url) => {
    if (url === ENDPOINTS.actionProtocolStatus) return protocolStatus();
    if (url === ENDPOINTS.guestEnter) return guestEnter();
    if (url === ENDPOINTS.guestActions) {
      posts++;
      throw new NodeRoomsError("HTTP_503", "upstream unavailable", 503);
    }
    if (url === actionStatusUrl(actionId)) {
      statusReads++;
      throw new NodeRoomsError("HTTP_404", "not found", 404);
    }
    throw new Error(`unexpected ${url}`);
  });
  await assert.rejects(() => sdk.createIdempotentGuestPost({
    actionId, fingerprintSha256: fingerprint, roomSlug: "playground", body: "hello"
  }), /reconcile/i);
  assert.equal(posts, 1);
  assert.equal(statusReads, 1);
});

test("different Agent-local Guest entry names remain strictly serialized", async () => {
  const names = ["Queue Alpha", "Queue Beta", "Queue Gamma"];
  const indexByName = new Map(names.map((name, index) => [name, index + 1]));
  const started = [];
  let activeEntries = 0;
  let maxActiveEntries = 0;
  const sdk = createSdk(async (url, init = {}) => {
    assert.equal(url, ENDPOINTS.guestEnter);
    const payload = JSON.parse(init.body);
    const index = indexByName.get(payload.agent_name);
    assert.ok(index);
    started.push(payload.agent_name);
    activeEntries += 1;
    maxActiveEntries = Math.max(maxActiveEntries, activeEntries);
    await new Promise((resolve) => setTimeout(resolve, 20));
    activeEntries -= 1;
    return {
      ...guestEnter(),
      guest_id: `nrog-${String(index).repeat(32)}`,
      guest_pass: `nrguest_${String(index).repeat(64)}`,
      agent_id: index,
      agent_slug: `queue-agent-${index}`,
      agent_name: payload.agent_name,
    };
  });

  const results = await Promise.all(names.map((agentName) =>
    sdk.enter({ agentName })));

  assert.equal(maxActiveEntries, 1);
  assert.deepEqual(started, names);
  assert.deepEqual(
    results.map((result) => result.agent_name),
    names,
  );
});

test("matching Agent-local Guest entry names share one in-flight request", async () => {
  let entryRequests = 0;
  const sdk = createSdk(async (url) => {
    assert.equal(url, ENDPOINTS.guestEnter);
    entryRequests += 1;
    await new Promise((resolve) => setTimeout(resolve, 20));
    return guestEnter();
  });

  const results = await Promise.all(Array.from(
    { length: 3 },
    () => sdk.enter({ agentName: "OpenClaw Guest Agent" }),
  ));

  assert.equal(entryRequests, 1);
  assert.equal(results.length, 3);
  assert.ok(results.every((result) =>
    result.agent_slug === "openclaw-guest-test"));
});

test("secret cleanup cancels active and queued Agent-local Guest entries", async () => {
  let releaseEntry;
  let signalEntryStarted;
  let entryRequests = 0;
  const entryStarted = new Promise((resolve) => {
    signalEntryStarted = resolve;
  });
  const entryReleased = new Promise((resolve) => {
    releaseEntry = resolve;
  });
  const sdk = createSdk(async (url) => {
    assert.equal(url, ENDPOINTS.guestEnter);
    entryRequests += 1;
    signalEntryStarted();
    await entryReleased;
    return guestEnter();
  });

  const active = sdk.enter({ agentName: "Cleanup Alpha" });
  await entryStarted;
  const queued = sdk.enter({ agentName: "Cleanup Beta" });
  const activeRejected = assert.rejects(
    active,
    (error) => error?.code === "GUEST_ENTRY_CANCELLED",
  );
  const queuedRejected = assert.rejects(
    queued,
    (error) => error?.code === "GUEST_ENTRY_CANCELLED",
  );
  sdk.clearSecrets();
  releaseEntry();

  await Promise.all([activeRejected, queuedRejected]);
  assert.equal(entryRequests, 1);
  assert.equal(
    sdk.safeRuntimeState().guest_pass_held_in_memory,
    false,
  );
});
