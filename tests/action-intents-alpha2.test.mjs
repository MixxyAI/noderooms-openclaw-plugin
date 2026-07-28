import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { ActionIntentStore } from "../dist/action-intents.js";
import { NodeRoomsError } from "../dist/contracts.js";

const ownerPrepare = {
  agentId: "main",
  channel: "discord",
  requesterSenderId: "841060426409705475",
};
const ownerCommand = {
  agentId: "main",
  channel: "discord",
  senderId: "841060426409705475",
  senderIsOwner: true,
  isAuthorizedSender: true,
};
function receipt(intent, status = "committed") {
  return {
    ok: status === "committed",
    protocol_version: "noderooms-action-idempotency-v1",
    action_id: intent.id,
    receipt_id: "nrreceipt_" + "a".repeat(32),
    action_type: intent.kind,
    action_status: status,
    idempotency_status: "created",
    fingerprint_sha256: intent.fingerprint,
    server_idempotency_enforced: true,
    duplicate_write_prevented: true,
    unknown_outcome_replay_blocked: true,
    replay_blocked: status !== "processing",
    public_write_attempted: true,
    dispatch_count: 1,
    exactly_once_effect: false,
    object_id: status === "committed" ? 301 : null,
    public_url: status === "committed" ? "https://noderooms.com/noderooms-post/?post_id=301" : null,
    error_code: status === "failed" ? "ACTION_REJECTED" : null,
    error_message: status === "failed" ? "Rejected." : null,
    created_at: "2026-07-22T00:00:00Z",
    updated_at: "2026-07-22T00:00:01Z",
    expires_at: "2026-07-22T02:00:00Z",
    committed_at: status === "committed" ? "2026-07-22T00:00:01Z" : null,
  };
}
async function fixture(t) {
  const dir = await mkdtemp(path.join(tmpdir(), "nr-alpha2-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return {
    path: path.join(dir, "action-intents-v1.json"),
    store: new ActionIntentStore({ stateFilePath: path.join(dir, "action-intents-v1.json") }),
  };
}

test("prepare creates a restart-safe intent without executing a write", async (t) => {
  const { store } = await fixture(t);
  const value = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "hello" }, ownerPrepare);
  assert.equal(value.write_intent_prepared, true);
  assert.match(value.intent_id, /^nrwi_[a-f0-9]{32}$/);
});

test("committed receipt seals the intent and replay does not execute again", async (t) => {
  const { store } = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "hello" }, ownerPrepare);
  let calls = 0;
  const first = await store.commit(prepared.intent_id, ownerCommand, async (intent) => {
    calls++;
    return receipt(intent);
  });
  const replay = await store.commit(prepared.intent_id, ownerCommand, async () => {
    calls++;
    throw new Error("must not run");
  });
  assert.equal(first.committed, true);
  assert.equal(replay.already_committed, true);
  assert.equal(calls, 1);
});

test("canonical failure is terminal and blocks redispatch", async (t) => {
  const { store } = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "hello" }, ownerPrepare);
  let calls = 0;
  const first = await store.commit(prepared.intent_id, ownerCommand, async (intent) => {
    calls++;
    return receipt(intent, "failed");
  });
  const replay = await store.commit(prepared.intent_id, ownerCommand, async () => {
    calls++;
    return {};
  });
  assert.equal(first.failed, true);
  assert.equal(replay.already_failed, true);
  assert.equal(calls, 1);
});

test("pre-dispatch failure restores prepared state", async (t) => {
  const { store } = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "hello" }, ownerPrepare);
  const error = new NodeRoomsError("ACTION_PROTOCOL_NOT_READY", "not ready");
  error.publicWriteAttempted = false;
  await assert.rejects(() => store.commit(prepared.intent_id, ownerCommand, async () => { throw error; }), /remains prepared/i);
  const second = await store.commit(prepared.intent_id, ownerCommand, async (intent) => receipt(intent));
  assert.equal(second.committed, true);
});

test("uncertain failure seals intent until read-only reconcile", async (t) => {
  const { store } = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "hello" }, ownerPrepare);
  await assert.rejects(() => store.commit(prepared.intent_id, ownerCommand, async () => {
    throw new NodeRoomsError("ACTION_OUTCOME_UNKNOWN", "unknown");
  }), /reconcile/i);
  await assert.rejects(() => store.commit(prepared.intent_id, ownerCommand, async () => ({})), /unknown/);
  const reconciled = await store.reconcile(prepared.intent_id, ownerCommand, async (intent) => receipt(intent));
  assert.equal(reconciled.ok, true);
  assert.equal(reconciled.result.action_status, "committed");
});

test("intent survives a new store instance", async (t) => {
  const { path: statePath, store } = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_comment", postId: 197, body: "hello" }, ownerPrepare);
  const replacement = new ActionIntentStore({ stateFilePath: statePath });
  const result = await replacement.commit(prepared.intent_id, ownerCommand, async (intent) => receipt(intent));
  assert.equal(result.committed, true);
});

test("another sender cannot commit the intent", async (t) => {
  const { store } = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "hello" }, ownerPrepare);
  await assert.rejects(() => store.commit(prepared.intent_id, {
    ...ownerCommand, senderId: "other"
  }, async () => ({})), /same verified Owner/i);
});

test("missing Agent context cannot resolve a side-effect intent", async (t) => {
  const { store } = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "hello" }, ownerPrepare);
  await assert.rejects(() => store.commit(prepared.intent_id, {
    channel: ownerCommand.channel,
    senderId: ownerCommand.senderId,
    senderIsOwner: true,
    isAuthorizedSender: true,
  }, async () => ({})), /another OpenClaw Agent/i);
});

test("deny is terminal and performs no executor", async (t) => {
  const { store } = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "hello" }, ownerPrepare);
  const denied = await store.deny(prepared.intent_id, ownerCommand);
  assert.equal(denied.denied, true);
  await assert.rejects(() => store.commit(prepared.intent_id, ownerCommand, async () => ({})), /denied/);
});


test("two concurrent commits across store instances execute exactly once", async (t) => {
  const { path: statePath, store } = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "concurrent" }, ownerPrepare);
  const secondStore = new ActionIntentStore({ stateFilePath: statePath });
  let calls = 0;
  const executor = async (intent) => {
    calls++;
    await new Promise((resolve) => setTimeout(resolve, 75));
    return receipt(intent);
  };
  const results = await Promise.allSettled([
    store.commit(prepared.intent_id, ownerCommand, executor),
    secondStore.commit(prepared.intent_id, ownerCommand, executor),
  ]);
  assert.equal(calls, 1);
  assert.equal(results.filter((entry) => entry.status === "fulfilled").length, 1);
  assert.equal(results.filter((entry) => entry.status === "rejected").length, 1);
  assert.match(results.find((entry) => entry.status === "rejected").reason.message, /committing|cannot be committed/i);
  const replay = await secondStore.commit(prepared.intent_id, ownerCommand, async () => {
    calls++;
    throw new Error("must not execute");
  });
  assert.equal(replay.already_committed, true);
  assert.equal(calls, 1);
});

test("canonical result format is inferred and persisted while keeping the rollback-compatible version 1 store", async (t) => {
  const { path: statePath, store } = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "migrate" }, ownerPrepare);
  await store.commit(prepared.intent_id, ownerCommand, async (intent) => receipt(intent));
  const document = JSON.parse(await readFile(statePath, "utf8"));
  assert.equal(document.version, 1);
  delete document.intents[0].resultFormat;
  await writeFile(statePath, JSON.stringify(document, null, 2) + "\n", "utf8");
  const replacement = new ActionIntentStore({ stateFilePath: statePath });
  const replay = await replacement.commit(prepared.intent_id, ownerCommand, async () => {
    throw new Error("must not execute");
  });
  assert.equal(replay.already_committed, true);
  const migrated = JSON.parse(await readFile(statePath, "utf8"));
  assert.equal(migrated.version, 1);
  assert.equal(migrated.intents[0].resultFormat, "canonical-v1");
});

test("legacy noncanonical terminal receipt remains readable but cannot cause redispatch", async (t) => {
  const { path: statePath } = await fixture(t);
  const createdAtMs = Date.now();
  const payload = { kind: "guest_post", roomSlug: "playground", body: "legacy" };
  const crypto = await import("node:crypto");
  const canonicalJson = (value) => Array.isArray(value)
    ? `[${value.map(canonicalJson).join(",")}]`
    : (value && typeof value === "object"
      ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`
      : JSON.stringify(value));
  const fingerprint = crypto.createHash("sha256").update(canonicalJson(payload)).digest("hex");
  const intentId = "nrwi_" + "e".repeat(32);
  await writeFile(statePath, JSON.stringify({
    version: 1,
    intents: [{
      id: intentId,
      kind: "guest_post",
      payload,
      owner: ownerPrepare,
      state: "committed",
      fingerprint,
      createdAtMs,
      expiresAtMs: createdAtMs + 7_200_000,
      result: { ok: true, post_created: true, post_id: 197 },
    }],
  }, null, 2) + "\n", "utf8");
  const replacement = new ActionIntentStore({ stateFilePath: statePath });
  let calls = 0;
  const replay = await replacement.commit(intentId, ownerCommand, async () => {
    calls++;
    return {};
  });
  assert.equal(replay.already_committed, true);
  assert.equal(calls, 0);
  const migrated = JSON.parse(await readFile(statePath, "utf8"));
  assert.equal(migrated.version, 1);
  assert.equal(migrated.intents[0].resultFormat, "legacy-v1");
});

test("tampered persisted canonical receipt is rejected before local replay", async (t) => {
  const { path: statePath, store } = await fixture(t);
  const prepared = await store.prepare({ kind: "guest_post", roomSlug: "playground", body: "tamper" }, ownerPrepare);
  await store.commit(prepared.intent_id, ownerCommand, async (intent) => receipt(intent));
  const document = JSON.parse(await readFile(statePath, "utf8"));
  document.intents[0].result.object_id = "301";
  await writeFile(statePath, JSON.stringify(document, null, 2) + "\n", "utf8");
  const replacement = new ActionIntentStore({ stateFilePath: statePath });
  await assert.rejects(
    () => replacement.commit(prepared.intent_id, ownerCommand, async () => ({})),
    /invalid object_id|canonical receipt/i,
  );
});
