import test from "node:test";
import assert from "node:assert/strict";
import {
  actionHeaders,
  validateActionProtocolStatus,
  validateCanonicalReceipt,
} from "../dist/sdk/action-protocol.js";

const actionId = "nrwi_" + "a".repeat(32);
const fingerprint = "b".repeat(64);
const receiptId = "nrreceipt_" + "c".repeat(32);

function status(overrides = {}) {
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

function receipt(overrides = {}) {
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
    object_id: 197,
    public_url: "https://noderooms.com/noderooms-post/?post_id=197",
    error_code: null,
    error_message: null,
    created_at: "2026-07-22T00:00:00Z",
    updated_at: "2026-07-22T00:00:01Z",
    expires_at: "2026-07-22T02:00:00Z",
    committed_at: "2026-07-22T00:00:01Z",
    ...overrides,
  };
}

test("protocol status passes only with every safety gate", () => {
  assert.equal(validateActionProtocolStatus(status()).protocol_ready, true);
});
for (const key of [
  "protocol_ready", "schema_ready", "routes_ready", "guest_auth_bridge_ready",
  "write_bridge_ready", "canonical_receipts_ready", "server_idempotency_enforced",
  "duplicate_write_prevented", "unknown_outcome_replay_blocked"
]) {
  test(`protocol status rejects missing ${key}`, () => {
    assert.throws(() => validateActionProtocolStatus(status({ [key]: false })), /not fully ready|incomplete|invalid/i);
  });
}
test("protocol rejects exactly_once_effect true", () => {
  assert.throws(() => validateActionProtocolStatus(status({ exactly_once_effect: true })));
});
test("protocol rejects persistence of guest pass", () => {
  assert.throws(() => validateActionProtocolStatus(status({ guest_pass_persisted: true })));
});
test("protocol rejects legacy fallback", () => {
  assert.throws(() => validateActionProtocolStatus(status({ fallback_to_legacy_direct_write: true })));
});
test("action headers bind id and fingerprint", () => {
  assert.deepEqual(actionHeaders(actionId, fingerprint, { Authorization: "Bearer x" }), {
    Authorization: "Bearer x",
    "Idempotency-Key": actionId,
    "X-NodeRooms-Action-Fingerprint": fingerprint,
  });
});
test("committed canonical receipt validates", () => {
  const value = validateCanonicalReceipt(receipt(), { actionId, fingerprintSha256: fingerprint, actionType: "guest_post" });
  assert.equal(value.object_id, 197);
});
test("replayed committed receipt validates", () => {
  assert.equal(validateCanonicalReceipt(receipt({ idempotency_status: "replayed" })).idempotency_status, "replayed");
});
test("failed canonical receipt validates and blocks replay", () => {
  const value = validateCanonicalReceipt(receipt({
    ok: false, action_status: "failed", object_id: null, public_url: null,
    error_code: "ACTION_REJECTED", error_message: "Rejected."
  }));
  assert.equal(value.action_status, "failed");
});
test("processing receipt validates", () => {
  const value = validateCanonicalReceipt(receipt({
    ok: false, action_status: "processing", object_id: null, public_url: null,
    error_code: null, error_message: null
  }));
  assert.equal(value.action_status, "processing");
});
test("receipt rejects dispatch count above one", () => {
  assert.throws(() => validateCanonicalReceipt(receipt({ dispatch_count: 2 })));
});
test("receipt rejects string object id", () => {
  assert.throws(() => validateCanonicalReceipt(receipt({ object_id: "197" })));
});
test("receipt rejects foreign origin", () => {
  assert.throws(() => validateCanonicalReceipt(receipt({ public_url: "https://example.com/post/197" })));
});
test("receipt rejects binding mismatch", () => {
  assert.throws(() => validateCanonicalReceipt(receipt(), { actionId: "nrwi_" + "d".repeat(32) }));
});
