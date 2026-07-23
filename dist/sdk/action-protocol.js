import { NodeRoomsError, NODEROOMS_ORIGIN } from "../contracts.js";
import { positiveInteger } from "./validation.js";

export const ACTION_PROTOCOL_VERSION = "noderooms-action-idempotency-v1";
export const ACTION_ID_PATTERN = /^nrwi_[a-f0-9]{32}$/;
export const RECEIPT_ID_PATTERN = /^nrreceipt_[a-f0-9]{32}$/;
export const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;
export const ACTION_STATUSES = Object.freeze(["committed", "failed", "processing", "unknown"]);
export const IDEMPOTENCY_STATUSES = Object.freeze(["created", "replayed"]);

function record(value, code, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new NodeRoomsError(code, message);
  }
  return value;
}

function requiredString(value, key, pattern, code) {
  const candidate = value[key];
  if (typeof candidate !== "string" || !pattern.test(candidate)) {
    throw new NodeRoomsError(code, `NodeRooms returned an invalid ${key}.`);
  }
  return candidate;
}

function requiredBoolean(value, key, expected, code) {
  if (value[key] !== expected) {
    throw new NodeRoomsError(code, `NodeRooms returned an unsafe ${key} contract.`);
  }
  return expected;
}

function optionalIso(value, key) {
  const candidate = value[key];
  if (candidate === null || candidate === undefined) return null;
  if (typeof candidate !== "string" || Number.isNaN(Date.parse(candidate))) {
    throw new NodeRoomsError("ACTION_RECEIPT_INVALID", `NodeRooms returned an invalid ${key}.`);
  }
  return candidate;
}

function pinnedPublicUrl(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") {
    throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "NodeRooms returned an invalid public_url.");
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "NodeRooms returned an invalid public_url.");
  }
  if (parsed.protocol !== "https:" || parsed.origin !== NODEROOMS_ORIGIN || parsed.username || parsed.password || (parsed.port && parsed.port !== "443")) {
    throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "NodeRooms returned a public_url outside the official HTTPS origin.");
  }
  return parsed.toString();
}

export function assertActionIdentity(actionId, fingerprintSha256) {
  if (typeof actionId !== "string" || !ACTION_ID_PATTERN.test(actionId)) {
    throw new NodeRoomsError("INVALID_ACTION_ID", "The NodeRooms action id is invalid.");
  }
  if (typeof fingerprintSha256 !== "string" || !FINGERPRINT_PATTERN.test(fingerprintSha256)) {
    throw new NodeRoomsError("INVALID_ACTION_FINGERPRINT", "The NodeRooms action fingerprint is invalid.");
  }
  return { actionId, fingerprintSha256 };
}

export function actionHeaders(actionId, fingerprintSha256, existing = {}) {
  assertActionIdentity(actionId, fingerprintSha256);
  return {
    ...existing,
    "Idempotency-Key": actionId,
    "X-NodeRooms-Action-Fingerprint": fingerprintSha256,
  };
}

export function validateActionProtocolStatus(value) {
  const status = record(value, "ACTION_PROTOCOL_STATUS_INVALID", "NodeRooms returned an invalid action protocol status.");
  const actionTypes = status.action_types;
  if (!Array.isArray(actionTypes) || actionTypes.length !== 2 || !actionTypes.includes("guest_post") || !actionTypes.includes("guest_comment")) {
    throw new NodeRoomsError("ACTION_PROTOCOL_STATUS_INVALID", "NodeRooms action types are incomplete.");
  }
  const ready = status.ok === true
    && status.protocol_ready === true
    && status.schema_ready === true
    && status.routes_ready === true
    && status.guest_auth_bridge_ready === true
    && status.write_bridge_ready === true
    && status.canonical_receipts_ready === true
    && status.server_idempotency_enforced === true
    && status.duplicate_write_prevented === true
    && status.unknown_outcome_replay_blocked === true
    && status.exactly_once_effect === false
    && status.guest_pass_persisted === false
    && status.payload_persisted === false
    && status.fallback_to_legacy_direct_write === false
    && status.protocol_version === ACTION_PROTOCOL_VERSION;

  if (!ready) {
    throw new NodeRoomsError("ACTION_PROTOCOL_NOT_READY", "NodeRooms server-side idempotency and canonical receipts are not fully ready. No public write was attempted.");
  }

  return {
    ok: true,
    protocol_ready: true,
    protocol_version: ACTION_PROTOCOL_VERSION,
    gateway: typeof status.gateway === "string" ? status.gateway : "noderooms_action_idempotency",
    version: typeof status.version === "string" ? status.version : null,
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
    reservation_ttl_seconds: positiveInteger(status.reservation_ttl_seconds, "reservation_ttl_seconds"),
    processing_stale_seconds: positiveInteger(status.processing_stale_seconds, "processing_stale_seconds"),
    idempotency_retention_days: positiveInteger(status.idempotency_retention_days, "idempotency_retention_days"),
    credentials_required_for_status: status.credentials_required_for_status === true,
    guest_pass_persisted: false,
    payload_persisted: false,
    fallback_to_legacy_direct_write: false,
  };
}

export function validateCanonicalReceipt(value, expected = {}) {
  const receipt = record(value, "ACTION_RECEIPT_INVALID", "NodeRooms returned an invalid canonical receipt.");
  const actionId = requiredString(receipt, "action_id", ACTION_ID_PATTERN, "ACTION_RECEIPT_INVALID");
  const receiptId = requiredString(receipt, "receipt_id", RECEIPT_ID_PATTERN, "ACTION_RECEIPT_INVALID");
  const fingerprint = requiredString(receipt, "fingerprint_sha256", FINGERPRINT_PATTERN, "ACTION_RECEIPT_INVALID");
  const actionType = receipt.action_type;
  if (actionType !== "guest_post" && actionType !== "guest_comment") {
    throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "NodeRooms returned an unsupported action_type.");
  }
  const actionStatus = receipt.action_status;
  if (!ACTION_STATUSES.includes(actionStatus)) {
    throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "NodeRooms returned an invalid action_status.");
  }
  const idempotencyStatus = receipt.idempotency_status;
  if (!IDEMPOTENCY_STATUSES.includes(idempotencyStatus)) {
    throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "NodeRooms returned an invalid idempotency_status.");
  }

  if (expected.actionId !== undefined && actionId !== expected.actionId) {
    throw new NodeRoomsError("ACTION_RECEIPT_BINDING_MISMATCH", "The canonical receipt belongs to another action id.");
  }
  if (expected.fingerprintSha256 !== undefined && fingerprint !== expected.fingerprintSha256) {
    throw new NodeRoomsError("ACTION_RECEIPT_BINDING_MISMATCH", "The canonical receipt fingerprint does not match the prepared action.");
  }
  if (expected.actionType !== undefined && actionType !== expected.actionType) {
    throw new NodeRoomsError("ACTION_RECEIPT_BINDING_MISMATCH", "The canonical receipt action type does not match the prepared action.");
  }

  if (receipt.protocol_version !== ACTION_PROTOCOL_VERSION) {
    throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "NodeRooms returned an unsupported action protocol version.");
  }
  requiredBoolean(receipt, "server_idempotency_enforced", true, "ACTION_RECEIPT_INVALID");
  requiredBoolean(receipt, "duplicate_write_prevented", true, "ACTION_RECEIPT_INVALID");
  requiredBoolean(receipt, "unknown_outcome_replay_blocked", true, "ACTION_RECEIPT_INVALID");
  requiredBoolean(receipt, "exactly_once_effect", false, "ACTION_RECEIPT_INVALID");

  const dispatchCount = receipt.dispatch_count;
  if (!Number.isSafeInteger(dispatchCount) || dispatchCount < 0 || dispatchCount > 1) {
    throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "NodeRooms returned an unsafe dispatch_count.");
  }

  const publicWriteAttempted = receipt.public_write_attempted === true;
  const replayBlocked = receipt.replay_blocked === true;
  let objectId = null;
  if (receipt.object_id !== null && receipt.object_id !== undefined) {
    if (!Number.isSafeInteger(receipt.object_id) || receipt.object_id < 1) {
      throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "NodeRooms returned an invalid object_id.");
    }
    objectId = receipt.object_id;
  }
  const publicUrl = pinnedPublicUrl(receipt.public_url);

  if (actionStatus === "committed") {
    if (receipt.ok !== true || !publicWriteAttempted || !replayBlocked || dispatchCount !== 1 || objectId === null || publicUrl === null) {
      throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "The committed canonical receipt is incomplete.");
    }
  } else {
    if (receipt.ok === true) {
      throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "A non-committed canonical receipt cannot be ok.");
    }
    if ((actionStatus === "failed" || actionStatus === "unknown") && !replayBlocked) {
      throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "A terminal canonical receipt must block replay.");
    }
  }

  const errorCode = receipt.error_code === null || receipt.error_code === undefined
    ? null
    : (typeof receipt.error_code === "string" && /^[A-Z0-9_:-]{1,128}$/.test(receipt.error_code)
      ? receipt.error_code
      : (() => { throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "NodeRooms returned an invalid error_code."); })());
  const errorMessage = receipt.error_message === null || receipt.error_message === undefined
    ? null
    : (typeof receipt.error_message === "string" && receipt.error_message.length <= 512
      ? receipt.error_message
      : (() => { throw new NodeRoomsError("ACTION_RECEIPT_INVALID", "NodeRooms returned an invalid error_message."); })());

  return {
    ok: actionStatus === "committed",
    protocol_version: ACTION_PROTOCOL_VERSION,
    action_id: actionId,
    receipt_id: receiptId,
    action_type: actionType,
    action_status: actionStatus,
    idempotency_status: idempotencyStatus,
    fingerprint_sha256: fingerprint,
    server_idempotency_enforced: true,
    duplicate_write_prevented: true,
    unknown_outcome_replay_blocked: true,
    replay_blocked: replayBlocked,
    public_write_attempted: publicWriteAttempted,
    dispatch_count: dispatchCount,
    exactly_once_effect: false,
    object_id: objectId,
    public_url: publicUrl,
    error_code: errorCode,
    error_message: errorMessage,
    created_at: optionalIso(receipt, "created_at"),
    updated_at: optionalIso(receipt, "updated_at"),
    expires_at: optionalIso(receipt, "expires_at"),
    committed_at: optionalIso(receipt, "committed_at"),
  };
}

export function actionOutcomeFromReceipt(receipt) {
  const validated = validateCanonicalReceipt(receipt);
  return {
    __noderooms_action_outcome: true,
    outcome: validated.action_status,
    public_write_attempted: validated.public_write_attempted,
    canonical_receipt: validated,
  };
}
