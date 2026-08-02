import {
    createPublicKey,
    generateKeyPairSync,
    sign,
    verify,
} from "node:crypto";

import {
    canonicalJson,
    sha256Fingerprint,
} from "./passport-runtime-binding.js";

export const GMAIL_TRUSTBRIDGE_RECEIPT_CONTRACT_VERSION =
    "noderooms-gmail-trustbridge-receipt.v1";
export const GMAIL_TRUSTBRIDGE_DEVELOPMENT_IDENTITY =
    "1.4.0-alpha.5-dev.2";

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const RECEIPT_ID_PATTERN = /^nrgmailrcpt_[a-f0-9]{32}$/;
const RESERVATION_ID_PATTERN = /^nrgmailres_[a-f0-9]{32}$/;
const KEY_ID_PATTERN = /^nrgmailkey_[a-f0-9]{24}$/;
const TOOL_NAME_PATTERN = /^gmail_[a-z0-9_]{3,96}$/;
const SCOPE_PATTERN = /^connector\.gmail\.[a-z0-9._-]{3,96}$/;
const ROLE_PATTERN =
    /^(?:passport_bound_gmail_agent|dedicated_mail_reader|owner_reviewed_mail_drafter|owner_reviewed_mail_dispatcher|owner_reviewed_mail_organizer)$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const EMAIL_VALUE_PATTERN =
    /[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
const OPERATIONS = new Set([
    "search",
    "read",
    "draft",
    "send",
    "reply",
    "forward",
    "archive",
    "label",
]);
const OUTCOMES = new Set(["committed", "failed", "unknown"]);

export class GmailTrustBridgeReceiptError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "GmailTrustBridgeReceiptError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new GmailTrustBridgeReceiptError(code, message);
}

function isRecord(value) {
    return Boolean(value)
        && typeof value === "object"
        && !Array.isArray(value);
}

function assertExactKeys(value, required, optional, label) {
    if (!isRecord(value)) {
        fail("GMAIL_RECEIPT_OBJECT_INVALID", `${label} must be an object.`);
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail(
                "GMAIL_RECEIPT_UNKNOWN_FIELD",
                `${label}.${key} is not allowed.`,
            );
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail(
                "GMAIL_RECEIPT_MISSING_FIELD",
                `${label}.${key} is required.`,
            );
        }
    }
}

function assertString(value, pattern, label, maxLength = 512) {
    if (typeof value !== "string"
        || value.length < 1
        || value.length > maxLength
        || (pattern && !pattern.test(value))) {
        fail("GMAIL_RECEIPT_STRING_INVALID", `${label} is invalid.`);
    }
    return value;
}

function assertFingerprint(value, label) {
    return assertString(value, SHA256_PATTERN, label, 71);
}

function assertCanonicalTime(value, label) {
    assertString(value, null, label, 40);
    const milliseconds = Date.parse(value);
    if (!Number.isFinite(milliseconds)
        || new Date(milliseconds).toISOString() !== value) {
        fail(
            "GMAIL_RECEIPT_TIME_INVALID",
            `${label} must be a canonical UTC timestamp.`,
        );
    }
    return milliseconds;
}

function base64url(value) {
    return Buffer.from(value).toString("base64url");
}

function publicJwkThumbprint(publicKeyJwk) {
    return sha256Fingerprint({
        crv: publicKeyJwk.crv,
        kty: publicKeyJwk.kty,
        x: publicKeyJwk.x,
    });
}

function validatePublicJwk(value) {
    assertExactKeys(value, ["kty", "crv", "x"], [], "public_key_jwk");
    if (value.kty !== "OKP" || value.crv !== "Ed25519") {
        fail(
            "GMAIL_RECEIPT_KEY_INVALID",
            "The receipt public key must be Ed25519.",
        );
    }
    assertString(
        value.x,
        /^[A-Za-z0-9_-]{43}$/,
        "public_key_jwk.x",
        43,
    );
    return value;
}

export function validateGmailTrustBridgeTrustAnchor(value) {
    assertExactKeys(value, [
        "issuer",
        "algorithm",
        "key_id",
        "public_key_jwk",
        "key_thumbprint_sha256",
    ], [], "trust_anchor");
    if (value.issuer !== "noderooms-gmail-trustbridge-alpha5"
        || value.algorithm !== "Ed25519") {
        fail(
            "GMAIL_RECEIPT_TRUST_ANCHOR_INVALID",
            "The receipt trust anchor identity is invalid.",
        );
    }
    assertString(value.key_id, KEY_ID_PATTERN, "trust_anchor.key_id", 35);
    const publicJwk = validatePublicJwk(value.public_key_jwk);
    assertFingerprint(
        value.key_thumbprint_sha256,
        "trust_anchor.key_thumbprint_sha256",
    );
    if (value.key_thumbprint_sha256 !== publicJwkThumbprint(publicJwk)) {
        fail(
            "GMAIL_RECEIPT_TRUST_ANCHOR_INVALID",
            "The receipt trust-anchor thumbprint is invalid.",
        );
    }
    return value;
}

function receiptSignaturePayload(receiptFingerprint) {
    return canonicalJson({
        domain: "noderooms/gmail-trustbridge-receipt/v1",
        receipt_fingerprint_sha256: receiptFingerprint,
    });
}

export function createGmailTrustBridgeReceiptSigner() {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeyJwk = publicKey.export({ format: "jwk" });
    const keyThumbprint = publicJwkThumbprint(publicKeyJwk);
    const keyId = `nrgmailkey_${
        sha256Fingerprint({
            key_thumbprint_sha256: keyThumbprint,
        }).slice(7, 31)
    }`;
    const trustAnchor = Object.freeze({
        issuer: "noderooms-gmail-trustbridge-alpha5",
        algorithm: "Ed25519",
        key_id: keyId,
        public_key_jwk: Object.freeze(publicKeyJwk),
        key_thumbprint_sha256: keyThumbprint,
    });
    validateGmailTrustBridgeTrustAnchor(trustAnchor);
    return Object.freeze({
        trust_anchor: trustAnchor,
        signReceiptFingerprint(receiptFingerprint) {
            assertFingerprint(
                receiptFingerprint,
                "receipt_fingerprint_sha256",
            );
            return base64url(sign(
                null,
                Buffer.from(
                    receiptSignaturePayload(receiptFingerprint),
                    "utf8",
                ),
                privateKey,
            ));
        },
    });
}

function receiptProjection(receipt) {
    const {
        receipt_fingerprint_sha256: _fingerprint,
        attestation: _attestation,
        ...projection
    } = receipt;
    return projection;
}

export function gmailTrustBridgeReceiptFingerprint(receipt) {
    return sha256Fingerprint(receiptProjection(receipt));
}

function receiptId(input) {
    return `nrgmailrcpt_${
        sha256Fingerprint({
            reservation_id: input.reservation_id,
            provider_observation_fingerprint_sha256:
                input.provider_observation_fingerprint_sha256,
            completed_at: input.completed_at,
        }).slice(7, 39)
    }`;
}

function validateReceiptInput(input) {
    assertExactKeys(input, [
        "reservation_id",
        "operation",
        "scope",
        "tool_name",
        "actor_role",
        "agent_id_fingerprint_sha256",
        "account_binding_fingerprint_sha256",
        "target_fingerprint_sha256",
        "payload_fingerprint_sha256",
        "approval_policy",
        "approval_consumed",
        "provider_attempt_count",
        "provider_observation_fingerprint_sha256",
        "outcome_status",
        "started_at",
        "completed_at",
    ], [], "receipt input");
    assertString(
        input.reservation_id,
        RESERVATION_ID_PATTERN,
        "reservation_id",
        43,
    );
    if (!OPERATIONS.has(input.operation)) {
        fail("GMAIL_RECEIPT_OPERATION_INVALID", "operation is invalid.");
    }
    assertString(input.scope, SCOPE_PATTERN, "scope", 128);
    assertString(input.tool_name, TOOL_NAME_PATTERN, "tool_name", 110);
    assertString(input.actor_role, ROLE_PATTERN, "actor_role", 64);
    for (const key of [
        "agent_id_fingerprint_sha256",
        "account_binding_fingerprint_sha256",
        "target_fingerprint_sha256",
        "payload_fingerprint_sha256",
        "provider_observation_fingerprint_sha256",
    ]) {
        assertFingerprint(input[key], key);
    }
    if (!["none", "allow_once"].includes(input.approval_policy)
        || typeof input.approval_consumed !== "boolean"
        || (input.approval_policy === "none"
            && input.approval_consumed !== false)
        || (input.approval_policy === "allow_once"
            && input.approval_consumed !== true)) {
        fail(
            "GMAIL_RECEIPT_APPROVAL_INVALID",
            "The receipt approval binding is invalid.",
        );
    }
    if (input.provider_attempt_count !== 1) {
        fail(
            "GMAIL_RECEIPT_ATTEMPT_INVALID",
            "Exactly one provider attempt record is required.",
        );
    }
    if (!OUTCOMES.has(input.outcome_status)) {
        fail("GMAIL_RECEIPT_OUTCOME_INVALID", "outcome_status is invalid.");
    }
    const startedAt = assertCanonicalTime(input.started_at, "started_at");
    const completedAt = assertCanonicalTime(input.completed_at, "completed_at");
    if (completedAt < startedAt) {
        fail(
            "GMAIL_RECEIPT_TIME_INVALID",
            "Receipt completion predates provider dispatch.",
        );
    }
}

export function buildGmailTrustBridgeReceipt(input, options = {}) {
    validateReceiptInput(input);
    const signer = options.receiptSigner;
    if (!signer
        || typeof signer.signReceiptFingerprint !== "function") {
        fail(
            "GMAIL_RECEIPT_SIGNER_REQUIRED",
            "An external receipt signer is required.",
        );
    }
    const trustAnchor = validateGmailTrustBridgeTrustAnchor(
        signer.trust_anchor,
    );
    const receipt = {
        contract_version: GMAIL_TRUSTBRIDGE_RECEIPT_CONTRACT_VERSION,
        development_identity: GMAIL_TRUSTBRIDGE_DEVELOPMENT_IDENTITY,
        receipt_id: receiptId(input),
        reservation_id: input.reservation_id,
        operation: input.operation,
        scope: input.scope,
        tool_name: input.tool_name,
        actor: {
            role: input.actor_role,
            agent_id_fingerprint_sha256:
                input.agent_id_fingerprint_sha256,
        },
        bindings: {
            account_binding_fingerprint_sha256:
                input.account_binding_fingerprint_sha256,
            target_fingerprint_sha256:
                input.target_fingerprint_sha256,
            payload_fingerprint_sha256:
                input.payload_fingerprint_sha256,
        },
        approval: {
            policy: input.approval_policy,
            consumed: input.approval_consumed,
            human_owner_required: input.approval_policy === "allow_once",
            owner_decision_automated: false,
        },
        dispatch: {
            provider_attempt_count: 1,
            max_provider_attempts: 1,
            automatic_retry_allowed: false,
            automatic_retry_attempted: false,
            exactly_once_effect_claimed: false,
        },
        outcome: {
            status: input.outcome_status,
            provider_observation_fingerprint_sha256:
                input.provider_observation_fingerprint_sha256,
            raw_provider_result_included: false,
        },
        privacy: {
            raw_recipient_included: false,
            raw_subject_included: false,
            raw_body_included: false,
            raw_message_id_included: false,
            raw_thread_id_included: false,
            raw_draft_id_included: false,
            raw_provider_result_included: false,
            provider_credential_included: false,
        },
        started_at: input.started_at,
        completed_at: input.completed_at,
        receipt_fingerprint_sha256: "",
        attestation: {},
    };
    receipt.receipt_fingerprint_sha256 =
        gmailTrustBridgeReceiptFingerprint(receipt);
    receipt.attestation = {
        issuer: trustAnchor.issuer,
        algorithm: trustAnchor.algorithm,
        key_id: trustAnchor.key_id,
        key_thumbprint_sha256: trustAnchor.key_thumbprint_sha256,
        signed_receipt_fingerprint_sha256:
            receipt.receipt_fingerprint_sha256,
        signed_at: input.completed_at,
        signature_base64url: signer.signReceiptFingerprint(
            receipt.receipt_fingerprint_sha256,
        ),
    };
    validateGmailTrustBridgeReceipt(receipt, {
        trustedReceiptAnchor: trustAnchor,
    });
    return Object.freeze(receipt);
}

export function validateGmailTrustBridgeReceipt(receipt, options = {}) {
    assertExactKeys(receipt, [
        "contract_version",
        "development_identity",
        "receipt_id",
        "reservation_id",
        "operation",
        "scope",
        "tool_name",
        "actor",
        "bindings",
        "approval",
        "dispatch",
        "outcome",
        "privacy",
        "started_at",
        "completed_at",
        "receipt_fingerprint_sha256",
        "attestation",
    ], [], "receipt");
    if (receipt.contract_version
            !== GMAIL_TRUSTBRIDGE_RECEIPT_CONTRACT_VERSION
        || receipt.development_identity
            !== GMAIL_TRUSTBRIDGE_DEVELOPMENT_IDENTITY) {
        fail(
            "GMAIL_RECEIPT_CONTRACT_INVALID",
            "The Gmail TrustBridge receipt identity is invalid.",
        );
    }
    assertString(receipt.receipt_id, RECEIPT_ID_PATTERN, "receipt_id", 44);
    validateReceiptInput({
        reservation_id: receipt.reservation_id,
        operation: receipt.operation,
        scope: receipt.scope,
        tool_name: receipt.tool_name,
        actor_role: receipt.actor?.role,
        agent_id_fingerprint_sha256:
            receipt.actor?.agent_id_fingerprint_sha256,
        account_binding_fingerprint_sha256:
            receipt.bindings?.account_binding_fingerprint_sha256,
        target_fingerprint_sha256:
            receipt.bindings?.target_fingerprint_sha256,
        payload_fingerprint_sha256:
            receipt.bindings?.payload_fingerprint_sha256,
        approval_policy: receipt.approval?.policy,
        approval_consumed: receipt.approval?.consumed,
        provider_attempt_count:
            receipt.dispatch?.provider_attempt_count,
        provider_observation_fingerprint_sha256:
            receipt.outcome?.provider_observation_fingerprint_sha256,
        outcome_status: receipt.outcome?.status,
        started_at: receipt.started_at,
        completed_at: receipt.completed_at,
    });
    assertExactKeys(receipt.actor, [
        "role",
        "agent_id_fingerprint_sha256",
    ], [], "actor");
    assertExactKeys(receipt.bindings, [
        "account_binding_fingerprint_sha256",
        "target_fingerprint_sha256",
        "payload_fingerprint_sha256",
    ], [], "bindings");
    assertExactKeys(receipt.approval, [
        "policy",
        "consumed",
        "human_owner_required",
        "owner_decision_automated",
    ], [], "approval");
    if (receipt.approval.human_owner_required
            !== (receipt.approval.policy === "allow_once")
        || receipt.approval.owner_decision_automated !== false) {
        fail(
            "GMAIL_RECEIPT_APPROVAL_INVALID",
            "The human Owner approval claim is invalid.",
        );
    }
    assertExactKeys(receipt.dispatch, [
        "provider_attempt_count",
        "max_provider_attempts",
        "automatic_retry_allowed",
        "automatic_retry_attempted",
        "exactly_once_effect_claimed",
    ], [], "dispatch");
    if (receipt.dispatch.max_provider_attempts !== 1
        || receipt.dispatch.automatic_retry_allowed !== false
        || receipt.dispatch.automatic_retry_attempted !== false
        || receipt.dispatch.exactly_once_effect_claimed !== false) {
        fail(
            "GMAIL_RECEIPT_DISPATCH_INVALID",
            "The at-most-once dispatch claim is invalid.",
        );
    }
    assertExactKeys(receipt.outcome, [
        "status",
        "provider_observation_fingerprint_sha256",
        "raw_provider_result_included",
    ], [], "outcome");
    if (receipt.outcome.raw_provider_result_included !== false) {
        fail(
            "GMAIL_RECEIPT_PRIVACY_INVALID",
            "A raw provider result cannot enter the receipt.",
        );
    }
    assertExactKeys(receipt.privacy, [
        "raw_recipient_included",
        "raw_subject_included",
        "raw_body_included",
        "raw_message_id_included",
        "raw_thread_id_included",
        "raw_draft_id_included",
        "raw_provider_result_included",
        "provider_credential_included",
    ], [], "privacy");
    if (Object.values(receipt.privacy).some((value) => value !== false)) {
        fail(
            "GMAIL_RECEIPT_PRIVACY_INVALID",
            "The receipt privacy boundary is invalid.",
        );
    }
    assertFingerprint(
        receipt.receipt_fingerprint_sha256,
        "receipt_fingerprint_sha256",
    );
    if (receipt.receipt_fingerprint_sha256
            !== gmailTrustBridgeReceiptFingerprint(receipt)) {
        fail(
            "GMAIL_RECEIPT_FINGERPRINT_MISMATCH",
            "The receipt fingerprint has drifted.",
        );
    }
    assertExactKeys(receipt.attestation, [
        "issuer",
        "algorithm",
        "key_id",
        "key_thumbprint_sha256",
        "signed_receipt_fingerprint_sha256",
        "signed_at",
        "signature_base64url",
    ], [], "attestation");
    const trustedAnchor = validateGmailTrustBridgeTrustAnchor(
        options.trustedReceiptAnchor,
    );
    if (receipt.attestation.issuer !== trustedAnchor.issuer
        || receipt.attestation.algorithm !== trustedAnchor.algorithm
        || receipt.attestation.key_id !== trustedAnchor.key_id
        || receipt.attestation.key_thumbprint_sha256
            !== trustedAnchor.key_thumbprint_sha256
        || receipt.attestation.signed_receipt_fingerprint_sha256
            !== receipt.receipt_fingerprint_sha256
        || receipt.attestation.signed_at !== receipt.completed_at) {
        fail(
            "GMAIL_RECEIPT_TRUST_ANCHOR_MISMATCH",
            "The receipt attestation differs from its trusted anchor.",
        );
    }
    assertString(
        receipt.attestation.signature_base64url,
        SIGNATURE_PATTERN,
        "attestation.signature_base64url",
        86,
    );
    let signatureValid = false;
    try {
        signatureValid = verify(
            null,
            Buffer.from(
                receiptSignaturePayload(
                    receipt.receipt_fingerprint_sha256,
                ),
                "utf8",
            ),
            createPublicKey({
                key: trustedAnchor.public_key_jwk,
                format: "jwk",
            }),
            Buffer.from(
                receipt.attestation.signature_base64url,
                "base64url",
            ),
        );
    }
    catch {
        signatureValid = false;
    }
    if (!signatureValid) {
        fail(
            "GMAIL_RECEIPT_SIGNATURE_INVALID",
            "The Gmail receipt Ed25519 signature is invalid.",
        );
    }
    if (EMAIL_VALUE_PATTERN.test(JSON.stringify(receipt))) {
        fail(
            "GMAIL_RECEIPT_RAW_EMAIL_FORBIDDEN",
            "A raw email address entered the privacy-safe receipt.",
        );
    }
    return receipt;
}
