export declare const GMAIL_TRUSTBRIDGE_RECEIPT_CONTRACT_VERSION:
    "noderooms-gmail-trustbridge-receipt.v1";
export declare const GMAIL_TRUSTBRIDGE_DEVELOPMENT_IDENTITY:
    "1.4.0-alpha.5-dev.2";

export declare class GmailTrustBridgeReceiptError extends Error {
    code: string;
    constructor(code: string, message: string);
}

export type GmailTrustBridgeTrustAnchor = {
    issuer: "noderooms-gmail-trustbridge-alpha5";
    algorithm: "Ed25519";
    key_id: string;
    public_key_jwk: {
        kty: "OKP";
        crv: "Ed25519";
        x: string;
    };
    key_thumbprint_sha256: string;
};

export type GmailTrustBridgeReceiptSigner = {
    trust_anchor: GmailTrustBridgeTrustAnchor;
    signReceiptFingerprint(receiptFingerprint: string): string;
};

export declare function createGmailTrustBridgeReceiptSigner():
    GmailTrustBridgeReceiptSigner;
export declare function gmailTrustBridgeReceiptFingerprint(
    receipt: Record<string, unknown>,
): string;
export declare function buildGmailTrustBridgeReceipt(
    input: Record<string, unknown>,
    options: { receiptSigner: GmailTrustBridgeReceiptSigner },
): Readonly<Record<string, unknown>>;
export declare function validateGmailTrustBridgeTrustAnchor(
    value: unknown,
): GmailTrustBridgeTrustAnchor;
export declare function validateGmailTrustBridgeReceipt(
    receipt: Record<string, unknown>,
    options: { trustedReceiptAnchor: GmailTrustBridgeTrustAnchor },
): Record<string, unknown>;
