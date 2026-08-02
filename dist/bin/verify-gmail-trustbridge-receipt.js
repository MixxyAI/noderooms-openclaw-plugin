#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
    validateGmailTrustBridgeReceipt,
    validateGmailTrustBridgeTrustAnchor,
} from "../gmail-trustbridge-receipt.js";

export async function verifyGmailTrustBridgeReceiptFiles(
    receiptPath,
    trustAnchorPath,
) {
    const [receipt, trustAnchor] = await Promise.all([
        readFile(path.resolve(receiptPath), "utf8").then(JSON.parse),
        readFile(path.resolve(trustAnchorPath), "utf8").then(JSON.parse),
    ]);
    const validatedAnchor =
        validateGmailTrustBridgeTrustAnchor(trustAnchor);
    const validatedReceipt = validateGmailTrustBridgeReceipt(receipt, {
        trustedReceiptAnchor: validatedAnchor,
    });
    return {
        ok: true,
        contract_version: validatedReceipt.contract_version,
        development_identity: validatedReceipt.development_identity,
        receipt_id: validatedReceipt.receipt_id,
        operation: validatedReceipt.operation,
        outcome_status: validatedReceipt.outcome.status,
        receipt_fingerprint_sha256:
            validatedReceipt.receipt_fingerprint_sha256,
        trusted_key_thumbprint_sha256:
            validatedAnchor.key_thumbprint_sha256,
        signature_verified: true,
        raw_recipient_included: false,
        raw_content_included: false,
        raw_provider_result_included: false,
    };
}

async function main() {
    const [receiptPath, trustAnchorPath] = process.argv.slice(2);
    if (!receiptPath || !trustAnchorPath) {
        throw new Error(
            "Usage: noderooms-verify-gmail-receipt <receipt.json> <trust-anchor.json>",
        );
    }
    const result = await verifyGmailTrustBridgeReceiptFiles(
        receiptPath,
        trustAnchorPath,
    );
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.stdout.write(
        "NR_GMAIL_TRUSTBRIDGE_RECEIPT_VERIFY=PASS\n",
    );
}

const invokedPath = process.argv[1]
    ? pathToFileURL(path.resolve(process.argv[1])).href
    : "";
if (import.meta.url === invokedPath) {
    main().catch((error) => {
        process.stderr.write(
            `NR_GMAIL_TRUSTBRIDGE_RECEIPT_VERIFY=FAIL ${
                error?.code ?? "UNEXPECTED_ERROR"
            }\n`,
        );
        process.exitCode = 1;
    });
}
