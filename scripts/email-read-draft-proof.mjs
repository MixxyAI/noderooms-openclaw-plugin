import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import {
    buildEmailReadDraftProfileV1,
    validateEmailReadDraftProfileV1,
} from "../src/email-read-draft-profile.js";
import { sha256Fingerprint } from "../src/passport-runtime-binding.js";
import {
    buildRuntimeToolInventoryV1,
} from "../src/universal-connector-engine.js";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

export async function buildEmailReadDraftProof() {
    const [descriptor, registry] = await Promise.all([
        readJson(
            "contracts/fixtures/"
            + "gmail-read-draft.runtime-tool-descriptor-v1.json",
        ),
        readJson("contracts/reference/gmail-read-draft.v1.json"),
    ]);
    const inventory = buildRuntimeToolInventoryV1({
        captured_at: descriptor.captured_at,
        refresh_reason: descriptor.refresh_reason,
        inventory_generation: descriptor.inventory_generation,
        source: descriptor.source,
        tools: descriptor.tools,
        registry,
    });
    const profile = validateEmailReadDraftProfileV1(
        buildEmailReadDraftProfileV1({
            profile_id: "nrc002_gmail_read_draft_001",
            captured_at: "2026-07-30T13:21:00Z",
            inventory_snapshot: inventory,
            owner_version: "0.1.5",
            version_source: "contract_fixture",
            account_binding_fingerprint_sha256: sha256Fingerprint({
                provider: "gmail",
                account_ref: "fixture-account-001",
            }),
            reader_agent_id: "mail_reader",
            drafter_agent_id: "mail_drafter",
        }),
    );

    return Object.freeze({
        contract_version: "noderooms-email-read-draft-proof-v1",
        proof_time: "2026-07-30T13:22:00Z",
        development_identity: profile.development_identity,
        status: profile.activation_state,
        runtime_validation_status: profile.runtime_validation_status,
        connector: Object.freeze({
            provider: profile.connector.provider,
            connector_id: profile.connector.connector_id,
            connector_version: profile.connector.connector_version,
            owner_id: profile.connector.owner.owner_id,
            credential_custodian:
                profile.connector.credential_custodian,
            provider_credentials_stored:
                profile.connector.noderooms_stores_provider_credentials,
        }),
        inventory: Object.freeze({
            inventory_tool_count:
                profile.inventory_binding.inventory_tool_count,
            schema_verified_tool_count:
                profile.inventory_binding.schema_verified_tool_count,
            unclassified_tool_count:
                profile.inventory_binding.unclassified_tool_count,
            drifted_tool_count:
                profile.inventory_binding.drifted_tool_count,
            inventory_snapshot_fingerprint_sha256:
                profile.inventory_binding
                    .inventory_snapshot_fingerprint_sha256,
        }),
        reader: Object.freeze({
            isolated_agent: true,
            input_trust: profile.reader.input_trust,
            sandbox_mode: profile.reader.sandbox_mode,
            workspace_access: profile.reader.workspace_access,
            tool_names: profile.reader.allowed_tool_names,
            summary_only_handoff:
                profile.reader.handoff_policy === "summary_only",
        }),
        draft: Object.freeze({
            tool_name: profile.drafter.tool.tool_name,
            mailbox_effect: profile.drafter.mailbox_effect,
            exact_recipient_resolution_required:
                profile.drafter.exact_recipient_resolution_required,
            automatic_recipient_selection_allowed:
                profile.drafter.automatic_recipient_selection_allowed,
            human_owner_review_required:
                profile.drafter.human_owner_review_required,
            approval_policy: profile.drafter.approval_policy,
            send_capability_present:
                profile.drafter.send_capability_present,
        }),
        safety: profile.safety,
        profile_fingerprint_sha256:
            profile.profile_fingerprint_sha256,
        closure: Object.freeze({
            c002_contract_acceptance: "pass",
            live_mailbox_read_enabled: false,
            live_draft_creation_enabled: false,
            email_send_enabled: false,
            external_openclaw_validation_pending: true,
            c003_messaging_runtime_enabled: false,
            c004_provider_write_enabled: false,
        }),
    });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    process.stdout.write(
        `${JSON.stringify(await buildEmailReadDraftProof(), null, 2)}\n`,
    );
}
