import { readFile } from "node:fs/promises";

import {
    buildPassportMessagingProfileV1,
    validatePassportMessagingProfileV1,
} from "../src/passport-messaging-profile.js";

const readJson = async (relativePath) => JSON.parse(await readFile(
    new URL(`../${relativePath}`, import.meta.url),
    "utf8",
));

export async function buildPassportMessagingProof() {
    const routeRegistry = await readJson(
        "contracts/reference/passport-messaging-routes.v1.json",
    );
    const profile = validatePassportMessagingProfileV1(
        buildPassportMessagingProfileV1({
            profile_id: "nrc003_passport_messaging_001",
            captured_at: "2026-07-30T15:10:00Z",
            openclaw_version: "2026.7.1-2",
            message_tool_name: "message",
            message_tool_schema_status:
                "narrowed_projection_runtime_capture_pending",
            route_registry: routeRegistry,
            agent_id: "passport_messaging_agent",
        }),
    );
    return Object.freeze({
        proof_version: "noderooms-passport-messaging-proof-v1",
        development_identity: profile.development_identity,
        status: profile.activation_state,
        runtime_validation_status: profile.runtime_validation_status,
        official_channels: profile.routes
            .filter((route) => route.owner.resolution === "exact_name_only")
            .map((route) => route.channel_id),
        pending_external_channels: profile.routes
            .filter((route) => route.owner.resolution === "unresolved")
            .map((route) => route.channel_id),
        passport: Object.freeze({
            verified_owner_required:
                profile.passport_gate.verified_human_owner_required,
            verified_passport_required:
                profile.passport_gate.verified_agent_passport_required,
            per_agent_lease_required:
                profile.passport_gate.per_agent_run_lease_required,
            max_actions_per_lease:
                profile.passport_gate.max_actions_per_lease,
        }),
        dispatch: Object.freeze({
            approval_policy: profile.outbound_dispatch.approval_policy,
            replay_semantics: profile.outbound_dispatch.replay_semantics,
            dispatch_attempt_ceiling:
                profile.outbound_dispatch.dispatch_attempt_ceiling,
            automatic_retry_allowed:
                profile.outbound_dispatch.automatic_retry_allowed,
        }),
        receipt: profile.receipt,
        safety: profile.safety,
        closure: Object.freeze({
            c003_contract_acceptance: "pass",
            external_openclaw_validation_pending: true,
            laptop_provider_login_pending: true,
        }),
    });
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
    console.log(JSON.stringify(await buildPassportMessagingProof(), null, 2));
    console.log("NR_OC_CONNECTOR_BETA_C003=PASS");
}
