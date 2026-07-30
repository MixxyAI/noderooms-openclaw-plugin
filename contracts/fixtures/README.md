# Connector contract fixtures

## C001 Connector Beta foundation

`connector-beta.github-reference-foundation-v1.json` is a deterministic,
discovery-only output fixture for development identity
`1.4.0-alpha.1-dev.1`. It reuses the existing exact GitHub Draft PR contract
descriptor to prove the additional owner-version and runtime-inventory
binding. It is `reference_only`, stores no provider credential or raw schema,
and grants no tool or connector authority.

The C001 schema admits future `email`, `discord`, `whatsapp`, and `sms`
families, but this fixture does not claim that any of those providers has been
inventoried or enabled. Each requires a separate exact runtime capture and
policy profile.

## C002 Email Read + Draft

`gmail-read-draft.runtime-tool-descriptor-v1.json` and
`../reference/gmail-read-draft.v1.json` define three exact contract tools:
Gmail search, Gmail thread read, and unsent draft creation. The fixture
contains no real account, mailbox, message, recipient, attachment, draft, or
credential data.

The C002 profile is `contract_only` and
`external_validation_pending`. It must not be represented as a live OpenClaw
runtime capture. Search and read belong only to a restricted reader Agent.
Draft creation requires a distinct drafter, exact recipient resolution, and
one human `allow_once` review. Send, forward, label mutation, archive, and
delete tools are explicitly forbidden.

## C003 Passport Messaging Foundation

`../reference/passport-messaging-routes.v1.json` records separate contract-only
routes for SMS, WhatsApp, Signal, Discord, Microsoft Teams, and Viber. The first
five use documented official OpenClaw package/channel names but still require
an exact installed runtime version, effective dynamic `message` schema,
account, target, provider limit, and live proof capture.

Viber remains `external_adapter_pending` and non-executable because no official
OpenClaw adapter was verified in this capture. Teams grants no Outlook Mail or
Calendar authority. Every route keeps credentials in OpenClaw and requires an
exact Agent Passport, Verified Owner, one-action lease, `allow_once` approval,
at-most-once dispatch, and signed receipt before a future live send.

These files are non-live examples for `NR-OC-TRUST-002A`:

```text
github-draft-pr.run-lease-v2.json
github-draft-pr.external-action-intent-v2.json
github-draft-pr.external-action-receipt-v2.json
```

Every fixture contains `"fixture": true`. A runtime implementation must reject
that marker and must not treat these ids, resources, timestamps, approvals, or
provider references as real.

The fixtures prove cross-layer binding only:

- one Agent, Passport, Owner, runtime, session, run, and channel;
- one registry and policy version;
- one exact connector, tool, input-schema fingerprint, scope, action, and
  resource;
- one human `allow_once` decision;
- one dispatch reservation and at most one provider write attempt;
- no automatic retry after uncertainty;
- read-only reconciliation;
- no exactly-once provider-effect claim;
- no provider credential, run secret, authorization header, raw prompt, raw
  body, or raw provider response.

They do not implement a server endpoint, activate a connector, or enable live
enforcement.

`NR-OC-TRUST-002B` adds:

```text
openclaw-agent-passport.pairing-challenge-v1.json
openclaw-agent-passport.pairing-assertion-v1.json
openclaw-agent-passport.runtime-binding-v1.json
openclaw-agent-passport.runtime-recovery-v1.json
```

The challenge and assertion contain a real, fixture-only Ed25519 public key and
a valid signature over the exact canonical challenge fingerprint. The private
key is not present and is not recoverable from the fixture. Verification still
requires atomic server-side challenge consumption; signature validity alone
does not make a binding live.

The binding fixture is `contract_only` and explicitly prohibits live
enforcement. The recovery fixture preserves the Agent and Passport but revokes
the previous runtime authority and reuses no runtime key, lease, or run secret.

The 002A lease, intent, and receipt fixtures are cross-bound to the exact 002B
binding ID, Gateway, runtime instance, OpenClaw Agent, runtime key thumbprint,
NodeRooms Agent, Passport, and Verified Owner binding.

`NR-OC-TRUST-002C` adds:

```text
github-draft-pr.capability-request-v2.json
github-draft-pr.owner-decision-v2.json
```

The request shows the exact Agent, Passport, Owner, runtime, channel, session,
run, connector, tool-schema fingerprint, action, resource, risk, TTL, action
count, goal, and resource limit that the Owner reviews.

The decision requires a `verified_human_owner` and sets
`decision_automated=false`. The grant cannot exceed the request. The updated
run lease binds both fingerprints, records atomic one-time decision
consumption, and prohibits wildcard authorization, shared leases, shared run
secrets, provider credentials, and automated Owner decisions.

All three records remain fixtures with `live_enforce_allowed=false`.

`NR-OC-TRUST-002D` replaces the provisional intent and receipt shapes with the
strict schema:

```text
canonical-external-action-intent-receipt-v2.schema.json
```

and adds these receipt outcomes:

```text
github-draft-pr.external-action-receipt-v2.json
github-draft-pr.external-action-unknown-receipt-v2.json
github-draft-pr.external-action-reconciled-receipt-v2.json
```

The intent atomically reserves one dispatch. The committed fixture records one
provider response. The unknown fixture proves that a lost response blocks
write replay. The reconciled fixture links that unknown receipt and resolves it
with read-only evidence while the dispatch count remains one.

Every receipt contains a valid fixture-only Ed25519 public key and signature.
The private key is absent. Validation requires the expected public-key
thumbprint as an external trust anchor; the embedded public key is not trusted
by itself.

The audit projection contains only attribution and evidence fingerprints.
Contract-only fixtures are ineligible for live reputation changes and apply a
score delta of zero.

`NR-OC-WORK-003A` adds:

```text
github-draft-pr.work-item-v1.json
github-draft-pr.research-work-receipt-v1.json
github-draft-pr.draft-work-receipt-v1.json
github-draft-pr.task-flow-binding-v1.json
github-draft-pr.workboard-binding-v1.json
```

The NodeRooms work item is canonical. Its Mission ID maps once to one
Workboard card and one managed Task Flow. The fixture shows two completed
tasks with separate leases, receipts, and artifact fingerprints, followed by a
Verified Human Owner wait. The Workboard claim is released and the queued
GitHub write has no lease or receipt.

Public receipt projections include only identifiers, status, timestamps,
artifact count, and safety booleans. Raw prompts, raw results, provider
credentials, claim tokens, and private artifact contents are absent.

The fixtures remain `contract_only` with `live_dispatch_allowed=false`. They do
not enable Workboard, create a live Task Flow, start a child task, dispatch a
connector, publish a package, or modify NodeRooms production.

`NR-OC-CONNECTOR-004A` adds:

```text
github-draft-pr.runtime-tool-descriptor-v1.json
openclaw-tools-catalog.schema-unavailable-v1.json
```

The first is the exact, schema-capable inventory descriptor for
`connector.github.pull_request.draft` and may reach
`covered_contract_only`. The second represents the current OpenClaw
`tools.catalog` gap and must fail closed as `schema_unavailable`.

Neither fixture grants execution authority or performs a connector write.

`NR-OC-CONNECTOR-004B` adds:

```text
noderooms-canonical-policy.trust-anchor-v1.json
github-draft-pr.canonical-policy-bundle-v1.json
github-draft-pr.policy-sync-checkpoint-v1.json
```

The trust anchor is external to the signed bundle and contains only a
fixture-only Ed25519 public key. The private signing key is absent. The bundle
binds the exact canonical origin, validity window, registry fingerprint,
GitHub Draft PR profile, tool name, and runtime owner
`mcp:github`. It is `contract_only`, names no live transport, and grants no
tool or connector authority.

The checkpoint proves monotonic, restart-safe comparison metadata without
storing a schema, signature, raw parameter, result, or credential. Exact
replay is idempotent; rollback, equivocation, sequence gaps, invalid
predecessors, and checkpoint drift fail closed.
