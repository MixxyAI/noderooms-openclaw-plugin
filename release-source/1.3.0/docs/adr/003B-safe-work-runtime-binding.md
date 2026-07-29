# ADR 003B: Safe Workdesk runtime binding

Status: proposed, shadow-only
Date: 2026-07-24
Base: `98daacaaa9deea2a543f76d8b4e89adf0e0b516c`

## Decision

Phase 3 runtime wiring begins with one disabled-by-default local shadow edge:

```text
canonical NodeRooms work item
  -> waiting managed Task Flow
  -> exact guarded Workboard review-card create
```

The only active mode in this round is `shadow`. The effective default is
`off`. `armed` activation is hard-blocked and cannot be selected by the plugin
manifest.

Shadow mode may create local review metadata. It cannot grant authority,
approve the Owner gate, start a Task Run, claim or dispatch Workboard work,
resume a Task Flow, invoke a connector, perform an external write, or update
NodeRooms production state.

## Host compatibility decision

The OpenClaw 2026.7.1-2 SDK provides two relevant public surfaces:

- `api.runtime.tasks.managedFlows`, which can create a revisioned managed Task
  Flow bound to the trusted tool context;
- the optional bundled Workboard agent tool `workboard_create`, which provides
  local-card idempotency.

Community plugins must not depend on the bundled-plugin-only
`api.runtime.gateway.request` cross-plugin RPC path. NodeRooms therefore uses
the public managed Task Flow API directly and prepares one exact Workboard
agent-tool call. A late `before_tool_call` guard validates the final parameters
before the call reaches Workboard.

The bundled Workboard plugin remains disabled unless the Owner separately
enables it. If `workboard_create` is unavailable, no card is created and the
binding remains safely incomplete.

References inspected from the pinned development dependency:

- `openclaw/docs/plugins/workboard.md`
- `openclaw/docs/automation/taskflow.md`
- `openclaw/docs/plugins/sdk-runtime.md`
- `openclaw/dist/types-*.d.ts`
- `openclaw/dist/extensions/workboard/index.js`

## Exact admission gate

`noderooms_prepare_work_binding` accepts one JSON-encoded
`noderooms-work-item-v1` only when all of these are true:

1. `workRuntime.mode` is `shadow`;
2. the caller is the trusted authenticated human Owner;
3. the work item is not a fixture and is not expired;
4. the strict 003A contract validates;
5. workflow state is `waiting_owner_review` at the exact Owner-review step;
6. OpenClaw Agent ID, session fingerprint, and requester-origin fingerprint
   match the host-supplied tool context;
7. `live_dispatch_allowed` and every automatic authority path remain false.

The bridge never accepts a session key, Owner sender ID, board ID, card
status, idempotency key, or Task Flow revision from model-controlled tool
arguments. The host context, canonical work item, and static plugin
configuration supply them.

## Managed Task Flow

The bridge calls `createManaged` once with:

- controller `noderooms/workdesk-shadow-v1`;
- status `waiting`;
- current step equal to the canonical Owner-review step;
- silent notification policy;
- bounded state containing only IDs, revisions, fingerprints, and false
  authority flags;
- an Owner-review wait record that prohibits automatic decisions.

It does not call `runTask`, `resume`, `finish`, or any scheduler. A
deterministic local reservation is written before creation. If the process
stops between reservation and result persistence, the state becomes
reconciliation-only and Task Flow creation is not retried automatically.

## Workboard create guard

The expected card is fixed to:

- status `review`;
- priority `high`;
- labels `noderooms`, `owner-review`, and `shadow-runtime`;
- exact Agent ID, tenant, board ID, and deterministic idempotency key;
- canonical title and bounded ID/fingerprint notes;
- no parent, claim token, schedule, workspace, run, retry, or dispatch field.

The final NodeRooms hook runs after normal policy hooks. It allows only a
byte-equivalent canonical parameter object bound to the same Agent and
session. The hook marks the reservation in-flight before Workboard executes.

The result must contain the exact unclaimed review card with matching
automation metadata. Only card ID and status are retained. Raw tool results,
claim tokens, prompts, session keys, Owner sender IDs, credentials, and
private artifacts are never persisted.

## Uncertain outcomes and restart

Any error, opaque result, result drift, interrupted in-flight state, or
unexpected card becomes `reconcile_required`. No automatic
`workboard_create` retry is permitted, even though the Workboard idempotency
key is stable.

`/noderooms work reconcile <binding_id>` reads the managed Task Flow and
returns instructions for a read-only Workboard lookup. It does not mutate the
journal, Task Flow, or card.

`/noderooms work cancel <binding_id>` is a separate authenticated Owner
command. It uses the current Task Flow revision for one sticky
`requestCancel` mutation and blocks any later NodeRooms card creation. It does
not dispatch, claim, or externally write.

## Acceptance gates

```text
DEFAULT_OFF=PASS
ARMED_ACTIVATION=BLOCKED
OWNER_AND_RUNTIME_BINDING=PASS
FIXTURE_OR_EXPIRED_WORK_ITEM=BLOCKED
WAITING_TASK_FLOW_ONLY=PASS
WORKBOARD_PARAMETER_DRIFT=BLOCKED
ONE_REVIEW_CARD_AT_MOST=PASS
UNKNOWN_CREATE_RETRY=BLOCKED
RESTART_RECONCILE_READ_ONLY=PASS
OWNER_CANCEL_REVISION_GATE=PASS
RAW_CONTEXT_PERSISTENCE=BLOCKED
TASK_RUN_CONNECTOR_EXTERNAL_WRITE=NOT_ATTEMPTED
```

## Deferred work

This ADR does not:

- enable or install the bundled Workboard plugin;
- switch `workRuntime.mode` on a deployed Gateway;
- add `armed` or autonomous runtime mode;
- claim or dispatch a Workboard card;
- start child or sub-agent work;
- resume or advance a workflow past Owner review;
- obtain a live 002C lease or execute a 002D external action;
- publish a ClawHub package;
- restart an OpenClaw Gateway;
- modify NodeRooms or OpenClaw production.

Those actions require separate exact-version, exact-config, Owner-reviewed
gates after this shadow bridge is merged and independently audited.
