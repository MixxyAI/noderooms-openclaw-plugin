# ADR 003C: Isolated shadow runtime install and E2E proof

Status: proposed, test-only
Date: 2026-07-24
Base: `09907fb745523a2c0b1f4784982efc31d1500a68`

## Decision

Phase 3B may advance toward closure only after its shadow boundary is proven
against the exact supported OpenClaw host, real plugin loader, bundled
Workboard implementation, and persistent managed Task Flow runtime.

The proof runs only in disposable directories:

```text
exact source
  -> linked install in isolated OpenClaw config/state/workspace
  -> loader-backed NodeRooms and Workboard inspection
  -> one waiting managed Task Flow
  -> one unclaimed review card
  -> fresh-process restart/reconcile and cancel proofs
  -> complete isolated-state removal
```

The proof never starts or restarts a Gateway. It does not touch the user's
default OpenClaw configuration, install the development plugin into a live
profile, call NodeRooms, invoke a connector, or modify production.

## Exact host and loader gate

The test reads the declared packages and requires:

- OpenClaw `2026.7.1-2`;
- NodeRooms `1.3.0-beta.2-dev.1`;
- Node.js within the package engine range;
- the NodeRooms plugin loaded through `plugins inspect --runtime --json`;
- the linked install source reported as `path`;
- exactly 14 NodeRooms tools and 5 hooks;
- the bundled Workboard plugin loaded with create, list, read, claim, and
  dispatch tools present.

Every OpenClaw CLI child process receives exact
`OPENCLAW_STATE_DIR`, `OPENCLAW_CONFIG_PATH`, and
`OPENCLAW_WORKSPACE_DIR` values under a newly created temporary root. A hash
of the default OpenClaw configuration must be identical before and after the
proof.

## Primary scenario

The primary scenario begins with zero managed Task Flows and zero cards. A
real non-fixture canonical 003A work item is bound through the 003B tool and
its guarded `workboard_create` call.

The observable state must then be exactly:

| Surface | Required state |
|---|---|
| Managed Task Flow | one, `managed`, `waiting`, revision `0` |
| Task Runs | zero |
| Workboard | one card, `review`, no claim |
| Dispatch | zero |
| Connector/network/external write | zero |

A second worker process loads the persisted SQLite and NodeRooms private
state. It must reuse the same binding without creating another flow or card.
A byte-drifted card create is blocked, and Owner reconcile must be read-only
with an unchanged private-state SHA-256.

## Revision and cancel scenario

A second disposable profile creates the same safe starting state. It first
submits a deliberately stale Task Flow revision and requires
`revision_conflict`. The authenticated Owner command then requests cancel
against the current revision.

The flow revision must advance, no child task may exist, and the Workboard card
must remain unclaimed in `review`. Cancellation does not claim, dispatch,
resume, retry, or externally write.

## Evidence boundary

The public evidence contains only:

- contract and exact version identifiers;
- generated binding, flow, and card identifiers;
- fingerprints, revisions, statuses, counts, and boolean gates;
- cleanup and no-production-change results.

The harness mechanically rejects known raw work title, repository selector,
session identity, Owner identity, Passport, and Owner-binding values before
writing evidence. It never serializes credentials, provider sessions, claim
tokens, raw work content, prompts, or private artifacts.

## Acceptance gates

```text
EXACT_OPENCLAW_VERSION=PASS
ISOLATED_STATE_CONFIG_WORKSPACE=PASS
REAL_PLUGIN_LOADER=PASS
ONE_WAITING_MANAGED_FLOW=PASS
ONE_UNCLAIMED_REVIEW_CARD=PASS
FRESH_PROCESS_RESTART=PASS
DUPLICATE_BINDING_REUSED=PASS
DRIFTED_CREATE=BLOCKED
RECONCILE_READ_ONLY=PASS
STALE_CANCEL_REVISION=BLOCKED
OWNER_CANCEL=PASS
TASK_RUN_RESUME_CLAIM_DISPATCH=0
CONNECTOR_NETWORK_EXTERNAL_WRITE=0
DEFAULT_CONFIG_UNCHANGED=PASS
ISOLATED_STATE_REMOVED=PASS
```

## Deferred work

003C is a test and evidence layer. It does not:

- change live plugin runtime code, manifest defaults, or tool contracts;
- enable Workboard or shadow mode in a user's real OpenClaw profile;
- start or restart a Gateway;
- advance past Owner review;
- create a Task Run, claim or dispatch work, or invoke a connector;
- obtain a live lease or perform an external write;
- publish, install, merge, deploy, or modify production.

The next mandatory round is a separate Phase 3 closure proof for the
Owner-initiated multi-step history, per-step lease and receipt boundaries, and
canonical NodeRooms Workdesk projection. It remains independently gated.
