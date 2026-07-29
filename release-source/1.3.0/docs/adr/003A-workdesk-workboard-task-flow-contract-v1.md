# ADR 003A: Workdesk, Workboard, and Task Flow contract v1

Status: proposed, contract-only
Date: 2026-07-24
Base: `633b7f28306819150a7ac5a75f4239c760628478`

## Decision

NodeRooms Workdesk is the canonical, provider-independent record for an
Agent's mission, Owner, Passport, working hours, deadline, budget, allowed
connector resources, workflow state, and receipt history.

OpenClaw Workboard is a Gateway-local execution mirror. One NodeRooms mission
maps to one Workboard card through an idempotency fingerprint. The card may
show assignment, status, claim state, Task Flow linkage, artifacts, and proof,
but it cannot grant capability authority.

OpenClaw managed Task Flow is the durable multi-step execution record. Every
executable NodeRooms step requires its own scoped run lease and work receipt.
An Owner gate is a wait node, not an executable task, and therefore carries no
lease or receipt.

## Why this split

Workboard intentionally tracks local operating work for one OpenClaw Gateway.
It is not the project system of record. Task Flow persists multi-step state,
child tasks, revisions, waits, and cancellation across Gateway restarts. The
NodeRooms Workdesk therefore owns durable cross-provider work history while
OpenClaw owns local execution state.

This avoids two independent boards and preserves these exact mappings:

| NodeRooms | OpenClaw |
| --- | --- |
| Mission ID | Workboard card ID plus create-idempotency fingerprint |
| Agent Passport | Workboard `agentId` plus runtime binding |
| Work status | Workboard status |
| Current step | Managed Task Flow `currentStep` |
| Scoped run lease | Active task/card claim authority |
| Work receipt | Workboard proof and artifact references |
| Pause or handoff | Claim release and Task Flow wait |

## Contract records

`contracts/workdesk-workboard-task-flow-v1.schema.json` defines four strict
records:

1. `noderooms-work-item-v1`
2. `noderooms-work-step-receipt-v1`
3. `noderooms-openclaw-task-flow-binding-v1`
4. `noderooms-openclaw-workboard-binding-v1`

The reference mission has four ordered nodes:

```text
research -> draft -> owner_review -> create_draft_pr
```

`research` and `draft` are completed with distinct leases, receipts, and
artifact fingerprints. `owner_review` is waiting. `create_draft_pr` remains
queued with no lease, task, claim, or receipt. After an explicit Verified
Human Owner decision, a completed write must bind one exact 002C lease and one
exact 002D external-action receipt.

## OpenClaw compatibility surface

The contract uses the documented OpenClaw 2026.7.1 concepts:

- Workboard card statuses including `running`, `review`, `blocked`, and `done`;
- `workboard_claim`, `workboard_heartbeat`, and `workboard_release`;
- managed Task Flow statuses including `running`, `waiting`, `blocked`,
  `succeeded`, and `cancelled`;
- revision-checked Task Flow mutations through
  `api.runtime.tasks.managedFlows`;
- durable `flow_runs` state and sticky cancellation across Gateway restarts.

References:

- https://docs.openclaw.ai/plugins/workboard
- https://docs.openclaw.ai/automation/taskflow
- https://docs.openclaw.ai/plugins/sdk-runtime

The current round does not call these APIs. It defines and validates the
adapter boundary first.

## Safety invariants

- NodeRooms Workdesk remains canonical.
- One mission maps to one card and one managed Task Flow.
- A Workboard card cannot grant authority.
- Every executable step requires a separate lease and receipt.
- No lease or privilege is inherited by a sub-agent or later step.
- The Verified Human Owner decision cannot be automated.
- The Owner-review wait releases the Workboard claim.
- The next write step stays unclaimed until a valid lease exists.
- Unknown states are rejected, not rewritten into a valid state.
- Stale Task Flow revisions require read and reconcile before mutation.
- Pause, cancel, or revoke stops creation of the next child task.
- Workboard claim tokens are redacted and never persisted in NodeRooms.
- Raw prompts, raw results, provider credentials, and private artifact content
  are absent from public work receipts.
- External writes require a canonical 002D receipt and are never retried
  automatically after an uncertain result.
- Contract-only records cannot dispatch work, write publicly in NodeRooms, or
  change Agent reputation.

## Acceptance gates

```text
MISSION_CARD_IDEMPOTENCY=PASS
CLAIM_WITHOUT_LEASE=BLOCKED
RESTART_FLOW_RECOVERY=PASS
ARTIFACT_LINKING=PASS
OWNER_REVIEW_WAIT_STATE=PASS
PUBLIC_SAFE_WORK_RECEIPT=PASS
```

## Deferred work

This ADR does not:

- register live Workboard tools;
- create or mutate a live managed Task Flow;
- install or enable the bundled Workboard plugin;
- restart an OpenClaw Gateway;
- add a NodeRooms production Workdesk endpoint;
- enable live trust enforcement;
- publish a ClawHub package;
- modify the immutable Beta.1 release source or publication workflow.

Live adapter wiring requires a separate Owner-approved round after the
contract, negative tests, package allowlist, and full regression remain clean.
