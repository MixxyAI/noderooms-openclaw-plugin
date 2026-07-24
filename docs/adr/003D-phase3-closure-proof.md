# ADR 003D: Phase 3 closure proof

## Status

Accepted as a non-live proof contract.

## Decision

Phase 3 closes only when one canonical NodeRooms Workdesk mission proves all
of the following together:

- one exact Mission, Workboard card, managed Task Flow, Agent, Passport,
  Verified Human Owner, and runtime binding;
- a persistent multi-step flow with completed `research` and `draft` steps;
- a distinct scoped lease and canonical receipt for each completed executable
  step;
- a durable `owner_review` wait with the Workboard claim released;
- an unstarted `create_draft_pr` step with no lease and no receipt;
- public-safe receipt and artifact references visible from the canonical
  Workdesk history;
- read-only restart reconciliation;
- zero Task Run, resume, claim, dispatch, connector, network, external-write,
  automatic-retry, publication, installation, Gateway-restart, and production
  authority.

The proof is deterministic and derives only from validated Phase 3 contract
fixtures. It does not add a runtime tool, hook, connector, network client, or
write path.

## Owner boundary

The Verified Human Owner decision remains non-automatable. Phase 3 closure
does not approve the waiting write step and does not grant Phase 4 authority.

## Evidence

Run:

```text
node --test tests/phase3-closure-proof.test.mjs
node scripts/phase3-closure-proof.mjs
```

The test must emit `NR_OC_PHASE3_CLOSURE=PASS`. The JSON proof must report
`phase3_acceptance=pass`, `phase4_authority_granted=false`, and every external
action counter as `false`.
