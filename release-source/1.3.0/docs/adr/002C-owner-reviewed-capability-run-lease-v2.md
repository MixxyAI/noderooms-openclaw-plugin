# ADR 002C: Owner-reviewed external capability and run lease v2

- Decision: `NR-OC-TRUST-002C`
- Status: Accepted for contract development
- Date: 2026-07-24
- Deployment status: Not deployed
- Live enforcement: Prohibited

## Context

`NR-OC-TRUST-002A` defines the exact connector, tool-schema, action, and
resource vocabulary. `NR-OC-TRUST-002B` binds that vocabulary to one NodeRooms
Agent, Passport, Verified Owner, OpenClaw Agent, Gateway, runtime instance, and
runtime key.

Neither contract records what a human Owner actually reviewed or prevents one
approval from being expanded, replayed, or moved to another session, run,
channel, resource, Agent, or runtime.

## Decision

An external capability request must be reviewed by the Verified Human Owner
before NodeRooms can issue a run lease. The review chain is:

```text
capability request fingerprint
→ Verified Human Owner decision fingerprint
→ atomically consumed decision
→ single run-lease authority fingerprint
```

The machine-readable schema is:

```text
contracts/owner-reviewed-capability-run-lease-v2.schema.json
```

The pure contract validator is:

```text
src/owner-capability-run-lease.js
```

It is packaged for review and testing but is not imported by the live plugin
entry point in 002C.

## Owner review surface

The Owner must be shown and decide on these exact values:

```text
NodeRooms Agent ID
Passport ID
Verified Owner binding ID
OpenClaw Agent, Gateway, runtime instance, and runtime key
channel, session, run, and bound Owner sender
registry and policy version
provider, connector, connector version
exact tool and tool-schema fingerprint
scope, action, resource, and access mode
risk and side-effect class
TTL and maximum action count
optional cost, goal, and resource limits
```

The decision record requires:

```text
reviewer.kind = verified_human_owner
reviewer.decision_automated = false
```

An Agent, scheduler, policy engine, delegated model, or previous approval cannot
make or silently extend this decision.

## Exact resource binding

The request contains exactly the resource claims required by the selected 002A
profile. Extra or missing claims, wildcard-like values, a changed selector, or
a selector fingerprint mismatch fail closed.

For the GitHub Draft PR reference profile this means one exact:

```text
repository_full_name
base_ref
```

It does not authorize another repository, base branch, action, connector,
tool, or schema version.

## Limits

An Owner grant may equal or narrow a request; it cannot expand it.

Contract maximums are:

```text
all leases:       TTL <= 24 hours, actions <= 100
write leases:     TTL <= 1 hour,  actions <= 10
high/critical:    TTL <= 15 min,  actions = 1
allow-once:       actions = 1
```

Optional cost limits use integer minor currency units. Goal limits contain a
goal ID and objective fingerprint, not a raw prompt. Resource limits remain
bound to the exact selector fingerprint.

`null` cost in the fixture means that no provider spend is granted. It is not an
unlimited budget.

## Run lease v2

The lease carries the full reviewed authority:

```text
request ID + request fingerprint
Owner decision ID + decision fingerprint
Agent + Passport + Owner
runtime binding + channel + session + run
registry + policy + connector + exact tool schema
action + access mode + risk + side effects
exact resource selector
TTL + action counters + optional limits
revocation state
```

The Owner decision must be consumed atomically during lease issuance. The same
request or decision cannot mint a second lease.

The stable `lease_authority_fingerprint_sha256` excludes mutable consumption
counters and revocation fields. This allows later intents and receipts to name
the original authority while every new execution still checks the current
counter and revocation state.

## Revocation, expiry, and exhaustion

A tool call fails closed when:

- the lease is expired;
- the lease is revoked;
- no action remains;
- counters are inconsistent;
- any request, decision, registry, Agent, Passport, Owner, runtime, channel,
  session, run, connector, tool, schema, action, resource, or limit differs.

Revocation prevents a new dispatch even when a previously issued authority
fingerprint still matches historical records.

## Secret boundary

The request, decision, lease, fixtures, and local validator contain no:

- provider credential or provider session;
- run secret or shared secret;
- channel token;
- authorization header or cookie;
- runtime private key;
- raw prompt, request, response, tool result, or provider body.

OpenClaw remains the credential and runtime boundary. NodeRooms stores only the
provider-independent trust decision and public-safe fingerprints.

## Contract-only safety

Every 002C fixture sets:

```text
fixture = true
activation_state = contract_only
live_enforce_allowed = false
```

An exact fixture match returns:

```text
contract_match_not_authorized
LIVE_ENFORCE_PROHIBITED
```

It never returns a live authorization.

## Non-goals for 002C

This decision does not:

- deploy an Owner review UI or server endpoint;
- persist or atomically consume a production decision;
- issue a real run lease or run secret;
- connect 002C validation to OpenClaw hooks;
- dispatch an external action;
- enable live `enforce`;
- publish to ClawHub;
- install or restart OpenClaw;
- modify NodeRooms production.

The next milestone is `NR-OC-TRUST-002D`: canonical external-action intent,
dispatch reservation, reconciliation, and receipt v2.
