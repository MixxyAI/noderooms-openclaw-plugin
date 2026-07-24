# ADR 002D: Canonical external-action intent and receipt v2

- Decision: `NR-OC-TRUST-002D`
- Status: Accepted for contract development
- Date: 2026-07-24
- Deployment status: Not deployed
- Live enforcement: Prohibited

## Context

`NR-OC-TRUST-002A` defines one exact connector, tool schema, action, and
resource. `002B` binds that scope to one Agent, Passport, Verified Owner, and
OpenClaw runtime. `002C` records the human Owner decision and issues one bounded
run-lease authority.

A lease alone does not prove what payload was about to be sent, whether a
dispatch slot was reserved before the provider call, whether a write was
retried after a lost response, or whether a later receipt belongs to that exact
intent.

## Decision

Every governed external write uses this immutable chain:

```text
reviewed run lease
→ canonical payload projection
→ immutable external-action intent
→ atomic dispatch reservation
→ at most one provider dispatch
→ signed canonical receipt
```

The machine-readable schema is:

```text
contracts/canonical-external-action-intent-receipt-v2.schema.json
```

The pure validator is:

```text
src/external-action-intent-receipt.js
```

It is packaged for review and testing but is not imported by the live plugin
entry point in 002D.

## Canonical payload projection

The intent never persists raw title or body content. The GitHub Draft PR
reference projection contains:

```text
repository_full_name
head_ref
base_ref
draft = true
title_sha256
body_sha256
```

The complete projection receives one canonical SHA-256 fingerprint. Repository
and base branch must equal the exact resource selector reviewed by the Owner.
Extra fields, wildcard-like values, missing claims, or any fingerprint mismatch
fail closed.

## Dispatch reservation

Before a provider call, the contract reserves one dispatch slot bound to:

```text
intent ID + intent authority
lease ID + lease-authority fingerprint
Agent + Passport + Owner
runtime + channel + session + run
registry + policy + connector + exact tool schema
action + resource
payload fingerprint
Owner decision
```

The reservation starts with:

```text
state = reserved
attempt_count = 0
max_attempts = 1
automatic_write_retry = false
reconcile_mode = read_only
```

One lease action cannot reserve a second intent. Duplicate intent,
reservation, lease, or authority fingerprints fail closed.

## Provider idempotency

Provider idempotency support is taken from the connector profile.

- When the profile declares `provider_idempotent`, the intent must contain only
  a fingerprint of the bound idempotency key and must require forwarding it.
- When the profile declares `at_most_once_dispatch`, no idempotency-key binding
  may be asserted.

The raw key is never stored in an intent, receipt, audit projection, or local
ledger.

## Outcome precision

The plugin contract guarantees:

```text
at-most-once provider dispatch
local replay blocked
automatic write retry attempted = false
```

It does not claim an exactly-once provider effect unless the provider offers a
transactional guarantee outside this contract. Every receipt therefore sets:

```text
exactly_once_effect_claimed = false
```

## Unknown outcome and reconciliation

If the provider response is lost after dispatch, the first receipt records:

```text
status = unknown
attempt_count = 1
automatic_write_retry_attempted = false
```

The write is not repeated. A second and final receipt may resolve that unknown
state only through a read-only provider observation. It must link the previous
receipt ID and fingerprint, retain the same dispatch attempt count, and set:

```text
reconciliation.mode = read_only
reconciliation.provider_write_attempted = false
```

A reconciliation receipt cannot follow a committed or failed predecessor and
cannot create a third receipt in this contract.

## Signed receipt

Every canonical receipt has:

```text
receipt fingerprint
issuer
Ed25519 public key and key thumbprint
key ID
signature time
Ed25519 signature
```

Validation requires an external trusted key thumbprint. Trusting the public key
embedded in the receipt alone is insufficient. The signature covers a
domain-separated projection containing the receipt ID, receipt fingerprint,
issuer, key ID, key thumbprint, and signature time.

The fixture contains a valid public key and signature. Its private key is not
stored and cannot be recovered from the fixture.

## Audit and reputation projection

The receipt contains bounded audit attribution and evidence fingerprints, not
raw provider content.

Because 002D is contract-only:

```text
eligible_for_reputation = false
score_delta_applied = false
score_delta = 0
reason_code = LIVE_REPUTATION_UPDATE_PROHIBITED
```

Receipt validity is evidence integrity. It is not a live reputation mutation.

## Secret boundary

The intent, receipt, fixtures, and validator contain no:

- provider credential, provider session, or authorization header;
- run secret, shared secret, channel token, or private key;
- raw title, body, prompt, request, response, result, or provider payload;
- unbounded provider error message.

OpenClaw remains the provider-credential boundary. NodeRooms receives only
public-safe identifiers, bounded projections, fingerprints, and attestations.

## Contract-only safety

Every 002D fixture sets:

```text
fixture = true
activation_state = contract_only
live_enforce_allowed = false
```

An exact signed match returns:

```text
contract_match_not_authorized
LIVE_ENFORCE_PROHIBITED
```

It never dispatches a tool or authorizes a write.

## Non-goals for 002D

This decision does not:

- deploy an intent, reservation, receipt, or reconciliation endpoint;
- create a production receipt-signing key or key-rotation service;
- atomically reserve or consume a production lease counter;
- connect the contract validator to OpenClaw hooks;
- dispatch a provider action;
- update live Agent reputation;
- enable live `enforce`;
- publish to ClawHub;
- install or restart OpenClaw;
- modify NodeRooms production.

`NR-OC-TRUST-002D` closes the contract-development portion of Phase 2. Product
work may proceed to Phase 3, while live enforcement remains blocked until the
complete server, key-management, atomicity, connector, and isolated E2E proofs
exist.
