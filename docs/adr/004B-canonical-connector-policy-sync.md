# ADR 004B: Canonical connector policy sync

## Status

Accepted as a signed, contract-only, non-live Phase 4 policy-sync foundation.

## Context

`NR-OC-CONNECTOR-004A` inventories the effective OpenClaw tool catalog and
records exact owner, schema, receipt, replay, side-effect, risk, coverage, and
drift metadata. Its compiled reference registry is useful for inventory
classification, but a local constant is not sufficient proof that a policy is
current, canonical, externally trusted, monotonic, or bound to the same
runtime-tool owner observed by OpenClaw.

Phase 4C must not execute a GitHub write merely because a tool name and schema
match a local fixture.

## Decision

Phase 4B adds a pure canonical-policy verifier and synchronization controller:

```text
external trust anchor
→ Ed25519-signed canonical policy bundle
→ monotonic compare-and-set checkpoint
→ exact 004A inventory binding
→ Phase 4C contract prerequisite
```

The implementation is:

```text
src/canonical-connector-policy-sync.js
```

It is built into `dist` for review but is not imported by the live plugin entry
point. It has no `fetch`, Gateway, connector, task, browser, shell, or provider
credential integration.

## Canonical source

The signed contract names one exact future source:

```text
origin: https://noderooms.com
path:   /.well-known/noderooms/connector-policy-v1.json
redirects: prohibited
```

The Phase 4B fixture uses `transport=contract_fixture`. Live policy fetch is
prohibited. The synchronization controller receives a bounded, injected
read-only source adapter so the contract can be exercised without performing a
network request.

## External trust anchor

The policy bundle does not establish its own trust. Validation requires a
separate Ed25519 trust-anchor record containing:

```text
canonical origin
key ID
public JWK
public-key thumbprint
valid-from and valid-until timestamps
```

The bundle attestation must match that external anchor exactly. The signature
covers a domain-separated projection containing the bundle ID, sequence,
bundle fingerprint, key ID, key thumbprint, and signing time.

The fixture contains only a public key and signature. The private signing key
is not stored.

## Exact policy bundle

The bundle binds:

```text
bundle ID and monotonic sequence
canonical origin, path, transport, and redirect policy
issued, not-before, expiry, and predecessor fingerprint
full connector registry and registry fingerprint
exact profile → tool → runtime owner binding
safety flags
bundle fingerprint and Ed25519 attestation
```

Every runtime owner binding is explicit:

```text
profile_id + tool_name + owner.kind + owner_id + resolution=exact
```

No owner is inferred from a description, tool prefix, provider name, model
output, parameter sample, or connector label.

Phase 4B accepts only:

```text
bundle activation_state = contract_only
registry activation_state = contract_only
profile status = reference_only
live_policy_sync_allowed = false
live_enforce_allowed = false
```

An active registry or profile is rejected rather than downgraded.

## Monotonic checkpoint

The controller loads a non-secret checkpoint before each source read and uses
one compare-and-set operation for a new accepted bundle.

It rejects:

- a sequence below the accepted checkpoint;
- the same sequence with another bundle ID or fingerprint;
- a sequence gap;
- an invalid predecessor fingerprint;
- a genesis bundle that does not equal the pinned minimum sequence;
- a concurrent checkpoint change.

An exact repeat is idempotent and does not rewrite the checkpoint. A fresh
controller can reload the external checkpoint, revalidate the signed bundle,
and accept that exact repeat without creating new authority.

## Inventory binding

After successful sync, Phase 4B binds the verified policy to one validated
004A inventory snapshot. Every required profile must have:

```text
exact tool discovery
exact owner kind and owner ID
exact input-schema fingerprint
exact registry and policy version
exact profile, scope, connector, action, resource, and approval binding
coverage_status = covered_contract_only
enforce_eligible = false
authority_status = inventory_only_no_authority
```

Unknown owners, unavailable schemas, schema drift, policy drift, version drift,
unclassified side-effecting tools, or missing profiles make the Phase 4C
contract prerequisite false.

Even a fully matching binding returns:

```text
authority_status = verified_policy_no_execution_authority
phase4c_external_write_authority_granted = false
```

## Failure behavior

Origin, path, redirect, size, time, key, thumbprint, signature, registry,
schema, policy, owner, sequence, chain, checkpoint, or inventory mismatch fails
closed. A failed sync exposes no verified registry and cannot retain a Phase 4C
ready binding.

Remote error text, raw schema, raw tool parameters, raw results, signatures,
public keys, and credentials are excluded from status projections.

## Safety boundary

004B:

- performs no live policy fetch;
- invokes no OpenClaw tool or connector;
- grants no tool or connector-execution authority;
- performs no external write;
- does not issue, consume, or expand a run lease;
- does not automate a Verified Human Owner decision;
- does not activate live enforcement;
- does not import the verifier into the live plugin entry point;
- does not publish, install, start or restart a Gateway, or modify production.

## Evidence

Run:

```text
node --test tests/canonical-connector-policy-sync.test.mjs
node scripts/canonical-connector-policy-sync-proof.mjs
```

The suite proves external-anchor signature validation, exact owner binding,
bounded source access, checkpoint compare-and-set, idempotent restart,
rollback/equivocation/gap/chain rejection, exact 004A inventory binding,
schema-gap blocking, and zero execution authority.

## Next milestone

`NR-OC-CONNECTOR-004C` may attempt one isolated, Owner-approved GitHub Draft PR
proof only after it independently revalidates this exact policy prerequisite,
an exact Agent/Passport/Owner/runtime binding, one unconsumed allow-once lease,
one immutable intent and dispatch reservation, at-most-one provider attempt,
and one canonical receipt.

Direct `main` writes, non-draft PRs, workflow changes, secret changes, retries
after an unknown outcome, wildcard resources, and automatic Owner decisions
remain prohibited.
