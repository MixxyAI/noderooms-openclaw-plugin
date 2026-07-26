# ADR 004C: Owner-approved GitHub Draft PR E2E proof

## Status

Contract controller accepted for isolated proof preparation. The live
OpenClaw/MCP provider proof remains fail-closed until the host exposes the exact
GitHub tool owner and input schema through a read-only, independently
verifiable preflight.

## Context

Phase 4A records runtime tool ownership and input-schema fingerprints. Phase 4B
requires an externally anchored signed policy bundle, a monotonic checkpoint,
and an exact policy-to-inventory binding. Both phases deliberately grant zero
connector-execution authority.

Phase 4C is the first milestone that may attempt an external connector write.
The only permitted proof action is creating one Draft pull request from one
already prepared, immutable non-`main` head to one exact `main` base.

An Owner message saying “go” is necessary but is not sufficient by itself. The
runtime owner, tool name, schema, repository, base, head, payload, approval
window, lease, intent, dispatch reservation, and receipt trust anchor must all
match before the provider call.

## Decision

Phase 4C adds a pure proof controller:

```text
src/github-draft-pr-e2e.js
```

The controller is built into `dist` for review but is not imported by the live
plugin entry point.

The controlled sequence is:

```text
signed 004B prerequisite
→ exact Agent / Passport / Verified Owner binding
→ exact OpenClaw runtime and MCP tool binding
→ immutable Draft PR payload fingerprint
→ short-lived Owner approval
→ allow-once lease
→ one dispatch reservation
→ before-tool-call compare-and-set
→ at most one provider attempt
→ after-tool-call outcome
→ Ed25519 receipt
→ replay blocked
→ optional read-only reconciliation
→ sticky revocation
```

## Exact action

The only accepted profile is:

```text
profile: nrscp_github_pull_request_draft_v1
scope:   connector.github.pull_request.draft
owner:   mcp / github / exact
tool:    github_create_pull_request
schema:  sha256:c12e12e4f6a0d03d85c46dbe4e17cfe814f7a988f56ecc4c2b40089d621f8c37
```

Those values identify the six-field NodeRooms policy action. They are not
aliases for the host transport tool.

The exact OpenClaw MCP transport binding for this proof is separate:

```text
server:     github-noderooms-draft-pr
exact id:   github-noderooms-draft-pr__create_pull_request
raw tool:   create_pull_request
raw schema: sha256:e249ccd5a1f2364cbfc0a5d9e11bebdc298626351cc7e43fd59b851c3d520238
adapter:    noderooms-github-mcp-create-pull-request-adapter-v1
```

The adapter is deterministic and memory-only. It splits the exact
`repository_full_name` into `owner` and `repo`, maps `head_ref` to `head` and
`base_ref` to `base`, carries the approved title/body, forces `draft=true` and
`maintainer_can_modify=false`, and omits `reviewers`. The approved plan binds
both the canonical payload fingerprint and the derived raw transport-payload
fingerprint. A raw tool, schema, server, exact ID, adapter, or derived-payload
drift blocks dispatch before the approval is consumed.

The provider payload has exactly the six fields signed by the 004B policy:

```text
repository_full_name
head_ref
base_ref
title
body
draft=true
```

Extra fields are rejected. The base must be `main`; the head must be a
different, immutable branch with a different exact commit SHA.

The plan also records the changed paths on that already prepared head. Workflow
files, environment files, credentials, secrets, private-key material,
traversals, and absolute paths are rejected.

## Owner decision

The approval must be:

- from a Verified Human Owner;
- recorded from one interactive user message;
- `approved_once`;
- explicitly non-automated;
- valid for no more than fifteen minutes;
- bound by fingerprint into the plan;
- consumed before the first possible provider side effect.

An Owner decision cannot be inferred from a model response, prior generic
consent, a stored default, an Agent message, a tool description, or a connector
configuration.

## Receipt trust

The controller creates a process-memory Ed25519 signer and binds its public
trust anchor into the approved plan before arming.

The private key remains inside the signer closure and is never serialized. A
receipt carries the public JWK, key ID, thumbprint, receipt fingerprint, and
signature. Reloaded state must match the plan-bound trust anchor and every exact
proof, approval, lease, intent, reservation, and tool-call identifier.

The receipt proves integrity and at-most-once dispatch. It never claims an
exactly-once provider effect.

## At-most-once dispatch

`beforeToolCall` uses one compare-and-set transition:

```text
armed
→ dispatching
provider_attempt_count: 0 → 1
approval_consumed: false → true
lease_actions_remaining: 1 → 0
```

The transition occurs before the connector call. Competing callers have one
winner. Every replay, restart replay, or second tool-call ID is blocked.

The file store is bounded, schema-validated, lock-protected, atomically
replaced, and stores neither raw title/body nor credentials.

## Outcomes

A known successful outcome is accepted only when the provider object is:

```text
type: pull_request
repository: exact
state: open
draft: true
base ref and SHA: exact
head ref and SHA: exact
URL and number: consistent
```

A transport failure after dispatch is conservatively `unknown`. The lease and
approval remain consumed and the write is never retried automatically.

Only a read-only observation may reconcile an unknown outcome. It must find
zero or one exact matching Draft PR:

- one exact match → `committed`;
- zero matches → `no_effect`;
- more than one match → fail closed.

Reconciliation never restores write authority.

## Revocation

Revocation is sticky and idempotent. Revoking an armed proof moves it to
`revoked`. Revoking a terminal proof records the revocation without rewriting
the outcome or creating another provider attempt.

## Live host preflight

Before a real invocation, the host must independently prove:

1. exact OpenClaw version;
2. exact OpenClaw Agent and session;
3. exact Gateway instance fingerprint;
4. one enabled MCP server owner;
5. one effective MCP tool with the exact namespaced tool ID and raw tool name;
6. the raw MCP `tools/list` input schema and its exact canonical fingerprint;
7. exact 004B policy and inventory binding;
8. one prepared head SHA and unchanged base SHA;
9. no existing pull request for that exact head/base pair;
10. one current interactive Owner approval.

The installed OpenClaw `2026.7.1-2` commands have an important limitation:

- `openclaw mcp probe --json` connects read-only and reports server/tool names,
  but its JSON projection omits input schemas;
- `tools.effective` reports the session-effective source and tool identity, but
  also omits input schemas.

Therefore a name-only host result cannot satisfy item 6. Phase 4C must stop with
`HOST_SCHEMA_UNAVAILABLE` unless a trusted read-only raw MCP `tools/list`
capture supplies the exact schema. The policy fingerprint must not be accepted
from documentation, a local fixture, or a guessed provider version as a
substitute for the live owner’s schema. The canonical policy schema and raw
transport schema are both required; one must never be relabeled as the other.

## Safety boundary

The 004C repository module:

- performs no network request;
- does not invoke OpenClaw or an MCP connector;
- does not create a branch or pull request;
- does not read or persist provider credentials;
- does not import itself into the live plugin;
- does not activate global or production enforcement;
- does not automate the Owner decision;
- does not permit direct `main` writes;
- does not permit non-Draft pull requests;
- does not permit workflow or secret changes;
- does not merge, publish, install, restart a Gateway, or modify production.

The real proof, when the preflight is complete, may make one
`tools.invoke` provider attempt with one intent-derived idempotency key. It
does not authorize any later connector action.

## Evidence

Run:

```text
node --test tests/github-draft-pr-e2e.test.mjs
node scripts/github-draft-pr-e2e-proof.mjs
```

The contract proof covers the success path, signed receipt, payload and runtime
drift, Owner expiry, exact 004B binding, concurrent dispatch, restart replay,
unknown outcome, read-only reconciliation, revocation, persistent-state
tampering, and absence of network/provider/Gateway/process paths.

The contract proof deliberately reports:

```text
proof_mode = isolated_contract_simulation_no_provider
phase4c_external_write_proof_completed = false
live_host_preflight_required = true
```

Those fields may change only after a separately captured real provider receipt.

## Next milestone

After one successful real Draft PR proof, Phase 4D may evaluate live enforcement
integration. The 004C proof itself grants no continuing or production
authority.
