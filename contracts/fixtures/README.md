# Connector contract fixtures

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

`NR-OC-TRUSTBRIDGE-005A` adds:

```text
claw-runtime-evidence.readonly-pass-v0.1.json
claw-runtime-evidence.revoked-v0.1.json
claw-runtime-evidence.unknown-outcome-v0.1.json
```

The positive fixture binds fictional exact archive bytes and a normalized
directory fingerprint to one fictional exact OpenClaw runtime and pseudonymous
Agent, Passport, Owner, Gateway, runtime, key, and sanitized-config
fingerprints. It contains no raw identity, credential, prompt, tool argument,
tool result, provider response, local path, or private key.

All required read-only checks pass and every side-effect counter is zero. The
fixture still states:

```text
authority_status=evidence_only_no_authority
live_enforce_allowed=false
absolute_safety_claimed=false
exactly_once_effect_claimed=false
execution_authority_granted=false
```

The revoked fixture is intentionally invalid because it marks revoked evidence
as active. The unknown-outcome fixture is intentionally invalid because
`unknown` is not a permitted completed check outcome. Both are negative
fail-closed test vectors, not examples for acceptance.

Fixture attestation remains `not_run`. A non-fixture record requires an
Ed25519 signature and a separate external trust-anchor reference; the evidence
record cannot establish trust by embedding its own public key.

These fixtures do not assess the published NodeRooms `1.3.0` artifact, install
or block any artifact, change an OpenClaw configuration, start a Gateway, call
production, write to a provider, or publish to ClawHub or npm.

`NR-OC-TRUSTBRIDGE-005B` adds:

```text
artifact-runtime-fingerprint-v1/package/
artifact-runtime-fingerprint-v1/runtime-observation.json
artifact-runtime-fingerprint-v1/expected-result.json
```

The fictional four-file package tree freezes the final
`noderooms-portable-directory-tree-sha256-v1` vector. Its normalized tree
fingerprint is:

```text
sha256:9c45a6821f4b0b47dbf26024baa3cd4d301127c9ede974c668c267323d8fb2a0
```

The runtime observation contains fictional fingerprints only. It binds the
fixture artifact to exact OpenClaw, Node, Gateway, Agent, runtime-key, and
sanitized-config observations without exposing any raw identity or
configuration. The expected runtime-instance fingerprint is:

```text
sha256:bd1fee1c2da451cb651875e7e302694257690c7f9e37591b2e6430741644ab15
```

The complete result fingerprint is:

```text
sha256:2c20f0d28accf9bf965fcff38dce7bfb892cbd2277bff188bb0d8f8c13eb5607
```

The directory profile rejects symlinks, traversal, non-portable paths, and
ASCII case collisions. It hashes raw file bytes, so line-ending changes are
visible. Permission bits, ownership, timestamps, xattrs, ACLs, hardlink
identity, and archive metadata are explicitly outside the directory claim.

The fixture has no archive, so
`archive_bytes_exactly_hashed=false`. Even when a separately supplied archive
is hashed, `archive_directory_correspondence_proven` remains false. The engine
does not install, extract, execute, approve, or block an artifact.
