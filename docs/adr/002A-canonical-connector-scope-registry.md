# ADR 002A: Canonical connector scope registry contract

- Decision: `NR-OC-TRUST-002A`
- Status: Accepted for contract development
- Date: 2026-07-23
- Deployment status: Not deployed
- Live enforcement: Prohibited

## Context

Trust Middleware Alpha 1 can observe exact external OpenClaw tool rules, but it
does not have a canonical NodeRooms server registry for connector scopes. A
free-form scope string is insufficient for authorization because the provider,
connector version, tool schema, action, resource, risk, approval policy, and
receipt semantics can drift independently.

OpenClaw tools can be supplied by core, plugins, MCP servers, and clients. Tool
registration includes an input schema, and the effective catalog is resolved
for a specific run. NodeRooms therefore binds authorization to an exact runtime
tool descriptor instead of trusting a human-readable tool name alone.

## Decision

NodeRooms connector authorization will be defined by a versioned registry. Each
profile contains these exact dimensions:

```text
provider
connector_id
connector_version
tool_name
tool_schema_fingerprint
action
resource_type
resource_selector
risk
side_effect_class
replay_semantics
approval_policy
receipt_profile
```

The registry also carries an exact `registry_version` and `policy_version`.

The machine-readable schema is:

```text
contracts/connector-scope-registry-v1.schema.json
```

The first reference profile is:

```text
contracts/reference/github-draft-pr.v1.json
```

It is intentionally `reference_only`. It cannot authorize or activate a live
tool call.

## Exact matching

Authorization is exact, never prefix-based:

1. resolve the effective tool for the current OpenClaw run;
2. obtain its exact connector identity, version, tool name, and input schema;
3. canonicalize the input schema and calculate its SHA-256 fingerprint;
4. find exactly one active registry profile matching every connector and tool
   dimension;
5. verify an Owner-approved run lease v2 matches the exact Agent, Passport,
   Owner binding, runtime, connector, tool, schema fingerprint, action,
   resource, registry version, and policy version;
6. verify expiry, revocation, remaining action count, and approval policy;
7. deny on any missing, ambiguous, unavailable, or mismatched value.

Wildcards, namespace grants, prefix grants, and fallback-to-name matching are
prohibited.

## Schema fingerprint

`tool_schema_fingerprint` is:

```text
sha256:<lowercase hexadecimal SHA-256 of RFC 8785 canonical JSON>
```

The fingerprint covers the complete registered input schema. A schema change
is authorization drift even if the tool name and connector version did not
change. Drift must block until a new profile version is reviewed.

## Scope identifiers

Scopes follow the exact naming contract in:

```text
docs/CONNECTOR_SCOPE_NAMING.md
```

The scope is a stable identifier, not a substitute for the other registry
dimensions. Read, write, destructive, and administrative operations require
separate profiles.

## Owner approval and lease v2

A governed write requires an explicit human Owner decision. A run lease v2
binds one exact capability to:

```text
Agent + Passport + Owner
+ runtime + connector + tool schema
+ action + resource
+ TTL + max_actions
+ registry_version + policy_version
+ revocation state
```

High and critical risk profiles require `allow_once`. `allow_always` is not a
valid approval policy.

The non-live fixture is:

```text
contracts/fixtures/github-draft-pr.run-lease-v2.json
```

## Intent and receipt v2

Before a governed write, NodeRooms creates a canonical external-action intent
and payload projection. Raw prompts, conversations, provider credentials, and
raw tool results are excluded.

The dispatch contract is:

- one dispatch reservation;
- at most one provider write attempt;
- provider idempotency key forwarding only when supported;
- no automatic write retry after an uncertain outcome;
- read-only reconciliation;
- no claim of exactly-once provider effect without a provider transaction.

The non-live fixtures are:

```text
contracts/fixtures/github-draft-pr.external-action-intent-v2.json
contracts/fixtures/github-draft-pr.external-action-receipt-v2.json
```

## Failure behavior

The following conditions fail closed:

- unknown or duplicate profile;
- wildcard or malformed scope;
- provider, connector, version, tool, or schema drift;
- Agent, Passport, Owner, runtime, session, run, or channel mismatch;
- action or resource mismatch;
- registry or policy version mismatch;
- expired or revoked lease;
- exhausted action count;
- missing required Owner approval;
- policy, registry, ledger, or receipt failure.

## Secret boundary

Provider credentials and run secrets remain in the execution environment that
owns them. The registry, fixtures, intent projection, and receipt contain no
credential value, authorization header, raw prompt, raw request body, or raw
provider response.

## Non-goals for 002A

This decision does not:

- deploy a NodeRooms server registry;
- enable public or live `enforce`;
- install a GitHub connector;
- issue a real capability or lease;
- dispatch a provider write;
- publish to ClawHub;
- install or restart OpenClaw;
- modify NodeRooms production.

## Change control

Changing any registry dimension, schema fingerprint, action, resource selector,
risk, approval policy, replay semantics, or receipt profile requires a reviewed
registry version change. Existing leases remain bound to their original
registry and policy versions and do not inherit broader permissions.

## References

- OpenClaw tools: https://docs.openclaw.ai/tools
- OpenClaw tool plugins: https://docs.openclaw.ai/plugins/tool-plugins
- OpenClaw Plugin SDK: https://docs.openclaw.ai/plugins/sdk-overview
- OpenClaw Code Mode catalog: https://docs.openclaw.ai/tools/code-mode
