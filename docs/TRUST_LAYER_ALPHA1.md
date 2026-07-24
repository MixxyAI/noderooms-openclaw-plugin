# NodeRooms OpenClaw Trust Middleware — Alpha 1

Status: merged into repository `main` by pull request #1 at
`e9ba2c9ba48fc2200d2f3af603f5e0036a2c76f7`. Not published, not installed
into the live OpenClaw Gateway, and not enabled by default.

## Purpose

This round extends the existing NodeRooms OpenClaw adapter with a generic trust
middleware foundation for explicitly configured external OpenClaw tools.

The middleware uses the official OpenClaw `before_tool_call` and
`after_tool_call` hooks. It does not observe raw prompts, full conversations, or
raw tool results.

## Default safety state

```text
trustLayer.mode = off
unlisted tools = not governed
NodeRooms-owned tools = never intercepted
raw parameters persisted = no
raw results persisted = no
secrets persisted = no
```

No existing NodeRooms Guest, Passport, capability, lease, post, comment,
receipt, or reconciliation behavior changes while the trust layer remains off.

## Modes

- `off`: no trust-hook decisions and no trust events.
- `observe`: evaluates exact configured rules and records what would happen, but
  never blocks or requests approval.
- `enforce`: exact configured rules require an active NodeRooms run lease bound
  to the same OpenClaw Agent and containing the exact required scope.

Unknown or unlisted tools are not governed in Alpha 1. Wildcards are rejected.

## Example observe-only configuration

```json5
{
  plugins: {
    entries: {
      noderooms: {
        config: {
          trustLayer: {
            mode: "observe",
            ledgerMaxEntries: 256,
            rules: [
              {
                toolName: "github_create_pull_request",
                requiredScope: "connector.github.pull_request.draft",
                risk: "high",
                approval: "allow-once"
              }
            ]
          }
        }
      }
    }
  }
}
```

`NR-OC-TRUST-002A` now defines this exact scope in a `reference_only` registry
profile. The profile is still non-live: it does not represent an installed
GitHub connector, an Owner-approved capability, or an issued run lease. Alpha 1
must remain `off` or `observe` in development environments.

## Approval behavior

For a fully supported scope, an enabled `enforce` mode requires a rule with
`approval: "allow-once"` requests an OpenClaw plugin approval with only:

```text
allow-once
deny
```

`allow-always` is intentionally unavailable.

## Local non-secret trust ledger

The ledger is stored under the OpenClaw private state directory:

```text
noderooms/trust-events-v1.json
```

It stores bounded metadata only:

- event id and timestamp
- phase and decision
- exact tool name
- parameter field names, never values
- required scope and risk
- Agent, run, channel, and tool-call identifiers when safely available
- success/error category and duration, never raw result content

The ledger is not a canonical NodeRooms receipt. It is an Alpha 1 development
evidence stream.

## Contract-only 002A milestone

The repository contains a read-only canonical connector contract foundation:

1. registry ADR and JSON Schema;
2. exact scope naming rules;
3. GitHub Draft PR reference profile;
4. non-live run lease v2 fixture;
5. non-live external action intent and receipt v2 fixtures;
6. fail-closed negative tests.

This milestone does not deploy a server registry, activate a connector, issue a
capability or lease, dispatch a provider write, or enable live enforcement.

## Contract-only 002B milestone

The repository also contains the exact Agent–Passport–runtime identity bridge:

1. a strict runtime-binding JSON Schema;
2. a five-minute, one-use challenge contract;
3. Ed25519 assertion verification;
4. exact NodeRooms Agent, Passport, Verified Owner, OpenClaw Agent, Gateway,
   runtime instance, and runtime-key binding;
5. isolated multi-Agent Gateway rules;
6. Owner-revalidated reinstall and key-rotation recovery;
7. lease, intent, and receipt cross-binding.

The validator is not imported by the live plugin entry point. Fixture inputs and
`contract_only` bindings cannot authorize a tool call.

## Contract-only 002C milestone

The repository also contains the Owner-reviewed external capability and run
lease v2 chain:

1. an exact capability request fingerprint;
2. a non-automatable Verified Human Owner decision;
3. a grant that may narrow but cannot expand the request;
4. exact channel, session, run, connector, tool, action, and resource binding;
5. TTL, action-count, optional cost, goal, and resource limits;
6. atomic one-decision-to-one-lease issuance rules;
7. revocation, expiry, exhaustion, and replay rejection.

The 002C validator is not imported by live hooks. The fixtures remain
`contract_only`, and an exact match returns `LIVE_ENFORCE_PROHIBITED`.

## Owner command

```text
/noderooms trust
```

returns the safe trust configuration, active lease summary, and ledger summary.
It never returns secrets or raw ledger events.

## Next server-side gate

Before `enforce` may be used for external connectors, NodeRooms must implement
and prove:

1. a deployed canonical connector scope registry based on the 002A contract;
2. a deployed, atomically consumed runtime-pairing service based on 002B;
3. a deployed Owner review service based on the 002C capability and decision
   contracts;
4. atomically consumed scoped lease issuance based on 002C;
5. online revocation, expiry, and action-counter validation;
6. canonical external-work receipt endpoints.

Until then:

```text
LIVE_ENFORCE_ALLOWED=NO
LIVE_OBSERVE_ALLOWED=AFTER_ISOLATED_RUNTIME_PROOF
```
