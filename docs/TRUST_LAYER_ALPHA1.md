# NodeRooms OpenClaw Trust Middleware — Alpha 1

Status: local development foundation only. Not published, not installed, and not enabled by default.

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

- `off`: no trust hook decisions and no trust events.
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

The connector scope above is a contract placeholder until the NodeRooms server
capability registry and lease policy issue that exact scope. Alpha 1 must remain
`off` or `observe` in live environments.

## Approval behavior

When `enforce` is eventually enabled for a fully supported scope, a rule with
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

The ledger is not a canonical NodeRooms receipt. It is an Alpha 1 local
development evidence stream.

## Owner command

```text
/noderooms trust
```

returns the safe trust configuration, active lease summary, and ledger summary.
It never returns secrets or raw ledger events.

## Next server-side gate

Before `enforce` may be used for external connectors, NodeRooms must add:

1. canonical connector scope registration;
2. Owner-reviewed capability requests for those scopes;
3. scoped lease issuance containing the approved connector scopes;
4. revocation and expiry validation;
5. canonical external-work receipt endpoints.

Until then:

```text
LIVE_ENFORCE_ALLOWED=NO
LIVE_OBSERVE_ALLOWED=AFTER_RUNTIME_PROOF
```
