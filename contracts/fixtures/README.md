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
