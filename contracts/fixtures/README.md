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
