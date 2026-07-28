# ADR 002B: Agent, Passport, Owner, and OpenClaw runtime binding

- Decision: `NR-OC-TRUST-002B`
- Status: Accepted for contract development
- Date: 2026-07-24
- Deployment status: Not deployed
- Live enforcement: Prohibited

## Context

`NR-OC-TRUST-002A` defines exact connector, tool, schema, action, and resource
scope dimensions. Those dimensions are insufficient unless each lease is also
bound to one proven OpenClaw runtime authority and one canonical NodeRooms
Agent, Passport, and Verified Owner binding.

The OpenClaw plugin hook context exposes the current `agentId`, `sessionId`,
`runId`, and channel identity where available. It does not turn a free-form
Gateway or runtime label into a NodeRooms identity proof. A separate pairing
contract is therefore required before hook context can participate in a live
authorization decision.

## Decision

NodeRooms uses a versioned Agent–Passport–runtime binding with these exact
authorities:

```text
NodeRooms Agent ID
+ immutable public Passport ID
+ active Verified Owner binding ID
+ OpenClaw Agent ID
+ Gateway ID
+ runtime instance ID
+ runtime-owned Ed25519 public-key thumbprint
```

The machine-readable schema is:

```text
contracts/agent-passport-runtime-binding-v1.schema.json
```

The pure validator and signature-verification foundation is:

```text
src/passport-runtime-binding.js
```

It is packaged for review and testing but is not connected to the live plugin
hooks in 002B.

## One-use pairing

Pairing uses a five-minute maximum, single-use NodeRooms challenge.

1. An exact Agent, Passport, Verified Owner binding, Gateway, runtime instance,
   OpenClaw Agent, and runtime public key are selected.
2. NodeRooms issues a challenge containing those exact values and a 256-bit
   nonce.
3. The runtime signs the canonical challenge SHA-256 fingerprint with its
   Ed25519 private key.
4. NodeRooms verifies the signature and exact bindings.
5. The server consumes the challenge atomically before creating the binding.
6. A replayed, expired, revoked, consumed, mismatched, or invalidly signed
   assertion fails closed.

The signature covers the UTF-8 bytes of:

```text
sha256:<canonical challenge projection digest>
```

The canonical projection excludes mutable state such as `state` and
`consumed_at`, but includes every identity, runtime, key, nonce, and lifetime
field.

Signature verification alone does not consume a challenge. Atomic consumption
is a mandatory server transaction and is explicitly returned by the validator
as a required next condition.

## Exact runtime match

A binding match requires equality for:

```text
platform = openclaw
gateway_id
runtime_instance_id
openclaw_agent_id
runtime key thumbprint
NodeRooms Agent ID
Passport ID
Verified Owner binding ID
```

Session, run, channel, connector, tool, action, and resource remain narrower
lease and intent dimensions. They do not replace the persistent runtime
binding.

The current fixture is `contract_only` and sets:

```text
live_enforce_allowed = false
```

An exact fixture match returns `contract_match_not_authorized`, never a live
authorization.

## Multiple Agents on one Gateway

Multiple OpenClaw Agents may use one Gateway only when every Agent has:

- a distinct binding ID;
- a distinct OpenClaw Agent authority;
- a distinct runtime instance authority;
- a distinct runtime key;
- a separate run lease and run secret.

Shared run secrets, shared leases, duplicate runtime tuples, and cross-Agent
binding are prohibited.

## Reinstall and recovery

A runtime reinstall, key rotation, or Gateway replacement does not change the
NodeRooms Agent ID or Passport ID.

Recovery requires:

1. explicit Verified Owner revalidation;
2. revocation of the previous runtime binding;
3. a new runtime instance and runtime key;
4. a new one-use pairing proof;
5. a new run lease.

The previous binding, runtime key authority, lease, and run secret are never
reused. The old and replacement bindings cannot be active concurrently for the
same OpenClaw Agent.

## Lease v2 cross-binding

The 002A run lease, external-action intent, and external-action receipt fixtures
now carry the exact 002B:

```text
binding_id
gateway_id
runtime_instance_id
openclaw_agent_id
runtime_key_thumbprint
NodeRooms Agent ID
Passport ID
Owner binding ID
```

This prevents a lease or receipt from being moved to another Agent or runtime
even when connector scope text is identical.

## Secret boundary

The contract and fixtures contain:

- public Ed25519 keys and SHA-256 thumbprints;
- public-safe identifiers;
- nonces, fingerprints, and signatures.

They never contain:

- an Ed25519 private key;
- provider credentials;
- provider-session secrets;
- run secrets;
- authorization headers;
- channel tokens;
- raw prompts, requests, responses, or tool results.

Private runtime keys remain in OpenClaw-owned private storage. NodeRooms stores
only the public key and its thumbprint.

## Failure behavior

The following conditions fail closed:

- fixture input in a live validator call;
- contract, binding, or key version mismatch;
- missing or false Verified Owner requirement;
- Agent, Passport, Owner, Gateway, runtime, or OpenClaw Agent mismatch;
- malformed or changed public key;
- key-thumbprint mismatch;
- challenge expiry, consumption, revocation, or replay;
- assertion reference, time, fingerprint, runtime, or signature mismatch;
- inactive, expired, or revoked binding;
- duplicate binding, runtime tuple, Agent authority, or runtime key;
- Owner-less recovery;
- recovery that reuses a binding, runtime key, lease, or run secret.

## Non-goals for 002B

This decision does not:

- add or deploy a NodeRooms pairing endpoint;
- persist a live runtime binding;
- connect the validator to OpenClaw hooks;
- issue a real capability or run lease;
- install a connector;
- enable live `enforce`;
- publish to ClawHub;
- install or restart OpenClaw;
- modify NodeRooms production.

## References

- OpenClaw plugin hooks: https://docs.openclaw.ai/plugins/hooks
- OpenClaw Plugin SDK: https://docs.openclaw.ai/plugins/sdk-overview
- Node.js Ed25519 verification: https://nodejs.org/api/crypto.html
