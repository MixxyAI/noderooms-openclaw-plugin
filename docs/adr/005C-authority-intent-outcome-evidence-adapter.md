# ADR 005C — Authority → Intent → Outcome Evidence Adapter

Status: Alpha4 contract foundation, repository-only, default-off.

## Decision

TrustBridge 005C adds a deterministic adapter that closes the references
between:

```text
005B exact artifact/runtime fingerprint
→ capability request
→ Verified Human Owner decision
→ one-action run lease
→ canonical external-action intent
→ at-most-once dispatch reservation
→ signed provider-outcome receipt
→ 005A claw-runtime-evidence.v0.1 envelope
```

The adapter is implemented at
`tools/trustbridge/action-evidence-adapter.mjs`. It is not imported by the
OpenClaw plugin entry point and grants no execution authority.

## Alpha4 boundary

The first implementation accepts contract fixtures only. Every authority
record must already pass the existing 002C and 002D validators with:

- one exact Agent, Passport, Verified Owner, Gateway, runtime, connector,
  tool, schema, action, resource, and payload fingerprint;
- a human, non-automated `allow_once` decision;
- one exact, non-shared lease and no shared run secret;
- one dispatch reservation with a maximum of one provider attempt;
- no automatic write retry;
- an Ed25519 receipt whose trust anchor is supplied explicitly by the caller.

The 005B runtime identity is cross-bound to the authority-chain runtime by
hashing the exact Gateway ID and OpenClaw Agent ID and by matching the runtime
key thumbprint. Package identity must match between the 005B artifact and
runtime bindings.

## Evidence projection

The adapter emits the existing 005A
`owner_approved_external_action_outcome` profile. It stores only bounded
metadata and fingerprints. Raw tool parameters, prompt content, provider
credentials, messages, e-mails, targets, provider responses, and private keys
are not copied into the evidence envelope.

The evidence fingerprint excludes the `$schema` locator, final fingerprint,
and attestation, matching the canonical 005A projection. The current contract
fixture remains unsigned and explicitly requires an external trust anchor.

## Non-claims

005C does not:

- authorize or dispatch a connector;
- activate Trust Middleware enforcement;
- start or restart a Gateway;
- install a plugin or modify OpenClaw configuration;
- call NodeRooms production or a provider;
- create a Gmail draft or send a message;
- prove exactly-once provider effect;
- generate a reputation score;
- attest that an artifact is safe;
- publish to npm or ClawHub.

Non-fixture evidence remains blocked until external runtime validation,
external attestation, lifecycle-status signing, revocation, and verifier
policy are independently proven.

## Validation

The 005C tests require:

- successful 005A JSON Schema validation;
- exact 005B result fingerprint validation;
- exact runtime cross-binding;
- exact capability, Owner decision, lease, intent, and receipt fingerprints;
- valid receipt signature;
- fail-closed rejection of Owner automation, replay expansion, runtime drift,
  artifact drift, receipt tampering, evidence tampering, and non-fixture use;
- zero live side effects;
- no import from the live plugin entry point;
- immutable stable `1.3.0`.
