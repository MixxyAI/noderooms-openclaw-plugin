# ADR C001: OpenClaw Connector Beta foundation

## Status

Accepted as a discovery-only foundation for development identity
`1.4.0-alpha.1-dev.1`.

## Decision

The published NodeRooms OpenClaw `1.3.0` release remains the immutable stable
baseline. Connector Beta development continues only on
`feature/noderooms-openclaw-connectors-beta` with a distinct development
identity.

C001 adds a strict, non-live manifest that can bind a connector only when all
of these dimensions are exact:

- OpenClaw host and plugin API versions;
- runtime inventory snapshot fingerprint;
- effective owner kind and owner ID;
- owner/plugin/channel/MCP version and its evidence source;
- provider, connector ID, and connector version;
- effective tool name and input-schema SHA-256;
- canonical profile, scope, action, resource, replay, risk, approval, and
  receipt metadata.

NodeRooms stores only these bounded identities and fingerprints. OpenClaw
remains the credential custodian.

## Reference fixture

The existing GitHub Draft PR contract fixture proves the C001 shape because it
already has one exact MCP owner, connector version, tool name, schema
fingerprint, and canonical policy profile. Its C001 status is
`reference_only`, and its authority status is
`discovery_only_no_authority`.

The reference fixture is not an installed GitHub connector and is not an
email, Discord, WhatsApp, or SMS implementation. Those families are admitted
by the contract but require their own exact runtime captures and policy
profiles in later phases.

## Phase boundary

C001 does not:

- wire the new module into `src/index.js`;
- add or change an OpenClaw public tool;
- log in to a provider;
- read or store provider credentials;
- persist raw tool schemas, parameters, results, messages, or email bodies;
- call `tools.catalog`, `tools.invoke`, a connector, network, or provider;
- automate a Verified Human Owner decision;
- enable `enforce`, dispatch, retry, reconciliation, or external write;
- modify a Gateway, NodeRooms production, ClawHub, npm, or `latest`.

Email read/draft work begins only in C002 after an exact, trusted runtime
capture. Discord, WhatsApp, and SMS inventory work begins only in C003. The
first provider write remains a separate C004 Owner-approved proof.

## Evidence

Run:

```text
node --test tests/connector-beta-foundation.test.mjs
node scripts/connector-beta-foundation-proof.mjs
```

The test must emit `NR_OC_CONNECTOR_BETA_C001=PASS`. The proof must show one
exact reference connector and tool, a matching schema fingerprint, zero
unclassified or drifted bindings, and zero live authority or side effects.
