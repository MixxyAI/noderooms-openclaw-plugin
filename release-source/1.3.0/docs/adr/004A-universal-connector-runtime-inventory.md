# ADR 004A: Universal Connector runtime tool inventory

## Status

Accepted as an inventory-only, non-live Phase 4 foundation.

## Decision

NodeRooms inventories every tool returned by the OpenClaw runtime catalog. Each
inventory entry has an exact effective tool name and an explicit owner
classification:

- OpenClaw core;
- native plugin;
- channel;
- MCP server.

When the host or a canonical connector profile supplies the declarations, the
entry also binds:

- input-schema SHA-256;
- output or canonical receipt profile;
- declared replay safety and replay semantics;
- side-effect class;
- risk;
- canonical scope and approval policy;
- coverage and drift status.

The inventory is refreshed at Gateway start. An unknown tool observed later is
recorded by name only and marks the inventory stale. It never records raw
parameters or results.

## Current OpenClaw boundary

OpenClaw `2026.7.1-2` exposes the read-only `tools.catalog` Gateway method, but
that result does not include tool input schemas or MCP server identity for
every effective MCP tool. NodeRooms does not infer either value from a
description, parameter sample, or model output.

Therefore:

- a catalog tool without its exact input schema is `schema_unavailable`;
- an MCP tool without an exact server owner is `owner_unresolved`;
- an unknown side-effecting tool remains unclassified;
- schema or policy mismatch is explicit drift;
- every such entry has `enforce_eligible=false`.

The exact GitHub Draft PR descriptor fixture demonstrates the complete
contract shape. It remains `covered_contract_only`; it is not live authority.

## Owner inspection

The existing authenticated `/noderooms` command adds four read-only views:

```text
/noderooms coverage
/noderooms connectors
/noderooms lease
/noderooms receipts
```

They require the authenticated human OpenClaw Owner. They expose only
public-safe or Owner-private metadata and never expose a run secret, provider
credential, raw tool parameter, or raw result.

## Safety boundary

004A:

- calls only the internal, read-only OpenClaw `tools.catalog` method;
- does not call `tools.invoke`;
- does not execute a tool or connector;
- does not perform an external network request or write;
- does not activate `enforce`;
- does not automate an Owner decision;
- does not grant Phase 4B policy-sync or Phase 4C GitHub-write authority.

## Evidence

Run:

```text
node --test tests/universal-connector-tool-inventory.test.mjs
node scripts/universal-connector-inventory-proof.mjs
```

The tests must emit `NR_OC_CONNECTOR_004A=PASS`. The proof must show 100%
inventory completeness for the supplied catalog, exact GitHub schema matching
for the contract descriptor, fail-closed handling of the host catalog schema
gap, and zero execution or external write.
