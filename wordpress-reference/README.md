# NodeRooms WordPress Gmail control-plane reference

This directory is the reviewed Alpha6 patch set for the existing
`agent-guild-os` WordPress plugin. It is not a standalone plugin and it contains
no private configuration, provider credential, OAuth token, or deployment key.

## Exact files

- `agent-guild-os.php` loads the connector control plane.
- `includes/class-ago-permission-scope-engine.php` declares the Gmail scope
  catalog, including permanently denied Delete/Trash.
- `includes/class-ago-trustbridge-connectors.php` implements the NodeRooms
  owner routes, schema v3, Agent-private Ed25519 worker pairing, signed v2 job
  protocol, purpose/target capability and one-action run-lease envelopes,
  exact-draft `allow_once` send reservation, receipts, and fail-closed states.
- `templates/owner-dashboard.php` contains the NodeRooms-only `Connect to Gmail`
  switch and capability-purpose controls.

The customer workflow is always:

```text
NodeRooms Owner
→ exact owner-bound active Passport Agent / TrustBridge
→ Owner-approved purpose- and target-bound capability
→ active one-action scoped run lease
→ invisible background runtime
→ Gmail search, thread read, unsent draft, or exact approved-draft send
→ result in NodeRooms
```

## Deployment boundary

Production rollout must be a separate, hash-gated operation against a fresh
read-only capture of the exact Kinsta files. Do not apply this reference over a
drifted file and do not rerun any rolled-back R2–R5 deployment.

Before enabling the runtime:

1. compare the four production files with their approved pre-change hashes;
2. lint all PHP files and apply schema v3 only through the explicitly approved
   WP-CLI migration gate;
3. provision the internal one-use worker pairing for the exact Agent/Passport;
4. configure storage and receipt keys outside the public web root;
5. verify the owner dashboard hard-denies without a live Owner binding,
   Passport, paired worker, capability, or run lease;
6. execute an external-user E2E in order: connect, search, thread read, create
   draft, inspect exact draft, approve once, send once, repeat-send denial,
   disconnect;
7. verify Delete/Trash has no route and uncertain writes never retry.

The runtime stays default-off until all gates pass. The stable npm/ClawHub
`1.3.0` release and production are not modified by this reference directory.
