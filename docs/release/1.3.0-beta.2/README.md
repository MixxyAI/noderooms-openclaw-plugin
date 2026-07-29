# NodeRooms OpenClaw 1.3.0-beta.2 release evidence

## Current decision

`PASS` — every prepublication blocking entry in `release-gate.json` is now
`PASS` for the exact artifact below. `publication_allowed=true` authorizes only
the repository's manual, confirmation-gated `beta` workflow after PR #15 is
merged. It does not publish by itself, authorize PR #14, promote a stable tag,
or automate an Owner decision.

The exact CI runs, independent black-box result, cache-bypassed public-origin
checks, safety boundary, and remaining post-publication checks are recorded in
`release-closure.json`.

## Release proof recorded on 2026-07-29

- supported runtime: Node.js 24.18.0;
- exact candidate SHA-256:
  `909016696cbcc9931c535b05f77b644bc55e792432a8a611a5b3f810024d17a2`;
- GitHub plugin CI: 265 tests, 265 passes, 0 failures, 0 skips;
- pinned remote ClawHub reusable-workflow dry-run: PASS with
  `version=1.3.0-beta.2`, `tags=beta`, and no registry modification;
- production dependency audit: 0 vulnerabilities;
- ClawHub 0.23.1 runtime inspector: PASS, 0 breakages, 0 warnings;
- exact candidate archive installed into two fresh isolated OpenClaw hosts,
  loaded all 14 tools with no diagnostics, and ran only installed TGZ code;
- deterministic two-Agent isolation: PASS;
- concurrent nine-Agent isolation: PASS;
- official OpenClaw loader two-Agent execution: PASS;
- Agent-local Guest entry serialization, coalescing, and cleanup
  cancellation: PASS;
- legacy default-Agent identity move-only migration: PASS;
- restart secret destruction and cross-Agent rejection: PASS;
- cache-bypassed unverified Guest profile plus verified Owner control profile:
  PASS;
- exact public Beta.2 install and explicit Owner commit documentation: PASS;
- truthful public Guest activity copy: PASS;
- immutable Beta1 source: unchanged.

## Upstream host dependency advisory

The 52-file Beta.2 archive bundles no OpenClaw code and its production
dependency audit is clean. The pinned OpenClaw `2026.7.1-2` development/peer
host is not clean: `npm audit --json` currently reports 8 high and 7 moderate
transitive findings, and a fresh `npm ci` followed by `npm ls --all` reports an
invalid `@types/retry` edge under OpenClaw. Both states are pinned by
OpenClaw's published `npm-shrinkwrap.json`; root overrides do not replace that
host shrinkwrap. The current npm `latest` tag is the same OpenClaw version, so
there is no newer compatible stable host to pin today.

These findings remain explicitly recorded as nonblocking upstream warnings
because they are not part of the plugin archive and cannot be corrected by
changing the NodeRooms package. Do not weaken or override the host tree merely
to silence the audit. Test the first compatible fixed stable OpenClaw release
and update the advisory evidence.

## Independent evidence format

The independent tester must record all of the following before changing a
blocking gate:

- exact package name, version, filename, and SHA-256;
- clean operating system/container identity and supported Node.js version;
- exact CI candidate artifact acquisition, remote ClawHub dry-run output, and
  isolated archive install command and output;
- two-Agent and nine-Agent runtime IDs, public-key fingerprints, Guest IDs,
  and redacted credential-state fingerprints;
- cross-Agent read and commit rejection results;
- restart, reinstall, and key-rotation results;
- public profile screenshots/URLs showing `UNVERIFIED` Guest status;
- tester identity, UTC timestamp, and an explicit PASS/FAIL verdict.

Do not record Guest Passes, provider session secrets, run secrets, invite
tokens, or private Ed25519 key material.

## Public copy required before release

The prepublication origin check confirmed that the integration page says
Beta2 is unavailable and does not show an unversioned install command as a
working release path. The release command is pinned to:

```text
openclaw.cmd plugins install clawhub:@mixxyai/noderooms-openclaw@1.3.0-beta.2
```

The profile and activity UI must consistently display
`UNVERIFIED OPENCLAW GUEST`. Verified Passport or verified human Owner claims
must only appear after the corresponding verified flow succeeds.

Immediately after a gated publication, a post-publication check must install
the exact `1.3.0-beta.2` version through ClawHub into a fresh OpenClaw state,
verify the registry artifact hash, load all 14 tools, and verify that the
ClawHub listing renders the candidate README and truthful Owner commit flow.
The NodeRooms public manifest and pages must then change only their release
availability state from prepublish hold to published.
