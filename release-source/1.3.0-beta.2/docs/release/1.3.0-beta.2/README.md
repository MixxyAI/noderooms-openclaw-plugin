# NodeRooms OpenClaw 1.3.0-beta.2 release evidence

## Current decision

`HOLD` — the candidate may be built and dry-run validated, but it must not be
published while any blocking entry in `release-gate.json` is not `PASS`.

The implementation-side isolation gates pass locally. Publication remains
blocked by:

1. the pinned ClawHub reusable workflow completing a remote dry-run against
   the hash-gated artifact;
2. an independent external two-Agent and nine-Agent pre-test;
3. truthful public NodeRooms UX that labels the OpenClaw Guest as
   `UNVERIFIED` and does not imply a verified human Owner;
4. exact public Beta.2 installation and `/noderooms commit <intent_id>`
   instructions;
5. public activity copy that does not claim unverified Guest activity can only
   come from verified Agent flows.

## Local proof recorded on 2026-07-28

- supported runtime: Node.js 24.18.0;
- exact candidate SHA-256:
  `909016696cbcc9931c535b05f77b644bc55e792432a8a611a5b3f810024d17a2`;
- full test suite: 265 test events, 264 passes, 0 failures,
  1 intentional skip;
- production dependency audit: 0 vulnerabilities;
- ClawHub 0.23.1 runtime inspector: PASS, 0 breakages, 0 warnings;
- exact candidate archive installed through OpenClaw `npm-pack:` semantics
  into a fresh isolated state, loaded all 14 tools with no diagnostics, and
  produced a byte-identical installed `dist/index.js`;
- deterministic two-Agent isolation: PASS;
- concurrent nine-Agent isolation: PASS;
- official OpenClaw loader two-Agent execution: PASS;
- Agent-local Guest entry serialization, coalescing, and cleanup
  cancellation: PASS;
- legacy default-Agent identity move-only migration: PASS;
- restart secret destruction and cross-Agent rejection: PASS;
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

Until publication, the integration page must say that Beta2 is unavailable
and must not show an unversioned install command as a working release path.
After every gate passes, the install command must pin:

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
