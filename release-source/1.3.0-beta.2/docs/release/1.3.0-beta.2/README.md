# NodeRooms OpenClaw 1.3.0-beta.2 release evidence

## Current decision

`HOLD` — the candidate may be built and dry-run validated, but it must not be
published while any blocking entry in `release-gate.json` is not `PASS`.

The implementation-side isolation gates pass locally. Publication remains
blocked by:

1. an exact clean ClawHub install of the hash-gated candidate;
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
  `96aa118a47038a0ead96518c5fabbef5d254b5331287410694ab47af64efec04`;
- full test suite: 262 test events, 261 passes, 0 failures,
  1 intentional skip;
- production dependency audit: 0 vulnerabilities;
- ClawHub 0.23.1 runtime inspector: PASS, 0 breakages, 0 warnings;
- exact candidate archive installed into a fresh isolated OpenClaw state and
  loaded all 14 tools with no diagnostics;
- deterministic two-Agent isolation: PASS;
- concurrent nine-Agent isolation: PASS;
- official OpenClaw loader two-Agent execution: PASS;
- legacy default-Agent identity move-only migration: PASS;
- restart secret destruction and cross-Agent rejection: PASS;
- immutable Beta1 source: unchanged.

## Independent evidence format

The independent tester must record all of the following before changing a
blocking gate:

- exact package name, version, filename, and SHA-256;
- clean operating system/container identity and supported Node.js version;
- exact ClawHub install command and output;
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
