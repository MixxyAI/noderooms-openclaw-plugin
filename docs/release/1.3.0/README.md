# NodeRooms OpenClaw 1.3.0 stable promotion evidence

Stable `1.3.0` promotes the exact externally verified `1.3.0-beta.2` runtime
to the ClawHub `latest` channel. Beta.1 and Beta.2 release sources remain
immutable.

The promotion intentionally changes no connector behavior or authority. The
runtime-package delta is limited to:

- package, OpenClaw manifest, and client version identity `1.3.0`;
- stable README, changelog, and security wording.

All other packaged files must remain byte-identical to Beta.2. The promotion
workflow enforces that invariant before it can build or validate the stable
artifact.

## Proven predecessor

```text
repository main: 85bc9985ab599178913f4ad7bf23b0a4df4ad443
Beta.2 package: 909016696cbcc9931c535b05f77b644bc55e792432a8a611a5b3f810024d17a2
Beta.2 publish run: 30439110714
Beta.2 ClawHub release: rd70zhfkejk4ha0t55f9g2nvqs8bf980
Stage G summary: b1c9675f340388603a6484f0439f9f35b6f81c6407915ad4cc7a4e859c2ff7ae
Stage G loader: 14 tools / 0 diagnostics
public content modified by Stage G: no
```

The canonical NodeRooms Integrations page, Developers page, public integration
JSON, and well-known manifest are unified on the canonical ClawHub URL and
truthful published Beta.2 state. Their final smoke reported zero legacy URLs
and zero release-hold phrases.

## Fail-closed stable sequence

1. The stable candidate branch and draft PR contain one exact package SHA-256.
2. Normal plugin CI runs the complete suite and ClawHub runtime validation.
3. The new stable workflow rebuilds the package, verifies both immutable Beta
   predecessors, enforces the restricted source and packaged-runtime delta, and
   calls the pinned ClawHub reusable workflow with `dry_run=true`,
   `version=1.3.0`, and `tags=latest`.
4. The machine gate remains `HOLD` and `publication_allowed=false` until those
   trusted PR checks are independently observed and recorded.
5. Publication requires a fresh workflow dispatch from merged `main`, the
   exact human confirmation `PUBLISH 1.3.0 STABLE`, a PASS machine gate, and
   `tags=latest`.
6. No failed or old workflow run may be rerun.

Post-publication checks must prove both exact-version and versionless install
resolution, `14 tools / 0 diagnostics`, the live read-only NodeRooms path, and
that `latest` moved from `1.1.2` to `1.3.0`. No NodeRooms production change is
part of the stable ClawHub publication.
