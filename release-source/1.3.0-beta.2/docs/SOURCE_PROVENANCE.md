# Source provenance and branch structure

Trust Middleware Alpha 1 pull request
[#1](https://github.com/MixxyAI/noderooms-openclaw-plugin/pull/1) was merged
into `main` as:

```text
merge commit: e9ba2c9ba48fc2200d2f3af603f5e0036a2c76f7
parent 1:     a4886cccc68b1875dbc1c224e3fdf7f1ae9705c9
parent 2:     646b7ce205b6ba6a0ec551ff6f7f4a074ccd54c1
main tree:    b44d4cb79f4e7c13b80bcbe5910945895ac3be65
```

The first parent introduced the exact published `1.3.0-beta.1` source under:

```text
release-source/1.3.0-beta.1
```

That release-source directory is immutable and remains the provenance input for
the published Beta.1 artifact. Its Git tree at the merge commit is:

```text
43f43635714769503ae33677a45fc1c12beb2753
```

The merged Alpha 1 history promoted the exact Beta.1 package source to the
repository root before adding the disabled-by-default trust middleware. This is
why pull request #1 contained a large source-layout diff from the older 1.1.2
TypeScript root.

At that historical merge point, the repository root was unpublished
development version `1.3.0-beta.2-dev.1`. The original trusted publication
workflow remains pinned to the immutable Beta.1 release source, with SHA-256:

```text
111b196aa36929eb2d8f49aaf70011455bbbf010dc44df5eb7073f95cafde248
```

`NR-OC-TRUST-002A` adds repository-only connector contract documents, fixtures,
and read-only tests on top of this merge state. It does not change the published
Beta.1 source or publication workflow.

Pull request
[#2](https://github.com/MixxyAI/noderooms-openclaw-plugin/pull/2) merged the
reviewed 002A head into `main` as:

```text
merge commit: 51405009593f0ea42c36c8338eacddff470a741c
parent 1:     e9ba2c9ba48fc2200d2f3af603f5e0036a2c76f7
parent 2:     b90da616ab9c7810da529ac203f4f0e152445eec
```

`NR-OC-TRUST-002B` is based on that exact merge and adds the contract-only
Agent–Passport–Verified Owner–OpenClaw runtime binding foundation. It does not
alter the published Beta.1 source or publication workflow.

Pull request
[#3](https://github.com/MixxyAI/noderooms-openclaw-plugin/pull/3) merged the
reviewed 002B head into `main` as:

```text
merge commit: 40513b13722745ec25eca34f5b73ff3a90ea98b6
parent 1:     51405009593f0ea42c36c8338eacddff470a741c
parent 2:     d3084f9bc23e4330fa724e5920a4ecb0a72af571
```

`NR-OC-TRUST-002C` is based on that exact merge and adds the contract-only
Verified Human Owner capability review and run-lease v2 validation foundation.
It does not alter the published Beta.1 source or publication workflow.

Pull request
[#4](https://github.com/MixxyAI/noderooms-openclaw-plugin/pull/4) merged the
reviewed 002C head into `main` as:

```text
merge commit: dbcb681b6f8191be4953c5ee026d9315d250fe05
parent 1:     40513b13722745ec25eca34f5b73ff3a90ea98b6
parent 2:     403d82301ae3d7c81a757448593133096d05b599
```

`NR-OC-TRUST-002D` is based on that exact merge and adds the contract-only
canonical external-action intent, dispatch reservation, signed receipt, and
read-only reconciliation foundation. It does not alter the published Beta.1
source or publication workflow.

Pull request
[#5](https://github.com/MixxyAI/noderooms-openclaw-plugin/pull/5) merged the
reviewed 002D head into `main` as:

```text
merge commit: 633b7f28306819150a7ac5a75f4239c760628478
parent 1:     dbcb681b6f8191be4953c5ee026d9315d250fe05
parent 2:     129f874e093b8946c23d4f0914f8e9039f3c6ac2
```

`NR-OC-WORK-003A` is based on that exact merge and adds the contract-only
NodeRooms Workdesk, OpenClaw Workboard, managed Task Flow, and public-safe work
receipt mapping. It does not alter the published Beta.1 source or publication
workflow.

Pull request
[#6](https://github.com/MixxyAI/noderooms-openclaw-plugin/pull/6) merged the
reviewed 003A head into `main` as:

```text
merge commit: 98daacaaa9deea2a543f76d8b4e89adf0e0b516c
parent 1:     633b7f28306819150a7ac5a75f4239c760628478
parent 2:     d9e94f2894049eb05d85ada9981bc0c46b2e78bb
```

`NR-OC-WORK-003B` is based on that exact merge. It imports the strict 003A work
item validator into one disabled-by-default local shadow bridge. The bridge
uses the public managed Task Flow API and a guarded `workboard_create` agent
tool call; it does not use cross-plugin Gateway RPC. It does not alter the
published Beta.1 source or publication workflow.

Pull request
[#7](https://github.com/MixxyAI/noderooms-openclaw-plugin/pull/7) merged the
reviewed 003B head into `main` as:

```text
merge commit: 09907fb745523a2c0b1f4784982efc31d1500a68
parent 1:     98daacaaa9deea2a543f76d8b4e89adf0e0b516c
parent 2:     1106bf97c55824d374030b02acea5766be33a10b
```

`NR-OC-WORK-003C` is based on that exact merge. It adds only an isolated
real-loader/runtime proof, tests, and documentation. The proof creates
disposable OpenClaw state, config, and workspace roots and removes them after
each run. It does not alter the 003B live source, plugin manifest, immutable
Beta.1 release source, publication workflow, a deployed Gateway, or
production.

Pull request
[#8](https://github.com/MixxyAI/noderooms-openclaw-plugin/pull/8) merged the
reviewed 003C head into `main` as:

```text
merge commit: 67d2435225d74832c29d8ec1271f1bc8ad85b491
parent 1:     09907fb745523a2c0b1f4784982efc31d1500a68
parent 2:     908191a1451f058ce56133f5f328ffe575b7484d
```

`NR-OC-WORK-003D` is based on that exact merge. It adds the deterministic
Phase 3 closure proof and read-only tests. It does not alter the published
Beta.1 source or publication workflow.

Pull request
[#9](https://github.com/MixxyAI/noderooms-openclaw-plugin/pull/9) merged the
reviewed 003D head into `main` as:

```text
merge commit: d11c4ef7a6796bafe2254c7c9a9a1b503d971661
parent 1:     67d2435225d74832c29d8ec1271f1bc8ad85b491
parent 2:     fdb01269bf00f9b660d8486488e034f8c1f9e1a8
```

`NR-OC-CONNECTOR-004A` is based on that exact merge. It adds the validated
runtime tool inventory foundation while keeping connector use disabled and
reference-only. It does not alter the published Beta.1 source or publication
workflow.

Pull request
[#10](https://github.com/MixxyAI/noderooms-openclaw-plugin/pull/10) merged the
reviewed 004A head into `main` as:

```text
merge commit: 53c348c401273b3a32fb8771baa5323dbf60e56a
parent 1:     d11c4ef7a6796bafe2254c7c9a9a1b503d971661
parent 2:     b2050872e0a49920e0b24ada1ffc6389899df533
```

`NR-OC-CONNECTOR-004B` is based on that exact merge. It adds the signed,
fail-closed canonical connector policy-sync foundation. It does not alter the
published Beta.1 source or publication workflow.

Pull request
[#11](https://github.com/MixxyAI/noderooms-openclaw-plugin/pull/11) merged the
reviewed 004B head into `main` as:

```text
merge commit: 50af96e0e0da80adac96eb4409cd14b758498d45
parent 1:     53c348c401273b3a32fb8771baa5323dbf60e56a
parent 2:     1680062fb218203dfdf931d6313f4b3c510d9dc1
```

`NR-OC-CONNECTOR-004C` is based on that exact merge. It adds one isolated,
Owner-approved GitHub Draft PR end-to-end controller, exact canonical-to-MCP
transport binding, create-once dispatch reservation, signed receipt, replay
block, read-only reconciliation, and sticky revocation proof.

Pull request
[#12](https://github.com/MixxyAI/noderooms-openclaw-plugin/pull/12) merged the
reviewed and hardened 004C head into `main` as:

```text
merge commit: c77757948e052b06d6a61077c4703e39be656509
parent 1:     50af96e0e0da80adac96eb4409cd14b758498d45
parent 2:     006c9481442d9b730601499939e2a4398e414fd9
main tree:    80a62f0a3314491bc864008f4e7f86bffd865bd9
```

The exact merge commit passed the full `246 pass / 0 fail / 1 skip` regression,
ClawHub package validation with zero breakages, warnings, deprecations, or
issues, and a non-publishing package dry-run. The feature branch remains
preserved. No package was published or installed, no Gateway was changed or
restarted, and production was not modified.

Important boundaries:

- `release-source/1.3.0-beta.1` is not modified.
- `.github/workflows/package-publish.yml` remains pinned to exact Beta.1 for
  immutable validation, and its publish job is disabled.
- `server-reference/` is a test/reference fixture and is not included in the npm
  package allowlist.
- the repository-root development source is not a ClawHub publication source.
- connector registry profiles with `status: reference_only` cannot authorize a
  live tool call.
- runtime binding fixtures with `activation_state: contract_only` cannot
  authorize a live tool call.
- capability requests, Owner decisions, and run leases with
  `activation_state: contract_only` cannot authorize a live tool call.
- external-action intents and receipts with
  `activation_state: contract_only` cannot authorize a live tool call, dispatch
  a provider write, or update Agent reputation.
- Phase 3A work items, work receipts, Workboard bindings, and Task Flow
  bindings with `activation_state: contract_only` cannot create a card, claim
  work, start a child task, dispatch a provider write, or update Agent
  reputation.
- Phase 3B accepts a non-fixture contract-only work item only for an
  Owner-bound local shadow mirror. It may create one unclaimed review card and
  one waiting managed Task Flow, but cannot claim or dispatch the card, start
  a Task Run, resume a flow, invoke a connector, retry an uncertain create, or
  perform an external write.
- Phase 3C link-installs only into a disposable test profile. It starts no
  Gateway, invokes no connector or external network, and removes the isolated
  state after proving loader, restart, reconcile, and cancel behavior.
- `workRuntime.mode` defaults to `off`; `armed` activation is not exposed and
  remains hard-blocked.
- source-language refactoring is a separate change and must preserve the
  tested runtime contract.

## Beta.2 isolation repair candidate

The forensic audit of main commit
`643b526ca50d7885632979f1eb1e241dc9a1e51f` reproduced a critical
multi-Agent defect in both the published Beta.1 source and the then-current
root development source. The baseline Beta.1 ClawPack remains immutable at:

```text
release-source/1.3.0-beta.1
SHA-256: 27f9fa2a5d4f3af9ed5aa984d6c8b260c9298f0292749fa698839c70e256ea27
```

The separate `1.3.0-beta.2` candidate introduces Agent-scoped runtime bundles,
private identities, credential state, tool factories, and intent execution
routing. Its immutable publication-candidate source and reproducible package
hash are:

```text
release-source/1.3.0-beta.2
SHA-256: d4839309193fb66696fdb3fa497b0193ef47a676d6db92f2353057f3fa6b4c5f
```

Two clean packs produced that same SHA-256. A fresh lockfile installation of
the release source passed 264 of 265 test events with 0 failures and
1 intentional skip; ClawHub 0.23.1 runtime inspection reported 0 breakages and
0 warnings. The machine-readable decision is
`docs/release/1.3.0-beta.2/release-gate.json`. The candidate preserves the
Beta.1 directory byte-for-byte.

Beta.2 is not eligible for publication solely because local tests pass.
Publication also requires:

- the pinned remote ClawHub reusable workflow to pass in dry-run mode against
  the exact hash-gated artifact;
- a real independent external 2-Agent and 9-Agent proof;
- corrected public install/version and explicit Owner commit instructions;
- a public Guest profile that does not claim a verified human Owner;
- truthful public activity copy for unverified Guest activity;
- a final immutable release-source tree and reproducible ClawPack hash.

OpenClaw `2026.7.1-2` publishes its own shrinkwrap, which currently pins
host-only audit findings and an invalid `@types/retry` edge. Those dependencies
are not bundled in the plugin archive and the plugin's production audit is
clean, so the machine-readable gate records them as nonblocking upstream
warnings. They must be retested against the first compatible fixed stable
OpenClaw host. Immediately after any gated publication, the exact registry
version must also pass a clean ClawHub install, 14-tool load, hash check, and
listing-copy verification.
