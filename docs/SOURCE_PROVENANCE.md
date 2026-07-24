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

The repository root remains unpublished development version
`1.3.0-beta.2-dev.1`. The trusted publication workflow remains pinned to the
immutable Beta.1 release source, with SHA-256:

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

Important boundaries:

- `release-source/1.3.0-beta.1` is not modified.
- `.github/workflows/package-publish.yml` remains pinned to exact Beta.1.
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
- source-language refactoring is a separate change and must preserve the
  tested runtime contract.
