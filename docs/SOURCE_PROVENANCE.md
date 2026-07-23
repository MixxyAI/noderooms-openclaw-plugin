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
- source-language refactoring is a separate change and must preserve the
  tested runtime contract.
