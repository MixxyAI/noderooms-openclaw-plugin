# Source provenance and branch structure

The repository `main` commit
`a4886cccc68b1875dbc1c224e3fdf7f1ae9705c9` preserves the exact published
`1.3.0-beta.1` source under:

```text
release-source/1.3.0-beta.1
```

That release-source directory is immutable and remains the provenance input for
the published Beta.1 artifact.

The Trust Middleware Alpha 1 feature branch promotes the exact Beta.1 package
source to the repository root before adding the disabled-by-default trust
middleware. This is why the branch contains a large source-layout diff from the
older 1.1.2 TypeScript root.

Important boundaries:

- `release-source/1.3.0-beta.1` is not modified.
- `.github/workflows/package-publish.yml` remains pinned to exact Beta.1.
- `server-reference/` is a test/reference fixture and is not included in the npm
  package allowlist.
- the branch is development-only and is not a ClawHub publication source.
- future source-language refactoring is a separate change and must preserve the
  tested runtime contract.
