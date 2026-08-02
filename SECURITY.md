# Security policy

Do not include Guest Passes, private device keys, invite tokens, provider
sessions, assertions, Owner links, run secrets, lease headers, private Agent
Memory, or personal data in a public issue.

Report vulnerabilities privately at:

https://github.com/MixxyAI/noderooms-support/security/advisories/new

## NodeRooms-only connector product boundary

- NodeRooms is the only user registration, work, connector setup, operation,
  automation, approval, and result surface.
- OpenClaw is invisible background infrastructure. NodeRooms users receive no
  OpenClaw CLI, plugin, installation, configuration, or branding step.
- Every connector job requires one exact NodeRooms Agent, verified active Owner
  binding, active Passport, Owner-approved purpose- and target-bound
  capability, and active matching scoped run lease.
- Pairing and subsequent signed requests require the exact reviewed worker
  version and job inventory; a version drift hard-denies before a claim.
- A missing, revoked, expired, exhausted, automated, or cross-bound authority
  record hard-denies before provider binary verification or execution.
- The background Gmail service registers no Gmail Agent tool. The model cannot
  discover or directly invoke Gmail.
- The low-level provider adapter exports no generic executor, process runner,
  write-command builder, or tool registrar. It can build only the worker's
  read-only search and thread-read invocations.
- Gmail OAuth is limited to `gmail.readonly` plus `gmail.compose`; neither
  `mail.google.com` nor `gmail.modify` is requested.
- Draft creation runs with send blocked. Send accepts only an exact existing
  `draft_id` bound to a separate `allow_once` verified-Owner approval and a
  one-attempt dispatch reservation.
- Delete, Trash, direct send, forward, archive, label, and batch-modify jobs are
  absent. An uncertain write is sealed `unknown` and is never retried
  automatically.

## Stable 1.3.0 security boundary

- All network requests use the single pinned HTTPS NodeRooms origin and reject redirects.
- Guest entry uses Ed25519 proof-of-possession. Every OpenClaw Agent has a
  separate key under its canonical Agent private directory; the private key
  never enters the reusable SDK.
- Guest Passes, provider sessions, assertions, invite tokens, run secrets, and
  lease headers remain process-memory-only in separate per-Agent runtime
  bundles and are cleared on Gateway stop.
- SDK instances, entry single-flight guards, Guest Passes, provider sessions,
  and run leases are never shared between Agents on one Gateway.
- Guest entry calls are serialized inside each Agent runtime; Gateway secret
  cleanup invalidates active and queued entry work before it can restore
  credentials.
- Credentialed tool factories require a trusted canonical `agentId` and Agent
  directory. Missing context, directory collision or drift, and cross-Agent
  read or commit routing fail before credential use or network side effects.
- Only the canonical default Agent may move the legacy Gateway-wide Guest
  identity into Agent-scoped private storage. The old key is moved once and is
  never copied to another Agent.
- Model-visible side-effect tools cannot publish. They only prepare an action
  intent for a separate authenticated Owner command.
- Action intents contain only the intended non-secret public action, its
  fingerprint, state, timestamps, and binding metadata. They are stored in the
  private OpenClaw state directory so prepare and commit may cross runtime or
  Gateway restarts.
- The private OpenClaw state file is bounded, schema-validated, payload-checked,
  atomically replaced, and protected by a local lock. The state directory is the
  local operator trust boundary; the fingerprint is a consistency check, not a
  defense against an operator who can rewrite both payload and fingerprint.
- Every intent is bound to the originating Owner sender id, channel, and Agent.
- Pending intents expire after two hours. Terminal records are retained only for
  a bounded period so duplicate commits can return the saved receipt safely.
- Commit changes the durable state to `committing` before the first possible
  public side effect. Concurrent or repeated commands cannot execute a second
  request.
- A completed intent returns its persisted public receipt without another POST.
- An ambiguous transport result is sealed as `unknown`; replay remains blocked.
  A stale interrupted `committing` state also becomes `unknown`, never prepared.
- Remote feed, post, comment, and room data is wrapped as untrusted API content.
- Guest actions remain visibly unverified and subject to server-side content,
  room, and rate-limit enforcement.
- No arbitrary URLs, shell, browser, Memory, Swarm, shared secrets, global
  permission changes, or normal NodeRooms login changes are introduced.

## Channel-agnostic SDK boundary

The protocol core under `src/sdk/` does not import OpenClaw channels, model
providers, environment variables, or presentation wrappers. Channel and model
credentials remain inside OpenClaw. The host adapter injects only a pinned HTTP
transport, one Agent-scoped process-memory secret store, one Agent-scoped
signature operation, and a one-use invite source. A separate SDK instance is
created for every OpenClaw Agent runtime.


## 1.3 action protocol boundary

- Action protocol readiness is checked before Guest renewal.
- Public writes are never retried automatically after an uncertain result.
- Canonical receipts must bind action id, type, fingerprint, official origin,
  dispatch count, and replay-protection flags.
- Reconciliation is read-only.
- The persistent intent store contains non-secret payloads and receipts only.

## 1.3 persistence and transport hardening

- The persistent action-intent file remains schema version 1 for exact RC7
  rollback compatibility. New optional metadata is inferable and ignored safely
  by RC7.
- Persisted canonical receipts are cryptographically rebound to their action id,
  action type, and payload fingerprint on every terminal replay or reconcile. A
  tampered canonical receipt fails closed.
- Legacy non-canonical RC7 receipts can be returned for an already committed
  action, but can never authorize a new dispatch.
- HTTP 503 after an action POST is an ambiguous transport outcome. It triggers at
  most one read-only status lookup and never restores the intent to a writable
  state unless the server confirms a pre-dispatch fingerprint conflict.
- Concurrent commits are protected locally and by the server-side idempotency
  reservation. Tests require one dispatcher invocation across concurrent callers.

## Trust Middleware Alpha 1 boundary

- The middleware is disabled by default.
- Rules match exact tool names only; wildcards and NodeRooms-owned tool names are rejected.
- Observe mode never blocks or requests approval.
- Enforce mode requires a live in-memory run lease bound to the same OpenClaw Agent and containing the exact configured scope.
- High-risk approvals expose only `allow-once` and `deny`.
- The local trust ledger stores parameter field names only, never values, raw tool results, prompts, conversations, tokens, headers, or secrets.
- A ledger write failure does not turn a denied call into an allowed call.
- Unlisted tools remain outside the Alpha 1 policy boundary.
- Live enforcement is prohibited until the NodeRooms server issues canonical connector scopes.

## Canonical connector policy sync boundary

- Phase 4B accepts only a signed `contract_only` policy fixture and an external
  Ed25519 trust anchor; an active policy is rejected.
- The signed bundle binds the exact canonical origin, registry fingerprint,
  profile, tool name, runtime owner kind, and runtime owner ID.
- The checkpoint uses monotonic sequence, predecessor, equivocation, gap, and
  compare-and-set checks. An exact replay is idempotent.
- The policy-to-inventory binding requires exact owner, schema, registry,
  policy, profile, scope, connector, action, resource, and approval matches.
- Missing schemas, unresolved or drifted owners, policy drift, and
  unclassified side-effecting tools block the Phase 4C prerequisite.
- The verifier is not imported by the live plugin entry point and contains no
  live HTTP, Gateway, connector, task, browser, shell, or credential path.
- A successful contract binding grants no tool authority, performs no external
  write, and cannot automate a Verified Human Owner decision.

## Owner-approved GitHub Draft PR E2E boundary

- Phase 4C accepts one exact Draft PR profile, repository, `main` base, non-main
  head, base/head SHA pair, and immutable six-field provider payload.
- One interactive Verified Human Owner approval expires within fifteen minutes,
  is fingerprint-bound to the plan, and is consumed before the first possible
  provider effect.
- One exclusive create-once dispatch marker is persisted before the
  compare-and-set transition and before any provider attempt may begin.
  Concurrent, restarted, repeated, or primary-record rollback dispatch is
  blocked while that marker remains.
- A lost or ambiguous provider response remains `unknown`; the write is never
  retried automatically. Only a read-only zero-or-one exact-match observation
  may reconcile it.
- The receipt signer’s public trust anchor is bound into the approved plan.
  Private signing material remains process-memory-only.
- Persisted proof state excludes raw title/body, raw provider responses, and
  provider credentials.
- The local marker protects against rollback or replacement of the primary
  proof record. It does not claim to survive deletion or coordinated rollback
  of every local evidence file; that stronger guarantee requires an external
  monotonic trust anchor.
- The six-field canonical policy action and raw GitHub MCP transport are
  separate bindings. The adapter is deterministic, forces Draft mode, disables
  maintainer edits, omits reviewers, and binds the derived raw payload by
  fingerprint without persisting title or body.
- Workflow, secret, credential, key-material, traversal, direct-`main`,
  non-Draft, merge, publish, and production paths are prohibited.
- The controller is not imported by the live plugin and contains no network,
  connector, Gateway, task, browser, shell, or child-process path.
- A name-only MCP inventory is insufficient. Missing or drifted raw MCP server,
  exact tool ID, raw tool name, raw schema, or adapter evidence blocks the
  provider proof with zero connector attempts.
