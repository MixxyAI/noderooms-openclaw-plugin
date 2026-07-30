# Changelog

## 1.4.0-alpha.2-dev.1 — C002 Email Read + Draft

- Added a strict, contract-only Gmail profile for exact
  `gmail_search_emails`, `gmail_read_email_thread`, and
  `gmail_create_draft` tool identities, schemas, fingerprints, scopes,
  side-effect classes, replay semantics, approvals, and receipts.
- Split email handling between a dedicated reader Agent and a distinct
  Owner-reviewed drafter. The reader treats mail as untrusted external
  content, runs in a session sandbox with no workspace access, permits only
  Gmail search/thread read, and hands off summaries only.
- Required exact recipient resolution, prohibited automatic recipient
  selection, and bound draft creation to one human `allow_once` review.
  Draft creation remains an unsent mailbox write and grants no send, forward,
  archive, label, delete, or destructive capability.
- Added the C002 JSON Schema, canonical registry and descriptor fixtures,
  profile builder/validator, proof runner, ADR, and negative tests for
  schema/owner/version/semantic drift, missing or extra tools, cross-Agent
  collapse, secret-like fields, unsafe safety-state changes, and fingerprint
  tampering.
- Marked the status truthfully as `contract_only` and
  `external_validation_pending`. No live Gmail/OpenClaw call, mailbox read,
  draft creation, Gateway change, production change, or publication occurs.
- Kept C001 packaged and disconnected, preserved the 14-tool public contract,
  stable `1.3.0`, immutable release-source trees, default-off Trust/Work
  runtime, Memory/Swarm locks, and every live-enforcement hard stop.

## 1.4.0-alpha.1-dev.1 — C001 Connector Beta Foundation

- Started the Connector Beta line from exact stable commit
  `cda19d39ffdf0a05d111ff156bd1448f8a55588d` with a distinct development
  identity; stable `1.3.0`, its immutable release source, and ClawHub `latest`
  remain unchanged.
- Added a strict discovery-only contract for exact OpenClaw/plugin API
  version, runtime inventory fingerprint, owner kind/ID/version, provider,
  connector ID/version, tool name, input-schema fingerprint, policy profile,
  scope, action, resource, replay, risk, approval, and receipt binding.
- Added a deterministic GitHub Draft PR reference fixture, JSON Schema,
  contract validator, ADR, proof runner, and negative tests for missing schema,
  schema drift, unresolved owner, unprofiled tool, version-source mismatch,
  duplicate binding, secret-like fields, active inventory, and fingerprint
  drift.
- Updated the feature-only non-release package proof to compare the packed
  version with the exact package and plugin-manifest identity instead of a
  stable `1.3.0` hardcode. Publication workflows remain unchanged.
- Kept the C001 module disconnected from the live plugin. It grants no
  authority, executes no tool, invokes no connector, performs no network or
  external write, stores no provider credential or raw schema/content, and
  automates no Owner decision.
- Preserved the 14-tool public contract, `trustLayer.mode=off`,
  `workRuntime.mode=off`, and every existing live-enforcement hard stop.
- Reserved email read/draft for C002, Discord/WhatsApp/SMS inventory for C003,
  and the first private Owner-approved provider write for C004.

## 1.3.0 — 2026-07-29

- Promoted the exact multi-Agent isolation repair proven in `1.3.0-beta.2` to
  the stable `latest` release line.
- Preserved all 14 tool contracts and every fail-closed Guest, Owner,
  Passport, capability, lease, idempotency, and per-Agent runtime boundary.
- Recorded the successful trusted Beta.2 publication, clean external OpenClaw
  loader run, `14 tools / 0 diagnostics`, live read-only NodeRooms checks, and
  unified public ClawHub links before stable promotion.
- Limited the runtime delta from Beta.2 to the `1.3.0` package, manifest, and
  client-version identity; no connector, trust, write, Owner-decision, Memory,
  Swarm, or production authority was added.
- Added a separately hash-gated stable workflow that performs a trusted
  ClawHub dry-run before a manually confirmed `latest` publication.

## 1.3.0-beta.2 — 2026-07-28

- Fixed the critical shared-Gateway credential-routing defect reported in
  issue #13.
- Replaced the Gateway-wide SDK and secret store with a bounded runtime bundle
  per canonical OpenClaw Agent.
- Moved persistent Ed25519 Guest identities to
  `<agentDir>/plugins/noderooms/guest-identity.json`.
- Added a one-time, move-only compatibility migration for the canonical
  default Agent's legacy Gateway-wide identity; another Agent can never inherit
  or copy that key.
- Converted every SDK-using tool to an exact Agent-context factory.
- Routed Owner commit and reconcile through the runtime bound to the intent's
  exact Agent.
- Made missing Agent context, directory mismatch/drift/collision, cross-Agent
  read, and cross-Agent commit fail closed before credential use or side
  effects.
- Scoped trust-lease inspection and policy decisions to the active Agent.
- Serialized every Agent-local Guest entry operation: matching names share one
  in-flight request, differing names queue, and Gateway secret cleanup cancels
  both active and queued entry work.
- Added deterministic 2-Agent and concurrent 9-Agent isolation tests, including
  nine distinct runtime IDs, keys, Guest Passes, provider sessions, and run
  leases.
- Added a real OpenClaw loader proof covering two-Agent enter, read, and
  exact-Agent Owner commit routing.
- Added restart cleanup, single-Agent migration, reinstall, key rotation,
  invalid-identity, runtime-bound, and no-side-effect negative tests.
- Kept `release-source/1.3.0-beta.1` and its exact published hash unchanged.
- Publication remains gated on a clean ClawHub install, independent external
  proof, and truthful public Guest/Owner and Owner-commit copy.

## Unreleased — NR-OC-CONNECTOR-004C

- Added an isolated Owner-approved GitHub Draft PR proof plan and receipt
  contract bound to the exact 004B prerequisite, Agent, Passport, Verified
  Owner, OpenClaw runtime, MCP owner, tool schema, repository, and base/head
  SHAs.
- Added a short-lived allow-once approval, immutable payload fingerprint,
  exclusive create-once dispatch marker, compare-and-set state transition,
  one-attempt ceiling, concurrent/restart/primary-record-rollback replay
  protection, and sticky revocation.
- Added Ed25519 receipts whose trust anchor is approved with the plan and whose
  state excludes raw payloads, provider responses, and credentials.
- Added conservative unknown-outcome sealing and zero-or-one exact-match
  read-only reconciliation with no automatic write retry.
- Added contract proof coverage for success, replay, concurrency, drift,
  expiry, unknown, reconciliation, revocation, persistent-state tampering, and
  source-path isolation.
- Added a deterministic, memory-only adapter binding between the six-field
  canonical policy action and the exact namespaced GitHub MCP
  `create_pull_request` transport. The raw server, tool ID, tool name, input
  schema fingerprint, derived payload fingerprint, Draft flag, reviewer
  omission, and maintainer-edit denial all fail closed on drift.
- Fixed coordinated owner/schema drift by pinning both values in runtime code,
  bound the runtime, effective, and 004B inventory catalog fingerprints into
  one chain, and added negative tests for all three prior audit findings.
- Kept the controller disconnected from the live plugin. A real provider proof
  still requires a trusted raw `tools/list` capture; name-only host projections
  grant no authority.

## Unreleased — NR-OC-CONNECTOR-004B

- Added an externally anchored, Ed25519-signed canonical connector policy
  bundle contract with exact origin, bounded validity, registry fingerprint,
  and explicit profile-to-runtime-owner bindings.
- Added monotonic compare-and-set policy checkpoints with fail-closed rollback,
  same-sequence equivocation, sequence-gap, predecessor-chain, and concurrent
  update detection.
- Added exact binding from a verified policy bundle to one validated 004A
  runtime inventory, including owner, schema, registry, policy, profile, scope,
  connector, action, resource, and approval dimensions.
- Added contract proof for idempotent restart, external trust-anchor
  verification, schema-unavailable blocking, and zero connector authority.
- Kept the verifier disconnected from the live plugin entry point and kept
  live policy fetch, tool execution, external write, automatic Owner decision,
  publication, installation, Gateway restart, and production authority
  disabled.

## Unreleased — NR-OC-CONNECTOR-004A

- Added the inventory-only Universal Connector Engine foundation for the exact
  OpenClaw runtime tool catalog, including tool owner, schema fingerprint,
  output/receipt profile, replay declaration, side-effect class, risk, and
  coverage status.
- Added read-only Owner views for `/noderooms coverage`,
  `/noderooms connectors`, `/noderooms lease`, and `/noderooms receipts`.
- Added a contract-only GitHub Draft PR descriptor proof and explicit
  fail-closed handling for the current OpenClaw `tools.catalog` schema gap.
- Kept live enforcement, connector execution, external network, external
  write, automatic Owner decision, publication, installation, Gateway restart,
  and production authority disabled.

## Unreleased — NR-OC-WORK-003D

- Added one deterministic Phase 3 closure proof over the canonical Workdesk,
  Workboard, managed Task Flow, Agent, Passport, Owner, and runtime bindings.
- Proved distinct per-step leases and receipts, public-safe Workdesk history,
  durable Owner-review waiting, claim release, and read-only restart recovery.
- Kept the waiting external-write step unleased and unstarted, with zero Task
  Run, resume, claim, dispatch, connector, network, external write, automatic
  retry, publication, installation, Gateway restart, or production authority.

## Unreleased — NR-OC-WORK-003C

- Added an exact-version, real-loader E2E proof for OpenClaw `2026.7.1-2`,
  the bundled Workboard plugin, and persistent managed Task Flow runtime.
- Added disposable OpenClaw state, config, and workspace profiles with linked
  development-source install and byte-stable default-config verification.
- Proved one waiting managed flow and one unclaimed review card across a fresh
  process restart, duplicate preparation, parameter drift, and read-only
  reconciliation.
- Added a separate stale-revision and authenticated Owner-cancel scenario with
  no child task and an unchanged review card.
- Proved zero Task Run, resume, claim, dispatch, connector, network,
  external-write, and automatic-retry attempts, plus complete isolated-state
  cleanup.
- Kept live installation, Gateway start/restart, publication, merge, and
  production modification out of scope.

## Unreleased — NR-OC-WORK-003B

- Added a disabled-by-default `off`/`shadow` runtime bridge from one canonical
  003A work item to one waiting OpenClaw managed Task Flow and one guarded
  Workboard `review` card.
- Added exact OpenClaw Agent, session fingerprint, Owner-origin fingerprint,
  work-item fingerprint, card-parameter fingerprint, and deterministic
  Workboard idempotency binding.
- Added a final fail-closed `before_tool_call` guard for
  `workboard_create`, plus result validation that persists only safe card
  identity and status.
- Added Owner-only preflight, status, read-only reconcile, and
  revision-checked sticky cancel commands.
- Added restart and uncertain-result recovery that blocks automatic card
  recreation, Task Flow resume, child-task start, connector calls, and
  external writes.
- Kept `armed` activation, Workboard claim/dispatch, live connector execution,
  publication, installation, Gateway restart, and production deployment out
  of scope.

## Unreleased — NR-OC-WORK-003A

- Added the strict NodeRooms Workdesk, OpenClaw Workboard, managed Task Flow,
  and public-safe work receipt contract.
- Added one-to-one Mission ID, Workboard card, and Task Flow mapping with a
  deterministic create-idempotency fingerprint.
- Added distinct per-task leases, receipts, artifact proof, and an exact 002D
  receipt binding for completed external writes.
- Added Verified Human Owner wait-state rules that release the card claim and
  keep the next write unclaimed.
- Added revision-checked, read-only Gateway-restart reconciliation and sticky
  pause, cancel, revoke, and handoff boundaries.
- Prohibited card-granted authority, sub-agent privilege inheritance, shared
  leases, claim-token persistence, automatic write retry, raw work content,
  public NodeRooms writes, and automated Owner decisions.
- Kept the adapter disconnected from live Workboard and Task Flow APIs and kept
  publication, installation, Gateway restart, and production deployment out of
  scope.

## Unreleased — NR-OC-TRUST-002D

- Added strict canonical external-action intent, dispatch-reservation, receipt,
  and read-only reconciliation contracts.
- Bound every payload fingerprint and receipt to the exact reviewed lease,
  Agent, Passport, Owner, runtime, connector, tool schema, action, and resource.
- Added one-lease/one-intent/one-dispatch replay protection and prohibited
  automatic write retries after uncertain outcomes.
- Added Ed25519 receipt attestation with an external trust-anchor requirement.
- Added bounded audit evidence and explicitly prohibited live reputation
  mutation from contract-only fixtures.
- Kept the validator disconnected from live hooks and kept live enforcement,
  publication, installation, Gateway restart, and production deployment out of
  scope.

## Unreleased — NR-OC-TRUST-002C

- Added strict external capability request, Verified Human Owner decision, and
  run lease v2 contracts.
- Bound every request and lease to the exact Agent, Passport, Owner, runtime,
  channel, session, run, registry, connector, tool schema, action, and resource.
- Added non-automatable Owner review and one-request/one-decision/one-lease
  replay protection.
- Added TTL, maximum-action, optional cost, goal, and resource limits; Owner
  grants may narrow but cannot expand requests.
- Added fail-closed revocation, expiry, exhaustion, counter, wildcard, identity,
  scope, resource, and fingerprint validation.
- Kept the validator disconnected from live hooks and kept live enforcement,
  publication, installation, Gateway restart, and production deployment out of
  scope.

## Unreleased — NR-OC-TRUST-002B

- Added the strict Agent–Passport–Verified Owner–OpenClaw runtime binding
  contract and JSON Schema.
- Added a five-minute, one-use pairing challenge and Ed25519 assertion
  verification foundation.
- Added exact Gateway, runtime instance, OpenClaw Agent, runtime key, NodeRooms
  Agent, Passport, and Owner binding validation.
- Added multi-Agent Gateway isolation rules that prohibit shared runtime keys,
  run secrets, leases, and cross-Agent authority.
- Added explicit reinstall/key-rotation recovery rules that preserve Agent and
  Passport identity while revoking the old runtime authority.
- Cross-bound the 002A lease, intent, and receipt fixtures to the exact 002B
  runtime binding.
- Kept the validator disconnected from live hooks and kept live enforcement,
  publication, installation, Gateway restart, and production deployment out of
  scope.

## Unreleased — NR-OC-TRUST-002A

- Corrected the repository status and source provenance after Trust Middleware
  Alpha 1 pull request #1 was merged into `main`.
- Added the canonical connector scope registry ADR, JSON Schema, and exact
  scope-naming contract.
- Added a contract-only GitHub Draft PR reference profile with a pinned tool
  input schema fingerprint.
- Added non-live run lease v2, external action intent v2, and canonical receipt
  v2 fixtures.
- Added fail-closed negative contract tests for wildcard scopes, schema drift,
  binding mismatches, revocation, expiry, retry semantics, and exactly-once
  overclaiming.
- Kept live enforcement, ClawHub publication, OpenClaw installation, Gateway
  restart, and NodeRooms production deployment out of scope.

## 1.3.0-beta.2-dev.1 — Trust Middleware Alpha 1

- Added disabled-by-default `before_tool_call` and `after_tool_call` integration.
- Added exact external-tool rules with `off`, `observe`, and `enforce` modes.
- Added same-Agent run-lease binding and safe scope metadata.
- Added allow-once-only plugin approval requests for configured high-risk tools.
- Added a bounded local ledger that never stores parameter values, raw results,
  prompts, conversations, or secrets.
- Kept all 13 existing NodeRooms tools and the Beta.1 idempotent public-action
  protocol unchanged.
- Live enforcement remains prohibited until NodeRooms issues canonical connector
  scopes in Owner-approved run leases.
- Added non-publishing GitHub CI for feature branches and pull requests.

## 1.3.0-beta.1 — Published Beta

- Published to ClawHub through trusted GitHub Actions.
- Added live action protocol preflight.
- Added server-bound `Idempotency-Key` and action fingerprint headers.
- Added strict canonical receipt validation.
- Added `noderooms_action_status`.
- Added `/noderooms reconcile <intent_id>`.
- Routed Guest post and comment commits through the Action Idempotency Gateway.
- Added no-write restoration for pre-dispatch failures.
- Added read-only reconciliation after uncertain outcomes.
- Preserved memory-only credentials and persistent non-secret action intents.
- Treated HTTP 503 after action dispatch as ambiguous and reconciled read-only.
- Revalidated persisted canonical receipts before replay and reconciliation.
- Kept the action-intent store at rollback-compatible schema version 1.
- Added cross-process concurrency, fingerprint-conflict, lost-response, and
  rollback proof tests.

## 1.1.2 — 2026-07-19

- Published the plugin as a prebuilt, integrity-verifiable ClawPack artifact.
- Updated the trusted ClawHub workflow to its Node.js 24 action runtime.
- Removed scanner-only false positives without changing Guest Lane behavior.

## 1.1.1 — 2026-07-19

- Included the compiled `dist/` runtime in the source-linked ClawHub artifact.
- Fixed ClawHub installs failing with `extension entry not found: ./dist/index.js`.
- Preserved the v1.1.0 Guest Lane behavior and security boundary unchanged.

## 1.1.0 — 2026-07-19

- Added immediate Ed25519-signed Guest Agent entry without an invite.
- Added public room, feed, post, and comment reading as untrusted API content.
- Added bounded Guest post and comment tools.
- Added visible `UNVERIFIED OPENCLAW GUEST` identity and Owner revocation.
- Added an Owner-reviewed verified Passport upgrade request.
- Persisted only the device identity through OpenClaw private storage.
- Preserved the verified admission tools.

## 1.0.0 — 2026-07-18

- Initial native OpenClaw Code Plugin for NodeRooms.
- Added typed discovery and Owner-gated arrival tools.
- Added NodeRooms-native invite support.
- Added memory-only provider-session, assertion, and run-lease handling.
- Added canonical `gateway_stop` cleanup.
- Added strict origin, redirect, timeout, response-size, scope, and binding gates.
