# ADR 005A: Claw runtime evidence contract foundation

## Status

Proposed for Alpha2 review.

Implemented only on the local development branch
`feature/noderooms-trustbridge-alpha2`. It is not merged, published, installed,
or connected to a live Gateway or production service.

## Exact base

005A starts from the exact reviewed repository state:

```text
repository: MixxyAI/noderooms-openclaw-plugin
base branch: main
base commit: cda19d39ffdf0a05d111ff156bd1448f8a55588d
root package version: 1.3.0
public tool count: 14
trustLayer default: off
workRuntime default: off
LIVE_ENFORCE_ALLOWED: false
```

The published `1.3.0` package, all immutable release-source trees, and all
publication workflows remain outside this change.

## Normative strategic supplement

Alpha2 development and communication also follow:

```text
docs/strategy/NODEROOMS_TRUSTBRIDGE_ALPHA2_COMPETITIVE_POSITION_20260730_HU.md
```

The supplement records a strict competitive boundary: Agent Passports,
permission layers, expiring grants, signed receipts, repository evidence, and
Agent communication platforms are not individually unique market claims.
TrustBridge is defensible only if it closes and independently verifies the
integrated chain:

```text
Verified Owner
→ persistent Agent Passport
→ exact artifact/runtime fingerprint
→ Agent/Gateway/runtime binding
→ exact Owner-approved scoped permit
→ canonical intent and dispatch reservation
→ actual provider outcome
→ signed privacy-preserving receipt
→ idempotency and replay protection
→ portable cross-Gateway evidence
```

This is a development priority rule, not a current production claim. Every
later Alpha2 task must state which missing link it closes. A task that closes
none of these links is not an Alpha2 priority by default.

## Context

Trust Middleware Alpha 1, merged by pull request #1, established:

- exact external-tool rules with wildcard rejection;
- public `off` and `observe` modes;
- an activation lock that prevents public `enforce`;
- same-Agent lease and exact-scope checks;
- mandatory `allow-once` routing for high and critical operations;
- fail-closed internal policy and audit behavior;
- a bounded local ledger that stores parameter names but not values and never
  stores raw tool results, prompts, conversations, or secrets.

Alpha 1 intentionally describes its ledger as a local development evidence
stream, not a canonical NodeRooms receipt. Later milestones added the exact
identity, authority, receipt, runtime inventory, signed policy, and isolated
provider-proof layers needed by TrustBridge:

```text
002A exact connector scope registry
002B Agent–Passport–Owner–Gateway–runtime binding
002C human Owner decision + capability + scoped run lease
002D immutable intent + reservation + signed receipt
004A exact runtime tool inventory
004B externally anchored signed policy
004C isolated Owner-approved GitHub Draft PR proof
```

No existing record binds these layers to one generic, exact artifact and exact
runtime evidence envelope that an independent verifier can evaluate without
granting authority.

## Alpha1 → Alpha2 inheritance decision

005A continues from Alpha 1 and its later reviewed layers; it does not replace
or edit them.

| Existing foundation | 005A inheritance |
|---|---|
| Alpha1 exact tool rules | Check IDs and versions are exact; wildcard values are rejected. |
| Alpha1 `off` / `observe` boundary | Evidence is descriptive only. `live_enforce_allowed=false`. |
| Alpha1 local trust ledger | May become a future bounded observation input, but never canonical evidence by itself. |
| Alpha1 public-safe ledger projection | Public evidence stores fingerprints and result codes, never raw values or results. |
| Per-Agent `safeState(agentId)` isolation | Runtime evidence binds a pseudonymous OpenClaw Agent and runtime instance. |
| 002B canonical JSON and SHA-256 helpers | The fixture evidence projection reuses the existing canonical fingerprint primitive. |
| 002B external runtime key thumbprint | Runtime binding records a thumbprint only, never a private key. |
| 002C Owner decision and run lease | Owner, decision, and lease fields are fingerprint references; Owner automation remains false. |
| 002D intent and receipt chain | External-action profiles must bind intent and receipt fingerprints and never claim exactly-once provider effect. |
| 004A runtime inventory | Future checks can bind exact tool owner, schema, and runtime observations. |
| 004B signed policy | Signed evidence requires an external trust anchor; an embedded key is never self-authorizing. |
| 004C isolated provider proof | Future external-action evidence may report at most one provider dispatch attempt and read-only reconciliation. |

The current Alpha1 source files remain unchanged in 005A:

```text
src/trust-policy.js
src/trust-middleware.js
src/trust-ledger.js
src/index.js
openclaw.plugin.json
```

## Decision

005A adds a strict JSON Schema:

```text
contracts/claw-runtime-evidence-v0.1.schema.json
```

The contract binds:

```text
exact schema bytes
→ exact package/archive and/or normalized directory identity
→ exact OpenClaw/plugin/Gateway/runtime/Agent fingerprints
→ optional exact Owner-bound authority-chain fingerprints
→ versioned bounded check results
→ strict aggregate result
→ explicit side-effect counters
→ expiry/revoke/supersede status reference
→ canonical evidence fingerprint
→ optional Ed25519 attestation requiring an external trust anchor
```

Every record states:

```text
authority_status=evidence_only_no_authority
live_enforce_allowed=false
absolute_safety_claimed=false
exactly_once_effect_claimed=false
execution_authority_granted=false
reputation_score_generated=false
owner_decision_automated=false
```

The correct public statement is **evidence available**, never **safe**.

All external statements must carry an exact proof status such as:

```text
implemented and locally tested
contract-level
isolated provider proof
observe-only
external validation pending
cross-Gateway proof pending
production enforcement disabled
```

Claims such as world-first, fully unique, production-safe, exactly-once,
tamper-proof, verified on every Gateway, or ClawHub-certified are prohibited
without separate, current evidence supporting the exact claim.

## Evidence profiles

The schema defines three explicit profiles:

### `artifact_runtime_assessment`

Binds an exact artifact to an exact observed runtime. It does not require an
Owner, capability, decision, lease, intent, or receipt.

### `owner_bound_read_only_observation`

Adds pseudonymous Agent, Passport, Owner, and runtime-binding-record
fingerprints. It performs no live lease request, Owner command, public write,
provider write, artifact install, or artifact block.

### `owner_approved_external_action_outcome`

Reserved for later 005C–005E adapters and proofs. It requires exact
capability-request, human Owner-decision, run-lease, intent, and receipt
fingerprints. It may describe at most one provider write attempt, but it still
grants no authority and makes no exactly-once effect claim.

The profile exists in the schema so later adapters cannot invent incompatible
field names. 005A contains no live external-action fixture or runtime hook.

## Archive bytes and directory trees are different claims

005A deliberately separates:

- `artifact_binding.archive.sha256`: the digest of exact archive bytes;
- `artifact_binding.directory.tree_fingerprint_sha256`: a canonical directory
  inventory produced by a named normalization profile.

One must never be substituted for the other.

The final cross-platform directory normalization profile, including path,
symlink, file-mode, Unicode, line-ending, archive-metadata, and set-like array
rules, is a blocking 005B design decision. The 005A fixture therefore uses the
explicit non-final name:

```text
fixture-directory-profile-v0.1
```

## Schema and semantic validation

JSON Schema 2020-12 freezes structural shape, exact constants, strict object
fields, basic patterns, profile requirements, check outcomes, and lifecycle
conditionals.

Cross-field rules require a separate normative semantic profile:

```text
noderooms-claw-runtime-evidence-semantic-v0.1
```

The 005A contract test proves stable fail-closed error codes for:

- unknown and missing fields;
- wrong version and malformed IDs;
- malformed or uppercase hashes;
- wildcard values;
- invalid timestamps and reversed time windows;
- revoked/active conflicts;
- self-supersede cycles;
- duplicate check ID/version pairs;
- required `not_run` checks aggregated as pass;
- unknown outcomes marked completed;
- aggregate counter drift;
- artifact/runtime package identity drift;
- missing Owner-bound authority references;
- authority or safety-claim expansion;
- non-zero side effects in read-only profiles;
- embedded private keys or public-key trust material;
- nested sensitive fields;
- query-bearing or credential-bearing URLs;
- local source paths;
- exact schema and evidence fingerprint drift;
- oversized documents and excessive nesting.

This test-only semantic harness does not become a live verifier. The independent
verifier implementation belongs to 005D.

## Canonical evidence fingerprint

005A reuses the existing repository canonical JSON and SHA-256 primitive from
002B. The evidence fingerprint covers the whole evidence projection except:

```text
$schema
evidence_fingerprint_sha256
attestation
```

This avoids self-reference and keeps signature material outside the evidence
projection. A later signed attestation binds the exact
`evidence_fingerprint_sha256`.

The raw schema file is independently bound by:

```text
fingerprint_profile=raw-utf8-lf-sha256-v1
```

005B must not silently change either profile. Any incompatible normalization
change requires a new explicit profile or contract version.

## Immutable lifecycle and external status

The evidence envelope is immutable. Revocation or supersession must not rewrite
its signed bytes.

The lifecycle block is a status observation that references a separately
signed external status record by exact:

```text
status record ID
HTTPS URI without query or fragment
status record SHA-256 fingerprint
status checked timestamp
```

005A defines the reference, not the future status-record schema or online
service. The verifier must later combine the immutable envelope, a trusted
status record, current time, expiry, and offline freshness policy.

`unknown_offline` is not active. `revoked`, `superseded`, and `expired` are not
active. Cyclic supersede chains must fail closed.

## Attestation and external trust anchor

Fixture records may use:

```text
attestation_status=not_run
reason_code=contract_fixture
```

A non-fixture record must use Ed25519 and bind the exact evidence fingerprint.
It must reference an external trust anchor by ID, URI, and fingerprint.

The evidence schema never embeds a JWK. An embedded public key cannot establish
trust, and private key material is always forbidden. Key generation, custody,
rotation, revocation, and actual signature verification are out of scope for
005A.

## Public-safe data boundary

Public evidence may contain:

- exact artifact and schema SHA-256 values;
- package and runtime versions;
- policy and config fingerprints;
- pseudonymous Agent, Passport, Owner, Gateway, and runtime fingerprints;
- check ID/version and bounded result codes;
- pass, fail, inconclusive, and not-run outcomes;
- side-effect class and counters;
- timestamps, expiry, revoke, and supersede references;
- signature and external key thumbprint when later signed.

It must never contain:

- API keys, OAuth tokens, credentials, cookies, or authorization headers;
- private JWK `d`, private signing keys, run secrets, or invite tokens;
- raw prompts, conversations, messages, emails, tool arguments, tool results,
  provider responses, or local sessions;
- Owner sender IDs, raw session keys, usernames, home paths, full local source
  paths, IP/MAC addresses, environment values, or Workboard claim tokens;
- query-bearing URLs;
- full private Passport, Owner, or runtime records.

The recursive denylist follows the established 002B/002D pattern: explicit
false safety-policy booleans such as `shared_run_secret_allowed=false` are
permitted, while any actual secret-bearing field is rejected at any depth.

## 005A fixtures

The positive fixture:

```text
claw-runtime-evidence.readonly-pass-v0.1.json
```

uses only fictional `example.invalid` artifact and status references. Its three
required checks pass, all side-effect counters are zero, and its schema and
evidence fingerprints match exact bytes.

Two intentionally invalid fixtures prove:

```text
claw-runtime-evidence.revoked-v0.1.json
  → revoked status cannot remain active

claw-runtime-evidence.unknown-outcome-v0.1.json
  → unknown is not a valid completed check outcome
```

No fixture is a claim about the published NodeRooms `1.3.0` package or any
third-party artifact.

## Package and release boundary

The 005A files live only under:

```text
contracts/
tests/
docs/
```

Those paths are outside the npm package allowlist. 005A does not change:

```text
package.json
package-lock.json
openclaw.plugin.json
README.md
CHANGELOG.md
SECURITY.md
src/
dist/
.github/workflows/
release-source/1.3.0-beta.1/
release-source/1.3.0-beta.2/
release-source/1.3.0/
```

Root `README.md` and `CHANGELOG.md` updates are intentionally deferred because
they are part of the exact published 52-file `1.3.0` package. Updating them
without a new development package identity would change package bytes under an
existing version.

## Zero-side-effect boundary

The 005A proof must report:

```text
NODE_ROOMS_PRODUCTION_NETWORK_CALLS=0
PUBLIC_WRITES=0
PROVIDER_WRITES=0
OWNER_COMMANDS=0
LIVE_LEASE_REQUESTS=0
GATEWAY_STARTS=0
GATEWAY_RESTARTS=0
CLAWHUB_PUBLISH_ATTEMPTS=0
NPM_PUBLISH_ATTEMPTS=0
OPENCLAW_CONFIG_WRITES=0
ARTIFACT_INSTALL_ATTEMPTS=0
ARTIFACT_BLOCK_ATTEMPTS=0
```

No user or default OpenClaw configuration is read for mutation or written.

## Explicitly out of scope

005A does not add:

- a runtime hook, tool, provider, network client, endpoint, or dataset;
- artifact scanning or directory fingerprint generation;
- signature creation or verification;
- a live trust anchor or revoke service;
- OpenClaw `security.installPolicy` integration;
- install allow/block decisions;
- automatic badges or reputation scores;
- ClawHub expected-check mapping;
- a provider write or retry;
- production, Gateway, npm, or ClawHub changes;
- hard host, kernel, hardware, or supply-chain attestation;
- cross-Gateway or cross-Owner trust.

## Next milestone

005B may implement a pure exact artifact/runtime fingerprint engine only after
the development package/version strategy and final normalization profile name
are explicitly decided.

The subsequent sequence is:

```text
005B exact artifact/runtime fingerprint
→ 005C authority/intent/outcome/receipt evidence adapter
→ 005D independent secret-free verifier
→ 005E reproducible GitHub and messaging proofs
→ 005F observe-only install-policy pilot
→ 005G ClawHub expected-checks/external-evidence mapping
→ later cross-Gateway and multi-Owner proof
```

The success metric is evidence-chain closure and external reproducibility, not
feature count. Evidence remains descriptive and never grants execution
authority.

The published `1.3.0` identity and all immutable release sources remain
untouched.
