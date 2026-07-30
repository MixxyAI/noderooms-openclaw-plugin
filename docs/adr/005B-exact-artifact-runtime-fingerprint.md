# ADR 005B: Exact artifact and runtime fingerprint engine

## Status

Implemented and locally tested on the repository-only Alpha2 development lane.

External validation is pending. Cross-platform reproducibility is a designed
property of the v1 profile, not yet an independently reproduced claim.
Production enforcement remains disabled.

## Exact predecessor

005B is stacked on the exact 005A draft-PR state:

```text
repository: MixxyAI/noderooms-openclaw-plugin
005A pull request: #17
005A head: 0313084b450cf915f9a2a2f95a08d9f27682c65a
005A base: cda19d39ffdf0a05d111ff156bd1448f8a55588d
005A changed files: 9
005A GitHub CI: success
stable package version: 1.3.0
stable package SHA-256:
3846f8f8a1c5d051064efc629da3e4cf768c0b10f3386436506aa3db8cdc5913
```

The local implementation branch is:

```text
feature/noderooms-trustbridge-alpha2-005b
```

The published `1.3.0` release source and package identity remain immutable.

## Missing evidence-chain link closed

005A froze a portable evidence envelope but intentionally used a non-final
fixture directory profile. 005B closes the next missing link in the strategic
TrustBridge chain:

```text
Verified Owner
→ Agent Passport
→ exact artifact/runtime fingerprint   ← 005B
→ Agent/Gateway/runtime binding
→ exact Owner-approved scoped permit
→ canonical intent and dispatch reservation
→ actual provider outcome
→ signed privacy-preserving receipt
→ replay protection
→ portable cross-Gateway evidence
```

005B does not add a permission layer, execution permit, provider adapter,
receipt signer, verifier trust decision, or runtime enforcement hook.

## Development package/version decision

No Owner-approved TrustBridge npm SemVer identity exists yet. 005B therefore
does not invent one.

The explicit package strategy for this milestone is:

```text
005B is a repository-side, package-excluded proof tool.
root package.json remains 1.3.0.
openclaw.plugin.json remains 1.3.0.
src/ and dist/ remain unchanged.
the npm files allowlist remains unchanged.
no development package is packed, installed, published, or presented as 005B.
```

Any future change that makes this engine part of the runtime package must stop
at a separate Owner decision for a new SemVer identity. A version proposed for
another connector-development lane is not automatically a TrustBridge version
decision.

This resolves the 005A version-strategy gate conservatively: 005B can be tested
without changing bytes under the already published `1.3.0` identity.

## Decision

005B adds a pure read-only engine:

```text
tools/trustbridge/artifact-runtime-fingerprint.mjs
```

It produces a result governed by:

```text
contracts/artifact-runtime-fingerprint-v1.schema.json
```

The three separate fingerprint profiles are:

```text
raw-artifact-bytes-sha256-v1
noderooms-portable-directory-tree-sha256-v1
noderooms-runtime-observation-sha256-v1
```

They are separate claims and cannot be substituted for one another.

## Archive byte fingerprint

The archive fingerprint is:

```text
SHA-256(exact archive bytes)
```

The output binds:

```text
declared archive format
exact byte count
lowercase SHA-256
```

The engine does not extract the archive and does not claim that a separately
supplied directory is the extraction of those archive bytes.

Therefore every result states:

```text
archive_directory_correspondence_proven=false
publisher_control_verified=false
origin_content_verified=false
```

Archive timestamps, tar headers, gzip headers, ZIP ordering, file modes, and
other container metadata affect the raw archive digest because they are part
of the exact archive bytes. They are not copied into the directory claim.

## Final directory normalization profile

The final v1 profile name is:

```text
noderooms-portable-directory-tree-sha256-v1
```

### Root and traversal

- the supplied root must be an existing real directory;
- a symlink supplied as the root is rejected;
- traversal never follows symlinks;
- every resolved directory must remain contained by the canonical root;
- `.` and `..` segments, absolute paths, backslashes, NUL, control characters,
  and path traversal are rejected;
- the local absolute root is never included in the result.

### Portable path rule

v1 deliberately uses a conservative portable ASCII path profile:

- UTF-8 bytes from printable ASCII only;
- `/` is the only separator;
- each segment is non-empty;
- Windows-reserved characters are rejected;
- trailing dot and trailing space are rejected;
- Windows device names such as `CON`, `NUL`, `COM1`, and `LPT1` are rejected;
- ASCII case-fold collisions are rejected;
- a segment is at most 120 bytes;
- the complete normalized relative path is at most 512 bytes.

Non-ASCII paths are not declared unsafe. They are unsupported by this v1
portable profile because Unicode normalization and case-fold behavior would
otherwise vary across filesystems and runtime Unicode tables. A future profile
may add a separately versioned Unicode policy.

### Entry types

v1 supports:

```text
directory
regular file
```

It rejects:

```text
symlink
socket
FIFO
device
other special filesystem object
```

Regular files with identical bytes are represented identically whether the
underlying filesystem stores them as independent files or hardlinks. Hardlink
identity is outside this content-tree claim.

### File bytes and line endings

Each regular-file entry binds:

```text
normalized relative path
exact byte count
SHA-256(exact file bytes)
```

Line endings are not normalized. LF and CRLF content produce different file
and tree fingerprints.

### Metadata

The portable directory profile excludes:

```text
permission and executable bits
uid and gid
owner names
timestamps
inode and device numbers
xattrs and ACLs
local absolute paths
archive-container metadata
directory enumeration order
```

This exclusion is explicit. The directory fingerprint proves the normalized
path/type/content tree, not the omitted metadata.

### Canonical manifest

The engine creates:

```text
{
  normalization_profile,
  root_label,
  file_count,
  directory_count,
  total_file_bytes,
  entries
}
```

Entries are sorted by normalized path UTF-8 byte order. The manifest is
serialized with the existing NodeRooms canonical JSON primitive and then
SHA-256 fingerprinted.

Empty directories are included as directory entries. The root itself is
represented only by the constant:

```text
root_label=package_root
```

No implicit ignore pattern exists. The caller must point the engine at the
exact package root whose complete content tree is being claimed.

## Bounds and race handling

The v1 limits are:

```text
maximum entries: 100000
maximum individual file: 2147483648 bytes
maximum total file bytes: 2147483648 bytes
maximum package.json: 1048576 bytes
```

Files are opened read-only with no-follow behavior where the host exposes it.
The engine compares file identity, size, mtime, and ctime before and after
reading. Directory identity, size metadata, mtime, and ctime are also compared
around traversal.

If a file or directory changes during the scan, the engine fails closed. This
is a local race-resistance measure, not a hardware or kernel attestation.

## Package identity

`package.json` is part of the same directory manifest. The engine reads its
exact bytes separately, validates the package name and version, and requires
the byte digest and size to match the manifest entry.

The output contains:

```text
package_name
package_version
package_json_sha256
directory tree fingerprint
optional independent archive digest
publisher_id metadata
origin_uri metadata
```

Publisher and origin values are caller-supplied metadata. 005B validates their
public-safe shape but does not contact a registry or prove publisher control.

## Runtime observation fingerprint

The runtime profile is:

```text
noderooms-runtime-observation-sha256-v1
```

It binds only explicit, secret-free observations:

```text
OpenClaw version
OpenClaw package.json fingerprint
OpenClaw directory-tree fingerprint
OpenClaw plugin API fingerprint
Node version
Node executable byte fingerprint
plugin package name and version
plugin directory-tree fingerprint
optional plugin archive fingerprint
Gateway fingerprint
OpenClaw Agent fingerprint
runtime key thumbprint
sanitized config fingerprint
platform
architecture
derived environment class
optional exact source commit
```

Raw Gateway IDs, raw Agent IDs, private runtime keys, raw configuration, host
names, environment variables, usernames, and local paths are not accepted in
the runtime manifest.

The environment class must be derived exactly as:

```text
<platform>-<architecture>-node<major>
```

The canonical runtime manifest fingerprint becomes the
`runtime_instance_fingerprint_sha256` used by the 005A-compatible
`runtime_binding`.

005B fingerprints supplied observations. It does not independently prove that
a live Gateway emitted them. External trust anchoring and verification belong
to 005D and later proof milestones.

Every result therefore states:

```text
runtime_observation_source_verified=false
```

## Result fingerprint

The complete 005B result fingerprint covers every root field except:

```text
$schema
result_fingerprint_sha256
```

The canonical JSON and SHA-256 primitive is the same existing repository
primitive used by the 002B and 005A contracts.

## Public-safe and authority boundary

Every result states:

```text
authority_status=evidence_only_no_authority
artifact_safe_claimed=false
execution_authority_granted=false
production_enforcement_enabled=false
owner_decision_automated=false
external_validation_complete=false
publisher_control_verified=false
origin_content_verified=false
runtime_observation_source_verified=false
```

The recursive input and result gate rejects secret-bearing fields. Output
contains normalized relative paths and fingerprints only; it never contains
the scanned absolute root.

The correct status is:

```text
engine: implemented and locally tested
public evidence integration: contract-level
external validation: pending
cross-platform independent reproduction: pending
production enforcement: disabled
```

## CLI boundary

The module exports pure programmatic functions and a local read-only CLI:

```text
node tools/trustbridge/artifact-runtime-fingerprint.mjs build <input.json>
```

The CLI reads one local input file and the explicitly selected artifact paths,
then writes canonical JSON to stdout. It has no output-file option.

The engine imports no HTTP, HTTPS, network, process-execution, worker, or write
filesystem API. It does not read `process.env`.

## Reproducible fixture

The fictional fixture lives under:

```text
contracts/fixtures/artifact-runtime-fingerprint-v1/
```

It contains:

- a four-file fictional package tree;
- a secret-free runtime observation;
- an exact expected result vector.

The fixture is not the published NodeRooms artifact and makes no statement
about a live OpenClaw Gateway.

## Validation contract

The 005B targeted suite proves:

- exact frozen profile names;
- schema-valid expected result;
- exact file, tree, runtime, and result fingerprints;
- UTF-8 byte ordering independent of creation order;
- raw LF/CRLF distinction;
- explicit permission-bit exclusion;
- symlink and symlink-root rejection;
- path traversal, non-portable name, and case-collision rejection;
- exact archive-byte hashing;
- runtime-observation drift sensitivity;
- unknown, sensitive, and inconsistent input rejection;
- package identity and tree drift after byte changes;
- compatibility with the 005A evidence envelope;
- absence of absolute local roots and secret material;
- absence of network, subprocess, environment, and write APIs;
- exclusion from the stable npm package allowlist.

## Zero-side-effect boundary

005B reports:

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

Temporary directories used by automated tests are isolated test inputs and
are deleted after each test. They are not OpenClaw or NodeRooms configuration.

## Completed local validation

The final candidate was validated with exact Node `24.18.0`:

```text
005B targeted tests: 18 pass / 0 fail
full repository suite: 297 total / 296 pass / 0 fail / 1 PHP skip
isolated OpenClaw loader: pass / 14 tools / 6 hooks
ClawHub 0.23.1: pass / 0 breakage / 0 warning / 0 deprecation / 0 issue
JSON parse: pass
git diff --check: pass
```

The final deterministic vector is:

```text
directory tree:
sha256:9c45a6821f4b0b47dbf26024baa3cd4d301127c9ede974c668c267323d8fb2a0

runtime instance:
sha256:bd1fee1c2da451cb651875e7e302694257690c7f9e37591b2e6430741644ab15

complete 005B result:
sha256:2c20f0d28accf9bf965fcff38dce7bfb892cbd2277bff188bb0d8f8c13eb5607
```

The post-change npm pack proof remains byte-exact stable:

```text
version: 1.3.0
entry count: 52
SHA-256:
3846f8f8a1c5d051064efc629da3e4cf768c0b10f3386436506aa3db8cdc5913
```

## Explicitly out of scope

005B does not:

- choose or publish a new npm package version;
- edit `src/`, `dist/`, manifest, root package docs, or a release source;
- install, unpack, execute, approve, or block an artifact;
- claim correspondence between independent archive and directory inputs;
- follow or preserve symlink semantics;
- claim permission, owner, timestamp, xattr, ACL, or archive metadata in the
  portable directory fingerprint;
- read a live Gateway, user config, environment, credential store, or secret;
- create an Owner decision, capability, lease, intent, dispatch, or receipt;
- sign evidence or establish an external trust anchor;
- act as the independent 005D verifier;
- call production, a provider, npm, ClawHub, or a registry;
- claim production safety, exactly-once behavior, tamper-proof operation,
  independent cross-platform proof, or cross-Gateway proof.

## Next milestone

005C may consume the exact 005B artifact and runtime bindings and connect them
to the already existing:

```text
Owner decision
→ scoped run lease
→ canonical intent
→ dispatch reservation
→ provider outcome
→ signed receipt
```

005C must remain evidence-only and must not create authority. The independent
secret-free verifier remains 005D.
