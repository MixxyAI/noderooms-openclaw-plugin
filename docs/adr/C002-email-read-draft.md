# ADR C002: Email Read + Draft contract

## Status

Accepted as a contract-only Connector Beta slice for development identity
`1.4.0-alpha.2-dev.1`. External OpenClaw runtime validation is pending.

## Decision

C002 defines a bounded Gmail profile with three exact actions:

- `gmail_search_emails` — read-only, replay-safe search;
- `gmail_read_email_thread` — read-only, replay-safe thread read;
- `gmail_create_draft` — one unsent mailbox draft, high risk, at-most-once,
  and `allow_once`.

The reader and drafter are distinct Agent identities. The reader treats every
email as untrusted external content, runs in a session-scoped sandbox with no
workspace access, receives only the two email read tools, and may hand off only
a summary. Filesystem, runtime, web, browser, cron, Gateway, and node tools
remain denied. Memory ingestion and Swarm remain disabled.

The drafter cannot select recipients automatically. One exact recipient set
and draft payload must be resolved before a human Verified Owner reviews one
`allow_once` action. Draft creation does not imply reply sending, forwarding,
label mutation, archiving, deletion, or any other mailbox permission.

OpenClaw remains the Gmail credential and session custodian. NodeRooms stores
only connector identities, schema and account-binding fingerprints, policy
metadata, and proof state. It stores no OAuth token, provider credential,
email body, draft body, recipient address, attachment, or raw connector
result.

## Truthful validation status

The current fixture is derived from the loaded Gmail app tool contracts and
is deliberately marked `contract_only` and
`external_validation_pending`. It is not represented as a live OpenClaw
`tools_effective` capture.

C002 cannot enter a live runtime until a separately captured OpenClaw
inventory proves the exact:

- OpenClaw and plugin API versions;
- Gmail plugin owner and version;
- per-Agent effective tool sets;
- raw input schemas and their SHA-256 fingerprints;
- account-binding fingerprint;
- reader sandbox, workspace, and tool policy;
- absence of send, forward, mutation, and destructive actions.

Any owner, version, schema, tool-set, side-effect, approval, Agent, account, or
policy drift fails closed.

## Phase boundary

C002 does not:

- wire `email-read-draft-profile` into `src/index.js`;
- add or change an OpenClaw public tool;
- inspect a live mailbox or create a live Gmail draft;
- invoke a connector, network, Gateway, or provider;
- send, forward, archive, label, Trash, or delete email;
- choose a recipient or automate a Verified Human Owner decision;
- persist raw email, draft, recipient, attachment, or credential data;
- enable Memory, Swarm, public write, or live trust enforcement;
- modify NodeRooms production, `main`, stable `1.3.0`, its release source,
  ClawHub, npm, or `latest`.

## Evidence

Run:

```text
node --test tests/email-read-draft-profile.test.mjs
node scripts/email-read-draft-proof.mjs
```

The test must emit `NR_OC_CONNECTOR_BETA_C002=PASS`. The proof must show three
schema-verified contract tools, zero unclassified or drifted tools, an
isolated reader, an Owner-reviewed unsent draft boundary, zero send
capability, zero live authority, and external OpenClaw validation pending.
