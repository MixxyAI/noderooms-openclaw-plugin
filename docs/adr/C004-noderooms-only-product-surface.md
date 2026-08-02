# ADR C004 — NodeRooms-only connector product surface

Status: accepted and enforced in the Alpha6 development line.

## Decision

NodeRooms is the only product, identity, registration, connector, work, and
approval surface presented to a user.

The canonical flow is:

```text
NodeRooms user
→ verified Owner binding
→ active NodeRooms Agent Passport / TrustBridge identity
→ Owner-approved, purpose- and target-bound capability
→ active scoped run lease
→ invisible background runtime
→ exact provider operation
→ public-safe result in NodeRooms
```

The Passport-bound Agent and TrustBridge are one NodeRooms authority identity;
they are not separate user-facing Agents.

## Product boundary

- A user registers only in NodeRooms and works only in NodeRooms.
- Gmail, WhatsApp, Discord, and future connectors are connected from the
  NodeRooms interface.
- Operations, automations, approvals, state, and results are presented in
  NodeRooms.
- OpenClaw is an internal runtime provider only. A NodeRooms user is never
  asked to install it, run its CLI, install a plugin, configure its files, or
  understand its name.
- Developer and infrastructure documentation may identify internal components;
  those names must not leak into the NodeRooms customer journey.

The machine-readable product contract is
`contracts/reference/noderooms-product-surface.v1.json`.

## Mandatory authority

Every claimed connector job carries a strict
`noderooms-connector-job-authority.v1` envelope. Before a provider executable
can start, the background worker validates:

1. every declared user surface is `noderooms`;
2. runtime visibility, CLI, installation, plugin, and branding exposure are
   all disabled;
3. the worker is bound to the exact NodeRooms Agent, verified Owner binding,
   and active Passport;
4. an active capability was explicitly allowed by the verified human Owner,
   was not automated, and matches the exact provider, account, target, scope,
   and purpose;
5. an active run lease matches that capability and the same Agent, Owner,
   Passport, provider, account, target, scope, and purpose, has remaining
   authority, and has not expired;
6. the authority envelope is bound to the exact job id, job type, and payload
   fingerprint.

Missing or invalid Owner binding or Passport is an immediate hard deny. The
same applies to missing, expired, exhausted, automated, or cross-bound
capability and lease records. A hard deny occurs before binary verification or
provider execution.

## Gmail Alpha6 execution surface

The first Gmail worker supports only:

- NodeRooms-initiated OAuth start and completion;
- search;
- sanitized thread read without attachment download;
- creation of one unsent plain-text draft;
- sending the exact previously created draft after a separate, unexpired
  `allow_once` Owner approval and one provider-attempt reservation;
- disconnect.

OAuth is limited to `gmail.readonly` plus `gmail.compose`. The broader
`mail.google.com` and `gmail.modify` scopes are not requested.

Draft creation runs with the provider's no-send guard. Send accepts only a
`draft_id`; recipient, subject, and body cannot be supplied to the send job.
The approval fingerprint binds that draft, job, payload, Agent, Passport,
Owner binding, capability, lease, provider account, target, scope, and purpose.

Delete, Trash, direct send, forward, archive, label, and batch-modify jobs do
not exist. A provider error after a draft or send attempt is sealed as
`unknown`; the provider operation is never retried automatically.

### Owner dashboard workflow

The selected Agent's Owner dashboard contains the only customer-facing Gmail
setup control. The `Connect to Gmail` switch is rendered only inside an active
NodeRooms Owner session. It remains fail-closed until the exact selected Agent
has both an active Passport and its internally provisioned background worker.

1. The Owner enters the Gmail address and turns on `Connect to Gmail`.
2. NodeRooms creates an exact Agent/Passport/account-bound OAuth job and then
   redirects only to a verified `https://accounts.google.com` consent URL.
3. Google returns to the fixed NodeRooms callback. The background worker stores
   the provider token in its Agent-private keyring; WordPress never receives it.
4. After connection, the Owner records an explicit automation purpose and may
   approve search, thread-read, and unsent-draft scopes. Every operation still
   receives its own exact target binding and one-action run lease.
5. Sending is never part of that reusable grant. NodeRooms must show the exact
   existing draft and obtain a new `allow_once` verified-Owner decision before
   reserving a single provider attempt.
6. Turning the switch off immediately clears Agent capabilities in NodeRooms
   and queues provider-keyring cleanup. Delete and Trash remain unavailable.

All status, operation, approval, terminal `unknown`, and result records remain
in NodeRooms. No internal runtime name, command, plugin, install step, or
configuration field is rendered in this dashboard workflow.

## Runtime boundary

The integration is registered only as a long-lived Gateway service during a
full runtime start. It registers no Gmail Agent tool. The model cannot discover
or invoke Gmail directly, and the worker polls only the NodeRooms control plane
for one-use jobs bound to its paired Agent, Owner, and Passport.

The stable `1.3.0` source, release trees, package publication, production
Gateway, and NodeRooms production deployment are outside this ADR and remain
unchanged.
