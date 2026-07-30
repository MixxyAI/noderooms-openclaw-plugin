# ADR C003: Passport-gated messaging foundation

## Status

Accepted as a contract-only Connector Beta slice for development identity
`1.4.0-alpha.3-dev.1`. Provider login and external OpenClaw runtime validation
are pending.

## Decision

C003 defines one narrow outbound text projection over OpenClaw's built-in
`message` tool with `action=send`. The projection requires an exact channel,
account, target, message payload fingerprint, and idempotency key. It covers
the documented OpenClaw channel IDs `sms`, `whatsapp`, `signal`, `discord`,
and `msteams`.

Every future dispatch must bind one exact NodeRooms Agent, Verified Human
Owner, Agent Passport, OpenClaw runtime, channel, account fingerprint, target
fingerprint, payload fingerprint, and one-action run lease. The Owner approval
is `allow_once`, the attempt ceiling is one, and the receipt is signed. An
unknown provider result is sealed for read-only reconciliation or manual
review; it is never retried automatically or redirected to another channel.

Incoming channel content is untrusted external data. Pairing or an allowlist is
required before it can reach an Agent. It cannot trigger an automatic external
action, Memory ingestion, or Swarm activity.

OpenClaw remains the credential custodian. NodeRooms stores fingerprints and
policy/receipt metadata only, never provider credentials, raw target values,
message bodies, or raw provider results.

## Provider boundary

- SMS uses the official downloadable `@openclaw/sms` channel and requires a
  later Twilio-backed runtime capture.
- WhatsApp uses the official downloadable `@openclaw/whatsapp` channel and
  requires a later QR login and runtime capture.
- Signal uses the official downloadable `@openclaw/signal` channel and
  requires a later `signal-cli`/bot-number runtime capture.
- Discord uses the official downloadable `@openclaw/discord` channel.
- Microsoft Teams uses the bundled or officially downloadable
  `@openclaw/msteams` channel.
- Viber has no verified official OpenClaw adapter in this capture. It remains
  `external_adapter_pending`, unresolved, and non-executable.

Microsoft is not treated as one broad authority. Teams is the C003 messaging
channel. Outlook Mail remains a separate planned C004 read/draft profile, and
Calendar is outside C003.

## Truthful runtime status

The local isolated OpenClaw `2026.7.1-2` profile did not have the five channel
plugins installed. The C003 registry therefore records official package names
from the shipped OpenClaw documentation but marks every runtime plugin version,
effective schema, account, and provider limit as capture-required. The
NodeRooms projection schema is fingerprinted separately and is not represented
as the full dynamic OpenClaw `message` schema.

## Phase boundary

C003 does not:

- wire `passport-messaging-profile` into `src/index.js`;
- add or change a public NodeRooms tool;
- install or log in to a channel;
- start a Gateway or invoke `message`;
- send or receive an SMS, WhatsApp, Signal, Discord, Teams, or Viber message;
- enable Outlook Mail or Calendar;
- choose a recipient, account, channel, or Owner decision automatically;
- retry an uncertain send or claim exactly-once provider effect;
- persist credentials, raw recipients, message bodies, or provider results;
- enable Memory, Swarm, public write, or live trust enforcement;
- modify NodeRooms production, `main`, stable `1.3.0`, its release sources,
  ClawHub, npm, or `latest`.

## Evidence

Run:

```text
node --test tests/passport-messaging-profile.test.mjs
node scripts/passport-messaging-proof.mjs
```

The proof must emit `NR_OC_CONNECTOR_BETA_C003=PASS`.
