# ADR C002A: Gmail TrustBridge Alpha5 pilot

## Status

Accepted for development identity `1.4.0-alpha.5-dev.2`.

The pilot is wired into the OpenClaw plugin but remains disabled by default:

```text
gmailTrustBridge.mode = off
```

It is not a stable release or a production-wide Gmail authorization.

## Exact capability set

Alpha5 governs four exact Gmail tools:

| Tool | Logical action | Agent identity | Approval |
| --- | --- | --- | --- |
| `gmail_search_emails` | search | Passport Agent | none |
| `gmail_read_email_thread` | read | Passport Agent | none |
| `gmail_create_draft` | unsent draft | Passport Agent | none |
| `gmail_send_email` | send or reply | Passport Agent | `allow_once` |

All four tools are bound to the same exact Passport Agent ID. Calls from any
other Agent fail before provider execution. Forward, archive, label, Trash,
delete, and all other unprofiled Gmail tools fail closed.

## Exact provider boundary

Alpha5 dev.2 supplies the four tools through the official `gog` CLI. It does
not expose `exec`, a shell, a generic CLI bridge, arbitrary arguments, batch
mailbox mutation, attachments, HTML bodies, or provider-side retries.

Every call is bound to one configured Gmail account, named OAuth client,
private `gog` home, absolute executable path, and executable SHA-256. The
binary is required to be a regular non-symlink file and its complete SHA-256 is
rechecked before each provider attempt. OAuth client secrets and refresh
tokens remain exclusively in `gog` and the operating-system credential store.

Read invocations add both `--readonly` and `--gmail-no-send`. Every tool adds
one `--enable-commands-exact` policy, `--no-input`, JSON output, and untrusted
content wrapping. Plain-text bodies travel on stdin instead
of process arguments. Provider output and runtime are bounded, no shell is
used, and every result is treated as untrusted external content.

## Recipient and delete boundary

Draft and send/reply accept exactly one bare recipient and no CC or
BCC. The recipient must match one of exactly two configured SHA-256
fingerprints. Raw addresses are never persisted by NodeRooms or copied into a
receipt.

`gmail_delete_emails`, forward, archive, and label tools are hard-denied even
when pilot mode is off. No provider command path exists for Trash or delete.

## One-action reservation

Every governed call creates a one-action reservation. Send and reply additionally:

1. binds the exact run, tool call, Agent, Gmail account fingerprint, target
   fingerprint, and complete payload fingerprint;
2. creates a private reservation before provider execution;
3. request only `allow-once` or deny from the OpenClaw host;
4. consumes the approval before the provider call;
5. permits one provider attempt;
6. blocks exact replay;
7. seals a write error as `unknown` and never advertises it as retry-safe.

The private store uses bounded, atomic, mode-`0600` state and contains no raw
parameters or provider results.

## Signed privacy-safe receipt

After each governed result, Alpha5 creates
`noderooms-gmail-trustbridge-receipt.v1`. The receipt contains:

- logical action, canonical scope, tool, and actor role;
- Agent, account, target, payload, and provider-observation fingerprints;
- approval-consumption and one-attempt facts;
- `committed`, `failed`, or conservative `unknown` outcome;
- explicit no-retry and no-exactly-once claims;
- privacy booleans proving raw values were excluded;
- an Ed25519 signature.

The signer private key stays process-local. Each persisted receipt retains its
own public trust anchor, and the store revalidates both the receipt fingerprint
and Ed25519 signature whenever it is read. `/noderooms gmail status` exposes
only public trust-anchor data and bounded receipt status. The packaged
`noderooms-verify-gmail-receipt` CLI validates a receipt in a separate process
against a separately supplied trust-anchor JSON document.

## Non-claims

Alpha5 does not claim:

- exactly-once provider effect;
- global Gmail authorization;
- automatic Owner decision;
- automatic retry after uncertain writes;
- storage or custody of Gmail OAuth credentials;
- permission to delete or move mail to Trash;
- modification of NodeRooms production or stable `1.3.0`;
- npm or ClawHub publication.

The public NodeRooms tool contract remains 14 tools. Alpha5 dev.2 additionally
registers four optional Gmail provider tools, each visible only to the exact
Passport Agent while pilot mode is active.

## Validation

Run:

```text
node --test tests/gmail-trustbridge-pilot.test.mjs
npm run verify:immutable-releases
npm test
```

The targeted suite must prove Passport-Agent isolation, recipient bounding,
draft-without-send-authority, send/reply `allow_once`, unsupported mutation and delete/Trash hard
denial, replay blocking, unknown-outcome sealing, receipt privacy, Ed25519
tamper detection, independent verification, default-off activation, and the
unchanged 14-tool NodeRooms public contract plus the four Passport-scoped Gmail
provider tools. Provider tests also compare the constructed commands with the
official `gog` v0.34.1 CLI schema/help contract.
