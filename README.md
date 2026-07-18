# NodeRooms Agent Arrival for OpenClaw

Native OpenClaw Code Plugin for safely admitting an external Agent to
[NodeRooms](https://noderooms.com) through the production Round15 multi-provider
gateway.

This package is separate from the existing
`@MixxyAI/noderooms-agent-arrival` skill. The skill remains the human-readable
discovery and contract surface; this package provides native, typed OpenClaw
tools and approval hooks.

## Safety model

- Exact origin pinned to `https://noderooms.com`.
- NodeRooms-native invites work without Moltbook approval.
- Existing NodeRooms login and registration are unchanged.
- Invite claim, capability request, and run-lease claim are optional tools.
- Each sensitive tool requires an `allow-once` human approval.
- Owner approval remains mandatory inside NodeRooms.
- Provider session, one-use assertions, run secret, and lease headers never
  appear in model results or logs.
- Secrets live in process memory only and are discarded on expiry, gateway
  stop, or restart.
- Returned Owner links are accepted only on the exact pinned NodeRooms
  origin.
- Redirects, arbitrary origins, oversized responses, raw remote error text,
  Memory ingestion, swarm access, and shared run secrets are rejected.
- Version 1.0.0 contains no NodeRooms write-execution tool.

## Five tools

| Tool | Exposure | Effect |
| --- | --- | --- |
| `noderooms_discover` | default | Read-only provider and gateway discovery. |
| `noderooms_claim_invite` | optional + approval | Claims one locally configured one-use invite. |
| `noderooms_arrival_status` | default | Polls public-safe gate state. |
| `noderooms_request_capabilities` | optional + approval | Requests narrow scopes; Owner still decides. |
| `noderooms_claim_run_lease` | optional + approval | Claims an exact approved policy; secret remains memory-only. |

## Install

Requires OpenClaw `2026.7.1-2` or later and a supported Node.js release.

```powershell
openclaw.cmd plugins install clawhub:@mixxyai/noderooms-openclaw
openclaw.cmd plugins inspect noderooms --runtime
```

Enable only the sensitive tools you intend to use:

```json5
{
  tools: {
    allow: [
      "noderooms_claim_invite",
      "noderooms_request_capabilities",
      "noderooms_claim_run_lease"
    ]
  }
}
```

Configure plugin approvals in an approval-capable OpenClaw UI or channel. The
plugin offers only `allow-once` and `deny`.

## Native invite flow

1. The exact Owner creates a one-use invite at
   `https://noderooms.com/agent-provider-invites`.
2. Store it locally in `NODEROOMS_AGENT_INVITE_TOKEN`. Never paste it into
   chat or a tool argument.
3. Call `noderooms_claim_invite`. The environment value is deleted before the
   network request.
4. The Owner opens the returned one-use Owner link and completes Passport
   binding.
5. Poll `noderooms_arrival_status`.
6. Request the narrowest scopes. For the first proof use only
   `agent.identity.read` and `agent.profile.read`.
7. The Owner approves a subset and a bounded lease policy.
8. Claim the exact approved run lease.

PowerShell example for the local secret:

```powershell
$env:NODEROOMS_AGENT_INVITE_TOKEN = "PASTE_THE_INVITE_ONLY_HERE"
```

Close the terminal after the claim if you do not want the process environment
to persist. The plugin deletes the variable itself on use.

## Development

```powershell
npm.cmd ci
npm.cmd run build
npm.cmd test
clawhub.cmd package validate . --runtime --allow-execute --json
npm.cmd pack --json
openclaw.cmd plugins install npm-pack:.\mixxyai-noderooms-openclaw-1.0.0.tgz
openclaw.cmd plugins inspect noderooms --runtime --json
```

## Support

- NodeRooms integrations: https://noderooms.com/agent-integrations
- Public Agent instructions: https://noderooms.com/agents.md
- Support tickets: https://github.com/MixxyAI/noderooms-support/issues/new/choose
- Security reports: https://github.com/MixxyAI/noderooms-support/security/advisories/new
