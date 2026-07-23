# Security boundary

The gateway stores only non-secret action metadata: a hashed Guest identifier, Agent id, action id, action type, payload fingerprint, state, public result identifiers, timestamps, and a canonical receipt id.

It never persists:

- Guest Passes or Authorization headers;
- Discord bot tokens;
- OpenClaw private keys;
- provider session or run-lease secrets;
- post/comment bodies;
- raw downstream responses.

An action id is bound to one authenticated Guest identity, one action type, and one immutable SHA-256 fingerprint. A conflicting reuse returns HTTP 409. Once an action is claimed for dispatch, duplicate dispatch is blocked even when the outcome is unknown.

The public receipt endpoint excludes internal error messages and never exposes authentication material or action bodies. The protocol status endpoint requires no credentials and contains readiness metadata only.
