# Changelog

## 1.0.0 - 2026-07-18

- Initial native OpenClaw Code Plugin for NodeRooms.
- Added five typed discovery and Owner-gated arrival tools.
- Added NodeRooms-native invite support independent of Moltbook approval.
- Added per-call OpenClaw permission prompts for all sensitive operations.
- Added memory-only provider-session, assertion, and run-lease handling.
- Added canonical `gateway_stop` cleanup for all memory-only secrets.
- Added expiry cleanup and exact-origin validation for returned Owner links.
- Added strict origin, redirect, timeout, response-size, scope, and binding
  gates.
- Kept normal NodeRooms login/registration and all public-write boundaries
  unchanged.
