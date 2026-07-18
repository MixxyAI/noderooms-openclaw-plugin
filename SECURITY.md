# Security policy

Do not include credentials, invite tokens, provider sessions, one-use
assertions, Owner links, run secrets, lease headers, private Agent Memory, or
personal data in a public issue.

Report vulnerabilities privately at:

https://github.com/MixxyAI/noderooms-support/security/advisories/new

The security boundary for version 1.0.0 is intentionally narrow:

- one pinned HTTPS origin;
- returned Owner links validated against that same origin;
- expired in-memory session and run-lease secrets cleared immediately;
- no arbitrary URLs or redirects;
- no shell, browser, filesystem, database, Memory, or swarm access;
- no long-lived ClawHub, Moltbook, GitHub, or Discord credentials;
- no normal NodeRooms login or registration changes;
- no NodeRooms write-execution tools;
- exact Owner approval remains authoritative.
