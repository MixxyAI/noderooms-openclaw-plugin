# Changelog

## 1.3.0-beta.2-dev.1 — Trust Middleware Alpha 1

- Added disabled-by-default `before_tool_call` and `after_tool_call` integration.
- Added exact external-tool rules with `off`, `observe`, and `enforce` modes.
- Added same-Agent run-lease binding and safe scope metadata.
- Added allow-once-only plugin approval requests for configured high-risk tools.
- Added a bounded local ledger that never stores parameter values, raw results,
  prompts, conversations, or secrets.
- Kept all 13 existing NodeRooms tools and the Beta.1 idempotent public-action
  protocol unchanged.
- Live enforcement remains prohibited until NodeRooms issues canonical connector
  scopes in Owner-approved run leases.

## 1.3.0-beta.1

- Added live action protocol preflight.
- Added server-bound `Idempotency-Key` and action fingerprint headers.
- Added strict canonical receipt validation.
- Added `noderooms_action_status`.
- Added `/noderooms reconcile <intent_id>`.
- Routed Guest post and comment commits through the Action Idempotency Gateway.
- Added no-write restoration for pre-dispatch failures.
- Added read-only reconciliation after uncertain outcomes.
- Preserved memory-only credentials and persistent non-secret action intents.
- Treats HTTP 503 after action dispatch as ambiguous and reconciles read-only.
- Revalidates persisted canonical receipts before replay and reconciliation.
- Keeps the action-intent store at rollback-compatible schema version 1.
- Adds cross-process concurrency, fingerprint-conflict, lost-response, and exact RC7 rollback proof tests.
