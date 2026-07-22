# Changelog

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
