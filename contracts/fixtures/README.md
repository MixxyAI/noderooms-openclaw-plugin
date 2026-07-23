# Connector contract fixtures

These files are non-live examples for `NR-OC-TRUST-002A`:

```text
github-draft-pr.run-lease-v2.json
github-draft-pr.external-action-intent-v2.json
github-draft-pr.external-action-receipt-v2.json
```

Every fixture contains `"fixture": true`. A runtime implementation must reject
that marker and must not treat these ids, resources, timestamps, approvals, or
provider references as real.

The fixtures prove cross-layer binding only:

- one Agent, Passport, Owner, runtime, session, run, and channel;
- one registry and policy version;
- one exact connector, tool, input-schema fingerprint, scope, action, and
  resource;
- one human `allow_once` decision;
- one dispatch reservation and at most one provider write attempt;
- no automatic retry after uncertainty;
- read-only reconciliation;
- no exactly-once provider-effect claim;
- no provider credential, run secret, authorization header, raw prompt, raw
  body, or raw provider response.

They do not implement a server endpoint, activate a connector, or enable live
enforcement.
