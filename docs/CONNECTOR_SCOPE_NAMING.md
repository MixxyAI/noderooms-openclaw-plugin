# Canonical connector scope naming

Contract version: `noderooms-connector-scope-naming-v1`

## Grammar

Every connector scope has exactly four dot-separated segments:

```text
connector.<provider>.<resource>.<capability>
```

Each variable segment:

- starts with a lowercase ASCII letter;
- contains only lowercase ASCII letters, digits, and underscores;
- is stable and provider-specific;
- contains no wildcard, placeholder, path, query, version, or resource id.

The complete pattern is:

```regex
^connector\.[a-z][a-z0-9_]{1,31}\.[a-z][a-z0-9_]{1,47}\.[a-z][a-z0-9_]{1,47}$
```

The first reference scope is:

```text
connector.github.pull_request.draft
```

## Meaning

The scope is only a stable identifier. Authorization also requires the exact
registry profile dimensions:

```text
provider + connector_id + connector_version
+ tool_name + tool_schema_fingerprint
+ action + resource_type + resource_selector
+ risk + side_effect_class + replay_semantics
+ approval_policy + receipt_profile
```

A matching scope string without matching dimensions is not authorization.

## Exact-match rules

- Compare the complete scope string.
- Never match by prefix or namespace.
- Never treat a parent segment as granting child capabilities.
- Never use `*`, `**`, glob, regular-expression, or empty segments.
- Never place a concrete repository, account, document, recipient, or device id
  in the scope.
- Bind concrete resources in the capability approval and run lease.
- Bind connector and policy versions outside the scope identifier.

## Separation rules

Read, write, destructive, and administrative actions use separate profiles and
must not share an authorization grant. A new action that broadens side effects
requires a new scope or a new reviewed profile version; it cannot silently
inherit an existing scope.

Examples:

```text
connector.github.repository.read
connector.github.pull_request.draft
connector.github.issue.comment
connector.github.repository.admin
```

These examples do not activate a connector. Only registry profiles with
`status: active`, a deployed registry, and an exact Owner-approved lease may be
considered in a future enforcement path.
