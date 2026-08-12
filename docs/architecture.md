# Architecture decision record

## The identity split

```text
Claude / scheduled workflow
  |  (MCP caller authentication: bearer token for the reference build,
  |   OAuth/OIDC for a compatible production MCP client)
  v
Cloud Run: Secure BigQuery MCP Gateway
  |  (attached user-managed service account; Application Default Credentials)
  v
Approved BigQuery reporting views
```

The MCP caller receives no Google credential. The Cloud Run service identity receives no
authority to modify BigQuery data. These are independent trust boundaries.

## Why views are preferred

Grant the service account access to purpose-built reporting views rather than raw Shopify,
advertising, or customer tables. Views create a durable contract for allowed columns,
aggregation, and row-level controls.

## Cost controls

- `maximum_bytes_billed` provides an enforced BigQuery ceiling per query.
- Dry-run estimation rejects queries that would exceed that ceiling before execution.
- The response cap prevents oversized result payloads from being returned to an LLM.
- BigQuery labels make all gateway jobs attributable in billing and audit views.
- A per-identity daily byte budget (`rate_limit.py`) additionally caps cumulative usage across a
  day, independent of any single query's own cap.

## Multiple connectors, one identity model

BigQuery was the first connector; Postgres and an allowlisted REST API followed, reusing the same
shape rather than inventing a second security model per connector:

```text
verified Identity (bearer subject, or OIDC subject + roles)
  |
  +-- RBAC gate: does any of the identity's roles reach the requested dataset/schema?
  |     (role_dataset_map in settings.py; the REST tool uses a simpler per-tool role gate)
  |
  +-- rate limiter: request/minute and daily byte budget, keyed by identity.subject
  |
  +-- connector-specific guardrails (query_policy.py / postgres_query_policy.py / host allowlist)
  |
  +-- PII masking on the result rows (masking.py)
  |
  +-- structured audit log entry (audit.py) — allowed, denied, or error, never raw row contents
```

Each connector still enforces its own guardrails independently (a Postgres RBAC pass does not
imply anything about BigQuery access), and a connector that isn't configured — Postgres without
`POSTGRES_DSN`, REST with an empty `REST_ALLOWED_HOSTS` — simply has nothing to reach, rather than
failing open.

## Why RBAC is a second gate, not the only one

`ALLOWED_DATASETS`/`POSTGRES_ALLOWED_SCHEMAS` remain the deployment-wide ceiling — nothing outside
that set is reachable by any identity, regardless of role. `ROLE_DATASET_MAP` narrows that further
per caller. A misconfigured role mapping can only ever *reduce* what's reachable relative to the
deployment ceiling, not expand past it, because both checks run and both must pass.
