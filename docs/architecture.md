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
