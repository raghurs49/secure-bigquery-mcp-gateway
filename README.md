# Secure BigQuery MCP Gateway

A public reference implementation for connecting an AI assistant to BigQuery without giving
the assistant a Google credential. It runs a remote MCP server on Cloud Run and enforces
read-only access, dataset boundaries, result limits, query budget limits, and audit-friendly
BigQuery labels.

> **Portfolio project, not a client system.** It contains no customer data, project IDs,
> service-account keys, or production endpoints.

## The design problem

An AI assistant needs to answer questions from an analytics warehouse while a business owner
is offline. The common mistake is to reuse a person's Google OAuth refresh token for every
part of the connection. This creates a fragile and over-privileged integration.

This project splits the trust boundary:

```text
AI assistant / scheduled workflow
  └── authenticates to the MCP endpoint
          └── Cloud Run MCP gateway
                  └── uses its own restricted service account for BigQuery
```

The caller can request an approved tool. It never receives direct Google Cloud credentials.
The Cloud Run service identity can query only approved reporting data. It cannot modify the
warehouse.

## What it demonstrates

- Remote MCP over **Streamable HTTP**, the recommended transport for deployed MCP servers.
- Python MCP implementation with a Cloud Run-ready container.
- Separate inbound caller authentication and outbound Google service identity.
- Application Default Credentials rather than a service-account JSON key.
- BigQuery dry-run cost checks plus `maximum_bytes_billed` enforcement.
- SQL guardrails: one statement, `SELECT`/`WITH ... SELECT` only, dataset allowlist, row cap,
  timeout, and query labels.
- A production-minded recommendation to grant access to curated reporting views rather than
  raw operational tables.

See [the architecture decision record](docs/architecture.md) for the security rationale.

## Important caveat about inbound authentication

The reference build protects `/mcp` with a bearer token injected from Secret Manager. This is
appropriate for a controlled machine-to-machine scheduler and makes the identity separation
visible in a small project.

For a Claude product that supports MCP OAuth/OIDC discovery, replace the middleware with a
standards-compliant OAuth/OIDC token verifier. The correct choice depends on the Claude client
and scheduling system; BigQuery access remains unchanged because it always comes from the
Cloud Run service account.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# Update .env with a non-production project, allowed reporting dataset, and random token.
python -m secure_bigquery_mcp_gateway.app
```

The MCP endpoint is available at `http://localhost:8080/mcp`. Supply:

```text
Authorization: Bearer <MCP_BEARER_TOKEN>
```

Run the policy tests without any external test runner:

```bash
python -m unittest discover -s tests
```

## Deploy to Cloud Run

Before deploying, create a dedicated service account and grant:

1. `roles/bigquery.jobUser` on the query project.
2. `roles/bigquery.dataViewer` on only the approved dataset or, preferably, curated views.

Build and deploy from the client-owned Google Cloud project:

```bash
gcloud builds submit --tag europe-west2-docker.pkg.dev/PROJECT_ID/mcp/secure-bigquery-mcp-gateway

gcloud run deploy secure-bigquery-mcp-gateway \
  --image europe-west2-docker.pkg.dev/PROJECT_ID/mcp/secure-bigquery-mcp-gateway \
  --region europe-west2 \
  --service-account claude-bq-mcp@PROJECT_ID.iam.gserviceaccount.com \
  --allow-unauthenticated \
  --set-env-vars GOOGLE_CLOUD_PROJECT=PROJECT_ID,ALLOWED_DATASETS=analytics_reporting \
  --set-secrets MCP_BEARER_TOKEN=mcp-bearer-token:latest
```

The application needs no `GOOGLE_APPLICATION_CREDENTIALS` file. Cloud Run supplies short-lived
credentials for its attached service account automatically.

`--allow-unauthenticated` is intentional for this reference build: the remote MCP caller cannot
usually mint a Google Cloud IAM token. The application protects `/mcp` with its own bearer-token
layer, which is separate from the Cloud Run service identity used for BigQuery. For an OAuth/OIDC
capable MCP client, replace this with a standards-compliant verifier and add edge protection.

## Production checklist

- [ ] Use reporting views or an authorised view layer, not raw customer/event tables.
- [ ] Store the bearer token in Secret Manager and rotate it; use OAuth/OIDC when the MCP client supports it.
- [ ] Set a conservative byte cap and alert on BigQuery job labels.
- [ ] Restrict Cloud Run ingress and use a custom domain/WAF when appropriate.
- [ ] Test a cold start, a denied write query, an over-budget query, and the real overnight caller.
- [ ] Keep deployment privileges separate from the running service account.

## Project story for clients

> I designed this gateway to solve the gap between an AI assistant's ability to call tools and
> a production data warehouse's need for least-privilege access. The key decision is separating
> the assistant's authentication to the MCP endpoint from the Cloud Run service account that
> executes constrained, read-only BigQuery queries.

## License

MIT
