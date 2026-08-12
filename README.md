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
- **OAuth/OIDC bearer-token verification with JWKS caching**, falling back to a static bearer
  token for simple machine-to-machine callers — see [`identity.py`](src/secure_bigquery_mcp_gateway/identity.py).
- **Role-based access control**: each verified identity's role(s) resolve to a set of reachable
  datasets/schemas via `ROLE_DATASET_MAP`, enforced independently of, and in addition to, the
  gateway-wide allowlist.
- **A second, independent read-only connector for Postgres** (schema allowlist, `SET TRANSACTION
  READ ONLY`, statement timeout, row cap) — see [`postgres_service.py`](src/secure_bigquery_mcp_gateway/postgres_service.py).
  Disabled by default; enabling it is one environment variable.
- **A host-allowlisted REST connector** for calling an approved external API without ever handing
  the caller, or the model, that API's credential.
- **Best-effort PII masking** applied to every connector's result rows before they leave the
  gateway (email/phone/SSN/card-shaped substrings) — a defence-in-depth layer, not a substitute
  for querying pre-masked views.
- **Structured JSON audit logging** of every tool call (subject, role, tool, decision, latency,
  row count, masked-field count) — one Cloud Logging entry per call, no raw query text or row
  contents logged.
- **Per-identity rate limiting and a rolling daily byte budget**, enforced in memory.
- Application Default Credentials rather than a service-account JSON key.
- BigQuery dry-run cost checks plus `maximum_bytes_billed` enforcement.
- SQL guardrails: one statement, `SELECT`/`WITH ... SELECT` only, dataset allowlist, row cap,
  timeout, and query labels.
- A production-minded recommendation to grant access to curated reporting views rather than
  raw operational tables.

See [the architecture decision record](docs/architecture.md) for the security rationale and
[the threat model](docs/threat-model.md) for what each control does and doesn't cover.

## Inbound authentication: bearer token or OIDC

The reference build defaults to a bearer token injected from Secret Manager — appropriate for a
controlled machine-to-machine scheduler, and it makes the identity separation visible in a small
project. Setting `OIDC_ISSUER`, `OIDC_AUDIENCE`, and `OIDC_JWKS_URL` switches the same deployment
to standards-compliant OIDC token verification with no code change: `identity.py` resolves roles
from the configured claim (`OIDC_ROLE_CLAIM`, default `roles`) and RBAC/audit logging use the
verified subject and roles either way. BigQuery access remains unchanged in both modes because it
always comes from the Cloud Run service account, never from the caller's token.

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

or, once `OIDC_ISSUER`/`OIDC_AUDIENCE`/`OIDC_JWKS_URL` are set, a valid OIDC identity token from
that issuer.

Four tools are exposed: `execute_readonly_sql` (BigQuery), `execute_readonly_sql_postgres`
(Postgres, only when `POSTGRES_DSN` is set), `call_allowed_rest_api` (only hosts in
`REST_ALLOWED_HOSTS`), and `gateway_capabilities` (reports the caller's own resolved roles and
reachable datasets — useful for confirming an RBAC change took effect without guessing).

Run the tests:

```bash
pytest -q
# or, without pytest:
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
- [ ] Prefer OIDC over the static bearer token once the MCP client supports it; rotate whichever is active.
- [ ] Set a conservative byte cap and alert on BigQuery job labels.
- [ ] Move `rate_limit.py`'s in-memory state to Memorystore/Redis before running more than one instance.
- [ ] Restrict Cloud Run ingress and use a custom domain/WAF when appropriate.
- [ ] Point `ROLE_DATASET_MAP` at the real roles your OIDC issuer will send, not just the reference `service:*`.
- [ ] If enabling Postgres, confirm the connecting database role is itself granted `SELECT` only — this
      gateway's read-only transaction is a second layer, not a substitute for that grant.
- [ ] Review `REST_ALLOWED_HOSTS` against the actual integrations you intend to expose; an empty
      allowlist (the default) means the REST tool can reach nothing.
- [ ] Confirm `mask_pii` behaves as expected against a sample of real column values before relying on it.
- [ ] Test a cold start, a denied write query, an over-budget query, an RBAC-denied dataset, and the real overnight caller.
- [ ] Keep deployment privileges separate from the running service account.

## Project story for clients

> I designed this gateway to solve the gap between an AI assistant's ability to call tools and
> a production data warehouse's need for least-privilege access. The key decision is separating
> the assistant's authentication to the MCP endpoint from the Cloud Run service account that
> executes constrained, read-only BigQuery queries. I extended it from a single-connector,
> bearer-token-only prototype into a multi-connector gateway (BigQuery, Postgres, and an
> allowlisted REST API) with OIDC support, per-role dataset access, PII-aware result masking,
> structured audit logging, and per-identity rate limits — the shape a client would actually
> need before trusting it with more than one data source or more than one caller.

## Known issue worth knowing about

`mcp>=2.0.0` removed `mcp.server.fastmcp`, which this project's server is built on. `pyproject.toml`
pins `mcp<2.0.0` accordingly — if a dependency bump ever breaks this, that's why.

## License

MIT
