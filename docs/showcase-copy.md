# Showcase copy

These drafts deliberately describe the public architecture only. Do not mention a prospective
client, their warehouse, datasets, business, or errors that inspired the project.

## LinkedIn post

I extended a reference project for a production GenAI problem that appears simple but has an
important security boundary: letting an AI assistant query enterprise data sources without
handing it broad credentials.

**Secure MCP Gateway** started as a single-connector BigQuery service and is now a multi-connector
gateway — BigQuery, Postgres, and an allowlisted REST API — behind one identity model:

- the AI assistant authenticates to the MCP endpoint, via a static bearer token or standards-
  compliant OIDC (issuer/audience/JWKS-verified, no code change to switch);
- each verified identity's role(s) resolve to the specific datasets/schemas it may reach — RBAC,
  not just "authenticated or not";
- the Cloud Run service uses its own dedicated, least-privilege identity for every connector's
  actual data access, never the caller's;
- every result row passes through PII-aware masking before it leaves the gateway;
- every tool call — allowed, denied, or errored — becomes one structured audit log entry, with
  row counts and latency but never raw query text or row contents;
- per-identity rate limits and a daily byte budget stop one caller from exhausting shared capacity.

The key lesson, extended: “read-only” and “authenticated” are not the whole security model. A
production integration needs per-caller authorization, not just a shared token; masked output, not
just restricted input; and an audit trail that's actually safe to keep.

Repository: [add GitHub link after publishing]

## Upwork portfolio description

**Secure MCP Gateway — BigQuery, Postgres, REST, OIDC/RBAC, Cloud Run, Python**

Designed and implemented a multi-connector reference architecture for securely connecting an AI
assistant to enterprise data sources (a BigQuery warehouse, a Postgres database, and an approved
REST API) through one remote MCP service with a shared identity and authorization model.

Highlights:

- Cloud Run-hosted Python MCP server using Streamable HTTP
- OIDC bearer-token verification (JWKS-cached) with a static-token fallback for simple callers
- Role-based access control: each identity's role resolves to the datasets/schemas it may reach
- Three independent connectors sharing one RBAC/rate-limit/audit/masking pipeline
- Least-privilege, read-only access through curated datasets/views/schemas, never raw credentials
  passed to the caller or the model
- SQL safety checks, dataset/schema allowlists, host allowlists, byte/row/timeout caps
- Best-effort PII masking (email/phone/SSN/card-shaped values) on every connector's results
- Structured JSON audit logging of every tool call — no raw row contents ever logged
- Per-identity rate limiting and a rolling daily byte budget
- A written threat model (docs/threat-model.md) covering each control and its residual risk
- Containerised deployment with no service-account key stored in code or the image

Technology: Python, MCP, OAuth/OIDC, Google Cloud Run, BigQuery, Postgres, REST, IAM, Secret
Manager, Docker, Cloud Build.

## Screenshot checklist before publishing

1. Repository README top section and architecture diagram.
2. Cloud Run service summary with the project ID and URL blurred.
3. A successful test output showing: an allowed query, a rejected write query, and an RBAC-denied
   query for a role that shouldn't reach that dataset.
4. A sample masked result row (synthetic data only) showing PII redaction in action.
5. A sample structured audit log line (synthetic subject/tool/decision).
6. Never show customer data, service-account emails, API keys, tokens, billing account IDs, or
   unblurred production project IDs.
