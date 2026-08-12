# Threat model

Scope: the gateway process itself and its three connectors. Out of scope: the security of the
underlying BigQuery/Postgres/REST data sources, the OIDC issuer's own operational security, and
the Cloud Run platform's own isolation guarantees — those are assumed trustworthy inputs.

## Assets

- Row data returned by any connector (may include PII).
- The Cloud Run service account's BigQuery/Postgres access.
- Whatever server-side credential a REST integration needs (never sent to the caller).
- The gateway's own availability and cost (BigQuery billing, REST call volume).

## Actors

- **Legitimate MCP caller** — an AI assistant or scheduler with a valid bearer token or OIDC token.
- **Malicious or compromised caller** — holds a stolen/leaked token, or a legitimate caller whose
  model was prompt-injected into requesting something it shouldn't.
- **Network attacker** — sits between the caller and the gateway, or between the gateway and a
  data source.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Caller with no token reaches a connector | `IdentityMiddleware` rejects any request without a valid bearer token or OIDC token before it reaches a tool | None known, assuming the token itself isn't leaked |
| Valid caller queries a dataset/schema their role shouldn't reach | RBAC check in `app.py` (`_enforce_rbac`) compares the query's referenced dataset(s)/schema(s) against `identity.datasets(settings)` | A role mapped too broadly in `ROLE_DATASET_MAP` grants more than intended — this is a configuration risk, not a code-level bypass |
| Prompt-injected model tries a write, multi-statement, or cross-dataset query | `query_policy.py`/`postgres_query_policy.py` reject on keyword, statement count, and dataset/schema allowlist, before anything executes | A sufficiently obscure SQL construct not covered by the keyword list — IAM/the DB role's own read-only grant is the backstop here, not this regex |
| Query is technically read-only but expensive/abusive | BigQuery dry-run cost check + `maximum_bytes_billed`; Postgres statement timeout + row cap; per-identity rate limiter and daily byte budget | A single instance's in-memory rate limiter resets on restart and doesn't share state across instances — noted in the production checklist |
| Result rows leak PII into the caller/model's context | `masking.py` redacts email/phone/SSN/card-shaped substrings from every connector's rows | Pattern-based masking misses PII that doesn't match a known shape (e.g. free-text notes containing a name) — curated reporting views remain the stronger control |
| REST connector is used to reach an internal/unintended host | Host allowlist checked before any request is made; scheme restricted to `https://` | A host on the allowlist is trusted for any path/query it's given — scope allowlist entries to specific integrations, not broad domains |
| Caller replays or forges a JWT | Signature verified against the issuer's live JWKS (`PyJWKClient`), audience/issuer/expiry all checked, `require: [exp, iat, sub]` | JWKS endpoint compromise or issuer misconfiguration is outside this gateway's control |
| Audit log itself leaks sensitive data | `audit.py` logs shape (row counts, latency, masked-field names) only, never raw SQL parameters or row values | A dataset/schema/host name is itself logged — treat those as non-sensitive by design, not row contents |
| One compromised identity exhausts the daily budget for everyone | Budgets and rate limits are tracked per `identity.subject`, not globally | A caller with multiple identities (multiple tokens) could still multiply their effective budget — bind tokens to a single legitimate service in the issuer's own token policy |

## Explicit non-goals

- This gateway does not attempt to detect or block prompt injection in the *content* the model
  reasons over before calling a tool — it constrains what the tool call itself can do once issued.
- It does not replace database-level least privilege (the connecting role should already be
  read-only) — every guardrail here is defence-in-depth on top of that, not instead of it.
