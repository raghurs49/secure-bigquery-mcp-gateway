# Showcase copy

These drafts deliberately describe the public architecture only. Do not mention a prospective
client, their warehouse, datasets, business, or errors that inspired the project.

## LinkedIn post

I built a small reference project for a production GenAI problem that appears simple but has an
important security boundary: letting an AI assistant query BigQuery without handing it broad
Google Cloud credentials.

**Secure BigQuery MCP Gateway** is a Cloud Run-hosted MCP service that separates two identities:

- the AI assistant authenticates to the MCP endpoint;
- the Cloud Run service uses a dedicated, least-privilege service account to execute read-only
  BigQuery queries.

The project adds practical controls: dataset allowlists, `SELECT`-only validation, BigQuery
dry-run cost checks, byte limits, result caps, timeouts, query labels, and a Cloud Run deployment
path using Application Default Credentials rather than downloadable service-account keys.

The key lesson: “read-only” is not the whole security model. A production integration needs
separate caller authentication, runtime identity, data boundaries, and cost guardrails.

Repository: [add GitHub link after publishing]

## Upwork portfolio description

**Secure BigQuery MCP Gateway — Cloud Run, MCP, BigQuery, Python**

Designed and implemented a reference architecture for securely connecting an AI assistant to a
BigQuery analytics warehouse through a remote MCP service.

Highlights:

- Cloud Run-hosted Python MCP server using Streamable HTTP
- Separate inbound MCP authentication and BigQuery runtime service identity
- Least-privilege, read-only BigQuery access through curated datasets/views
- SQL safety checks, dataset allowlists, query byte caps, timeouts, and response limits
- BigQuery dry runs and labelled jobs for cost visibility and auditability
- Containerised deployment with no service-account key stored in code or the image

Technology: Python, MCP, Google Cloud Run, BigQuery, IAM, Secret Manager, Docker, Cloud Build.

## Screenshot checklist before publishing

1. Repository README top section and architecture diagram.
2. Cloud Run service summary with the project ID and URL blurred.
3. A successful test output showing an allowed query and a rejected write query.
4. Never show customer data, service-account emails, API keys, tokens, billing account IDs, or
   unblurred production project IDs.
