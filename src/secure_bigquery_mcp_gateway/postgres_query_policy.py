import re


class PostgresQueryPolicyError(ValueError):
    """Raised when SQL breaks the gateway's read-only Postgres policy."""


_FORBIDDEN_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|MERGE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|CALL|COPY|VACUUM|"
    r"REFRESH|LISTEN|NOTIFY|SET|RESET)\b",
    re.IGNORECASE,
)
# schema.table or "schema"."table", matched only right after FROM/JOIN. Postgres has no
# required delimiter around an unquoted identifier (unlike BigQuery's backticks), so a bare
# "schema.table" pattern would also match ordinary alias.column references (e.g. `a.id`) in a
# WHERE/SELECT/ON clause. Anchoring to FROM/JOIN avoids that false match.
_SCHEMA_REFERENCE = re.compile(r'\b(?:FROM|JOIN)\s+"?(\w+)"?\."?\w+"?', re.IGNORECASE)


def validate_readonly_sql(sql: str, allowed_schemas: set[str]) -> str:
    """Apply the same shape of guardrail as query_policy.py, adapted for Postgres.

    The Postgres connector additionally expects the underlying role to be
    granted SELECT only (see postgres_service.py's `SET TRANSACTION READ ONLY`),
    so this is a fast-feedback layer, not the sole enforcement point.
    """

    normalized = sql.strip()
    if not normalized:
        raise PostgresQueryPolicyError("SQL must not be empty.")
    if ";" in normalized.rstrip(";"):
        raise PostgresQueryPolicyError("Only one SQL statement is allowed.")
    if not re.match(r"^(SELECT|WITH)\b", normalized, re.IGNORECASE):
        raise PostgresQueryPolicyError("Only SELECT queries and WITH ... SELECT queries are allowed.")
    if _FORBIDDEN_KEYWORDS.search(normalized):
        raise PostgresQueryPolicyError("The query contains a prohibited keyword.")

    referenced_schemas = {match.group(1).lower() for match in _SCHEMA_REFERENCE.finditer(normalized) if match.group(1)}
    if not referenced_schemas:
        raise PostgresQueryPolicyError(
            "Use schema-qualified table references, e.g. reporting.daily_revenue."
        )
    unapproved = referenced_schemas - allowed_schemas
    if unapproved:
        raise PostgresQueryPolicyError(
            f"Query references schema(s) outside the allowlist: {', '.join(sorted(unapproved))}."
        )
    return normalized


def extract_schemas(sql: str) -> set[str]:
    """Schemas a query references, for RBAC checks that run after the base
    allowlist check above. Shares the same regex so the two checks never disagree."""

    return {match.group(1).lower() for match in _SCHEMA_REFERENCE.finditer(sql) if match.group(1)}
