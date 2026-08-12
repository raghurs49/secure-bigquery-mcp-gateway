import re


class QueryPolicyError(ValueError):
    """Raised when SQL breaks the gateway's read-only policy."""


_FORBIDDEN_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|MERGE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|CALL|EXPORT|LOAD)\b",
    re.IGNORECASE,
)
_DATASET_REFERENCE = re.compile(r"`(?:[\w-]+\.)?([\w-]+)\.[\w-]+`", re.IGNORECASE)


def validate_readonly_sql(sql: str, allowed_datasets: set[str]) -> str:
    """Apply a deliberately small, auditable policy before BigQuery executes SQL.

    IAM remains the final control: the attached Cloud Run identity has no write role.
    This guard provides fast feedback and prevents accidental expensive or unsafe tool calls.
    """

    normalized = sql.strip()
    if not normalized:
        raise QueryPolicyError("SQL must not be empty.")
    if ";" in normalized.rstrip(";"):
        raise QueryPolicyError("Only one SQL statement is allowed.")
    if not re.match(r"^(SELECT|WITH)\b", normalized, re.IGNORECASE):
        raise QueryPolicyError("Only SELECT queries and WITH ... SELECT queries are allowed.")
    if _FORBIDDEN_KEYWORDS.search(normalized):
        raise QueryPolicyError("The query contains a prohibited keyword.")

    referenced_datasets = {match.group(1).lower() for match in _DATASET_REFERENCE.finditer(normalized)}
    if not referenced_datasets:
        raise QueryPolicyError(
            "Use fully-qualified BigQuery table or view references enclosed in backticks."
        )
    unapproved = referenced_datasets - allowed_datasets
    if unapproved:
        raise QueryPolicyError(
            f"Query references dataset(s) outside the allowlist: {', '.join(sorted(unapproved))}."
        )
    return normalized
