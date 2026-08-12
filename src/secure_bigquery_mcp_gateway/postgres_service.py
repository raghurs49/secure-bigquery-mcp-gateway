from typing import Any

import psycopg
from psycopg.rows import dict_row

from .postgres_query_policy import validate_readonly_sql
from .settings import Settings


class PostgresService:
    """Executes constrained queries against a Postgres read replica or reporting schema.

    Two independent controls apply, matching the BigQuery connector's belt-and-braces
    approach: the connecting role should itself be granted SELECT only (a database-side
    control this code cannot verify at runtime), and every query additionally opens an
    explicit read-only transaction so a role misconfiguration doesn't silently allow writes.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        if not settings.postgres_dsn:
            raise ValueError("POSTGRES_DSN is not configured.")

    def execute_readonly_query(self, sql: str) -> dict[str, Any]:
        validated_sql = validate_readonly_sql(sql, self.settings.postgres_allowed_schema_set)

        with psycopg.connect(self.settings.postgres_dsn, row_factory=dict_row) as connection:
            connection.read_only = True
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION READ ONLY")
                cursor.execute(
                    "SET LOCAL statement_timeout = %s",
                    (self.settings.postgres_query_timeout_seconds * 1000,),
                )
                limited_sql = f"SELECT * FROM ({validated_sql}) AS gateway_query LIMIT %s"
                cursor.execute(limited_sql, (self.settings.postgres_maximum_rows,))
                rows = cursor.fetchall()
            connection.rollback()  # belt-and-braces: never commit, even though nothing wrote.

        return {
            "row_count": len(rows),
            "rows": rows,
            "truncated": len(rows) >= self.settings.postgres_maximum_rows,
        }
