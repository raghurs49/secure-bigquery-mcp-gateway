import unittest

from secure_bigquery_mcp_gateway.postgres_query_policy import (
    PostgresQueryPolicyError,
    extract_schemas,
    validate_readonly_sql,
)

APPROVED = {"reporting"}


class PostgresQueryPolicyTests(unittest.TestCase):
    def test_allows_single_select_from_approved_schema(self) -> None:
        sql = "SELECT revenue FROM reporting.daily_revenue LIMIT 10"
        self.assertEqual(validate_readonly_sql(sql, APPROVED), sql)

    def test_allows_quoted_schema_reference(self) -> None:
        sql = 'SELECT revenue FROM "reporting"."daily_revenue"'
        self.assertEqual(validate_readonly_sql(sql, APPROVED), sql)

    def test_rejects_unsafe_or_out_of_scope_sql(self) -> None:
        unsafe_sql = [
            "DELETE FROM reporting.daily_revenue WHERE TRUE",
            "SELECT * FROM reporting.daily_revenue; DROP TABLE x",
            "SELECT * FROM raw_events.events",
            "SET statement_timeout = 0; SELECT 1",
        ]
        for sql in unsafe_sql:
            with self.subTest(sql=sql), self.assertRaises(PostgresQueryPolicyError):
                validate_readonly_sql(sql, APPROVED)

    def test_rejects_unqualified_table_reference(self) -> None:
        with self.assertRaises(PostgresQueryPolicyError):
            validate_readonly_sql("SELECT * FROM daily_revenue", APPROVED)

    def test_extract_schemas_matches_validation(self) -> None:
        sql = "SELECT a.x FROM reporting.daily_revenue a JOIN reporting.accounts b ON a.id = b.id"
        self.assertEqual(extract_schemas(sql), {"reporting"})


if __name__ == "__main__":
    unittest.main()
