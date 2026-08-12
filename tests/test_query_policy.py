import unittest

from secure_bigquery_mcp_gateway.query_policy import QueryPolicyError, validate_readonly_sql


APPROVED = {"analytics_reporting"}


class QueryPolicyTests(unittest.TestCase):
    def test_allows_single_select_from_approved_dataset(self) -> None:
        sql = "SELECT revenue FROM `demo-project.analytics_reporting.daily_revenue` LIMIT 10"
        self.assertEqual(validate_readonly_sql(sql, APPROVED), sql)

    def test_rejects_unsafe_or_out_of_scope_sql(self) -> None:
        unsafe_sql = [
            "DELETE FROM `demo-project.analytics_reporting.daily_revenue` WHERE TRUE",
            "SELECT * FROM `demo-project.analytics_reporting.daily_revenue`; DROP TABLE x",
            "SELECT * FROM `demo-project.raw_events.events`",
        ]
        for sql in unsafe_sql:
            with self.subTest(sql=sql):
                with self.assertRaises(QueryPolicyError):
                    validate_readonly_sql(sql, APPROVED)
