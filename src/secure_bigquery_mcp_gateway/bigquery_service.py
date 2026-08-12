from typing import Any

from google.cloud import bigquery

from .query_policy import validate_readonly_sql
from .settings import Settings


class BigQueryService:
    """Executes constrained queries with Application Default Credentials.

    On Cloud Run, ADC resolves to the attached user-managed service account.
    No service-account JSON key is read by this application.
    """

    def __init__(self, settings: Settings, client: bigquery.Client | None = None) -> None:
        self.settings = settings
        self.client = client or bigquery.Client(project=settings.google_cloud_project)

    def execute_readonly_query(self, sql: str) -> dict[str, Any]:
        validated_sql = validate_readonly_sql(sql, self.settings.allowed_dataset_set)
        job_config = bigquery.QueryJobConfig(
            dry_run=True,
            use_query_cache=False,
            maximum_bytes_billed=self.settings.maximum_bytes_billed,
            labels={"component": "secure-mcp-gateway", "operation": "readonly-query"},
        )
        dry_run_job = self.client.query(validated_sql, job_config=job_config)
        bytes_estimated = dry_run_job.total_bytes_processed or 0
        if bytes_estimated > self.settings.maximum_bytes_billed:
            raise ValueError(
                f"Query would process {bytes_estimated} bytes, exceeding the configured limit "
                f"of {self.settings.maximum_bytes_billed} bytes."
            )

        execution_config = bigquery.QueryJobConfig(
            use_query_cache=True,
            maximum_bytes_billed=self.settings.maximum_bytes_billed,
            labels={"component": "secure-mcp-gateway", "operation": "readonly-query"},
        )
        job = self.client.query(validated_sql, job_config=execution_config)
        rows = list(
            job.result(timeout=self.settings.query_timeout_seconds, max_results=self.settings.maximum_rows)
        )
        return {
            "job_id": job.job_id,
            "location": job.location,
            "bytes_estimated": bytes_estimated,
            "row_count": len(rows),
            "rows": [dict(row.items()) for row in rows],
        }
