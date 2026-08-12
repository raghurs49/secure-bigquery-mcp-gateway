from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration. Secrets are injected by Cloud Run, not committed."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    google_cloud_project: str
    allowed_datasets: str
    maximum_bytes_billed: int = 1_073_741_824
    maximum_rows: int = 500
    query_timeout_seconds: int = 30
    mcp_bearer_token: str

    @property
    def allowed_dataset_set(self) -> set[str]:
        return {
            dataset.strip().lower()
            for dataset in self.allowed_datasets.split(",")
            if dataset.strip()
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
