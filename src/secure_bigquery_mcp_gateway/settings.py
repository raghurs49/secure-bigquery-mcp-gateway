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

    # OAuth/OIDC verification. Unset by default: the gateway falls back to the
    # bearer token above for simple machine-to-machine callers. Set all three
    # to switch a deployment to standards-compliant OIDC identity tokens.
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_role_claim: str = "roles"

    # RBAC. Each role maps to the datasets/tools it may reach. The bearer
    # token path (no OIDC) is assigned this single role.
    bearer_token_role: str = "service"
    role_dataset_map: str = "service:*"
    """Semicolon-separated `role:dataset,dataset` pairs. `*` means every allowed dataset."""

    # Postgres connector.
    postgres_dsn: str | None = None
    postgres_allowed_schemas: str = ""
    postgres_maximum_rows: int = 500
    postgres_query_timeout_seconds: int = 15

    # REST connector. Gated by role (which host, if any, is a coarser-grained
    # decision than per-dataset RBAC, so it gets its own role list rather than
    # overloading role_dataset_map).
    rest_allowed_hosts: str = ""
    rest_allowed_roles: str = "service"
    rest_timeout_seconds: int = 10
    rest_max_response_bytes: int = 1_000_000

    # PII masking, applied to every connector's result rows before they reach the caller.
    mask_pii: bool = True

    # Per-identity limits, enforced in memory (single-instance reference behaviour;
    # a multi-instance deployment should move this to Cloud Memorystore/Redis).
    rate_limit_per_minute: int = 30
    daily_byte_budget_per_identity: int = 10_737_418_240

    @property
    def allowed_dataset_set(self) -> set[str]:
        return {
            dataset.strip().lower()
            for dataset in self.allowed_datasets.split(",")
            if dataset.strip()
        }

    @property
    def postgres_allowed_schema_set(self) -> set[str]:
        return {
            schema.strip().lower()
            for schema in self.postgres_allowed_schemas.split(",")
            if schema.strip()
        }

    @property
    def rest_allowed_host_set(self) -> set[str]:
        return {host.strip().lower() for host in self.rest_allowed_hosts.split(",") if host.strip()}

    @property
    def rest_allowed_role_set(self) -> set[str]:
        return {role.strip() for role in self.rest_allowed_roles.split(",") if role.strip()}

    @property
    def role_dataset_map_parsed(self) -> dict[str, set[str]]:
        parsed: dict[str, set[str]] = {}
        for pair in self.role_dataset_map.split(";"):
            pair = pair.strip()
            if not pair or ":" not in pair:
                continue
            role, datasets = pair.split(":", 1)
            parsed[role.strip()] = {d.strip().lower() for d in datasets.split(",") if d.strip()}
        return parsed


@lru_cache
def get_settings() -> Settings:
    return Settings()
