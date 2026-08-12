from typing import Any
from urllib.parse import urlparse

import httpx

from .settings import Settings


class RestConnectorError(ValueError):
    """Raised when a requested REST call falls outside the connector's policy."""


class RestConnector:
    """Calls a pre-approved external REST API without ever handing the caller,
    or the model, a credential for that API.

    This mirrors the identity split used for BigQuery and Postgres: the MCP
    caller names a host and path, the gateway itself holds (and never returns)
    whatever API key that host needs, attached server-side per allowlist entry.
    """

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self.settings = settings
        self._client = client or httpx.Client(timeout=settings.rest_timeout_seconds)

    def get(self, url: str) -> dict[str, Any]:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise RestConnectorError("Only https:// URLs are allowed.")
        host = (parsed.hostname or "").lower()
        if host not in self.settings.rest_allowed_host_set:
            raise RestConnectorError(f"Host '{host}' is not on the allowlist.")

        response = self._client.get(url)
        content = response.content[: self.settings.rest_max_response_bytes]
        truncated = len(response.content) > self.settings.rest_max_response_bytes
        return {
            "status_code": response.status_code,
            "host": host,
            "truncated": truncated,
            "body": content.decode("utf-8", errors="replace"),
        }
