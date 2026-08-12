import unittest
from dataclasses import dataclass

from secure_bigquery_mcp_gateway.rest_connector import RestConnector, RestConnectorError
from secure_bigquery_mcp_gateway.settings import Settings


@dataclass
class _FakeResponse:
    status_code: int
    content: bytes


class _FakeHttpxClient:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response
        self.requested_urls: list[str] = []

    def get(self, url: str) -> _FakeResponse:
        self.requested_urls.append(url)
        return self._response


def _settings(**overrides) -> Settings:
    base = {
        "google_cloud_project": "demo-project",
        "allowed_datasets": "analytics_reporting",
        "mcp_bearer_token": "token",
        "rest_allowed_hosts": "api.example.com",
        "rest_max_response_bytes": 1000,
    }
    base.update(overrides)
    return Settings(**base)


class RestConnectorTests(unittest.TestCase):
    def test_allows_https_call_to_allowlisted_host(self) -> None:
        client = _FakeHttpxClient(_FakeResponse(status_code=200, content=b'{"ok": true}'))
        connector = RestConnector(_settings(), client=client)
        result = connector.get("https://api.example.com/v1/status")
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["host"], "api.example.com")
        self.assertFalse(result["truncated"])

    def test_rejects_host_outside_allowlist(self) -> None:
        client = _FakeHttpxClient(_FakeResponse(status_code=200, content=b"{}"))
        connector = RestConnector(_settings(), client=client)
        with self.assertRaises(RestConnectorError):
            connector.get("https://not-allowed.example.com/v1/status")
        self.assertEqual(client.requested_urls, [])  # never even attempted the call

    def test_rejects_non_https_scheme(self) -> None:
        connector = RestConnector(_settings(), client=_FakeHttpxClient(_FakeResponse(200, b"{}")))
        with self.assertRaises(RestConnectorError):
            connector.get("http://api.example.com/v1/status")

    def test_truncates_oversized_response_body(self) -> None:
        big_body = b"x" * 5000
        client = _FakeHttpxClient(_FakeResponse(status_code=200, content=big_body))
        connector = RestConnector(_settings(rest_max_response_bytes=100), client=client)
        result = connector.get("https://api.example.com/v1/big")
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["body"]), 100)


if __name__ == "__main__":
    unittest.main()
