import time
import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from secure_bigquery_mcp_gateway.identity import Identity, IdentityError, IdentityVerifier
from secure_bigquery_mcp_gateway.settings import Settings


def _settings(**overrides) -> Settings:
    base = {
        "google_cloud_project": "demo-project",
        "allowed_datasets": "analytics_reporting,other_dataset",
        "mcp_bearer_token": "static-test-token",
        "role_dataset_map": "service:*;analyst:analytics_reporting",
    }
    base.update(overrides)
    return Settings(**base)


class _StaticSigningKey:
    def __init__(self, key) -> None:
        self.key = key


class _StubJwksClient:
    def __init__(self, public_key) -> None:
        self._public_key = public_key

    def get_signing_key_from_jwt(self, _token: str) -> _StaticSigningKey:
        return _StaticSigningKey(self._public_key)


class BearerIdentityTests(unittest.TestCase):
    def test_valid_bearer_token_yields_configured_role(self) -> None:
        verifier = IdentityVerifier(_settings())
        identity = verifier.verify("Bearer static-test-token")
        self.assertEqual(identity.auth_method, "bearer")
        self.assertIn("service", identity.roles)

    def test_wrong_bearer_token_is_rejected(self) -> None:
        verifier = IdentityVerifier(_settings())
        with self.assertRaises(IdentityError):
            verifier.verify("Bearer wrong-token")

    def test_missing_header_is_rejected(self) -> None:
        verifier = IdentityVerifier(_settings())
        with self.assertRaises(IdentityError):
            verifier.verify("")


class OidcIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.settings = _settings(
            oidc_issuer="https://issuer.example.com/",
            oidc_audience="secure-bigquery-mcp-gateway",
            oidc_jwks_url="https://issuer.example.com/.well-known/jwks.json",
        )
        self.verifier = IdentityVerifier(self.settings)
        self.verifier._jwks_client = _StubJwksClient(self.public_key)  # bypass network JWKS fetch

    def _token(self, **claim_overrides) -> str:
        claims = {
            "sub": "analyst-1",
            "iss": "https://issuer.example.com/",
            "aud": "secure-bigquery-mcp-gateway",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "roles": ["analyst"],
        }
        claims.update(claim_overrides)
        return jwt.encode(claims, self.private_key, algorithm="RS256")

    def test_valid_token_yields_roles_from_claim(self) -> None:
        identity = self.verifier.verify(f"Bearer {self._token()}")
        self.assertEqual(identity.subject, "analyst-1")
        self.assertEqual(identity.roles, frozenset({"analyst"}))
        self.assertEqual(identity.auth_method, "oidc")

    def test_expired_token_is_rejected(self) -> None:
        token = self._token(iat=int(time.time()) - 1000, exp=int(time.time()) - 500)
        with self.assertRaises(IdentityError):
            self.verifier.verify(f"Bearer {token}")

    def test_wrong_audience_is_rejected(self) -> None:
        token = self._token(aud="someone-else")
        with self.assertRaises(IdentityError):
            self.verifier.verify(f"Bearer {token}")

    def test_missing_role_claim_is_rejected(self) -> None:
        token = self._token(roles=[])
        with self.assertRaises(IdentityError):
            self.verifier.verify(f"Bearer {token}")

    def test_space_delimited_scope_string_is_parsed(self) -> None:
        token = self._token(roles="analyst service")
        identity = self.verifier.verify(f"Bearer {token}")
        self.assertEqual(identity.roles, frozenset({"analyst", "service"}))


class IdentityDatasetResolutionTests(unittest.TestCase):
    def test_wildcard_role_reaches_every_allowed_dataset(self) -> None:
        settings = _settings()
        identity = Identity(subject="svc", roles=frozenset({"service"}), auth_method="bearer")
        self.assertEqual(identity.datasets(settings), {"analytics_reporting", "other_dataset"})

    def test_scoped_role_reaches_only_its_mapped_dataset(self) -> None:
        settings = _settings()
        identity = Identity(subject="analyst-1", roles=frozenset({"analyst"}), auth_method="oidc")
        self.assertEqual(identity.datasets(settings), {"analytics_reporting"})

    def test_unknown_role_reaches_nothing(self) -> None:
        settings = _settings()
        identity = Identity(subject="ghost", roles=frozenset({"unmapped"}), auth_method="oidc")
        self.assertEqual(identity.datasets(settings), set())


if __name__ == "__main__":
    unittest.main()
