"""Caller identity: OIDC-verified when configured, bearer-token otherwise.

The gateway never receives a Google Cloud credential from the caller (see
docs/architecture.md). This module answers a narrower question: who is
calling the MCP endpoint, and which roles do they hold? RBAC and audit
logging key off the `Identity` this module produces.
"""

from __future__ import annotations

import hmac
import uuid
from dataclasses import dataclass

import jwt
from jwt import PyJWKClient

from .settings import Settings


class IdentityError(Exception):
    """Raised when a caller cannot be authenticated or holds no usable role."""


@dataclass(frozen=True)
class Identity:
    subject: str
    roles: frozenset[str]
    auth_method: str  # "bearer" | "oidc"

    def datasets(self, settings: Settings) -> set[str]:
        """Union of datasets this identity's roles may reach, resolved against
        the configured allowlist. A role mapped to "*" reaches every dataset
        the gateway is allowed to query at all."""

        role_map = settings.role_dataset_map_parsed
        allowed: set[str] = set()
        for role in self.roles:
            granted = role_map.get(role, set())
            if "*" in granted:
                return set(settings.allowed_dataset_set)
            allowed |= granted
        return allowed & settings.allowed_dataset_set


class IdentityVerifier:
    """Verifies the `Authorization` header and returns an `Identity`.

    OIDC is used when `oidc_issuer`/`oidc_audience`/`oidc_jwks_url` are all
    set; the JWKS client caches keys in memory and re-fetches on a signature
    it doesn't recognise (e.g. after issuer key rotation). Otherwise the
    gateway compares against the static bearer token, matching the original
    reference build's machine-to-machine mode.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._jwks_client: PyJWKClient | None = None
        if settings.oidc_issuer and settings.oidc_audience and settings.oidc_jwks_url:
            self._jwks_client = PyJWKClient(settings.oidc_jwks_url, cache_keys=True)

    @property
    def oidc_enabled(self) -> bool:
        return self._jwks_client is not None

    def verify(self, authorization_header: str) -> Identity:
        token = authorization_header.removeprefix("Bearer ").strip()
        if not token:
            raise IdentityError("Missing bearer token.")

        if self.oidc_enabled:
            return self._verify_oidc(token)
        return self._verify_static_bearer(token)

    def _verify_static_bearer(self, token: str) -> Identity:
        if not hmac.compare_digest(token, self.settings.mcp_bearer_token):
            raise IdentityError("Invalid bearer token.")
        return Identity(
            subject="static-bearer-caller",
            roles=frozenset({self.settings.bearer_token_role}),
            auth_method="bearer",
        )

    def _verify_oidc(self, token: str) -> Identity:
        assert self._jwks_client is not None
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=self.settings.oidc_audience,
                issuer=self.settings.oidc_issuer,
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.PyJWTError as error:
            raise IdentityError(f"OIDC verification failed: {error}") from error

        subject = str(claims.get("sub"))
        raw_roles = claims.get(self.settings.oidc_role_claim, [])
        if isinstance(raw_roles, str):
            raw_roles = raw_roles.split()
        roles = frozenset(str(role) for role in raw_roles)
        if not roles:
            raise IdentityError(
                f"Token has no roles in claim '{self.settings.oidc_role_claim}'."
            )
        return Identity(subject=subject, roles=roles, auth_method="oidc")


def request_id_from_headers(headers: dict[str, str]) -> str:
    """Propagates an inbound correlation id, or mints a fresh one. audit.py and
    app.py share this so a caller-supplied trace id survives into the audit log."""

    existing = headers.get("x-request-id")
    return existing if existing else f"req-{uuid.uuid4().hex[:16]}"
