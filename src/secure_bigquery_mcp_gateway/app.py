import logging
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.types import ASGIApp

from .audit import AuditEvent, Timer
from .bigquery_service import BigQueryService
from .identity import Identity, IdentityError, IdentityVerifier, request_id_from_headers
from .masking import mask_rows
from .postgres_query_policy import PostgresQueryPolicyError, extract_schemas
from .postgres_service import PostgresService
from .query_policy import QueryPolicyError, extract_datasets
from .rate_limit import DailyBudgetExceeded, RateLimiter, RateLimitExceeded
from .rest_connector import RestConnector, RestConnectorError
from .settings import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

settings = get_settings()
bigquery_service = BigQueryService(settings)
postgres_service = PostgresService(settings) if settings.postgres_dsn else None
rest_connector = RestConnector(settings)
identity_verifier = IdentityVerifier(settings)
rate_limiter = RateLimiter(settings.rate_limit_per_minute, settings.daily_byte_budget_per_identity)

mcp = FastMCP(
    "Secure BigQuery Gateway",
    instructions=(
        "Run read-only analytics queries only. Use fully-qualified, backtick-enclosed table or view "
        "references from the approved analytics dataset. Postgres and REST tools are available only "
        "when the deployment configures them."
    ),
    stateless_http=True,
    json_response=True,
)

_identity_var: ContextVar[Identity | None] = ContextVar("identity", default=None)
_request_id_var: ContextVar[str] = ContextVar("request_id", default="req-unset")


class _ToolDenied(Exception):
    """Raised by RBAC/rate-limit checks inside a tool, caught once at the call site."""


def _current_identity() -> Identity:
    identity = _identity_var.get()
    if identity is None:
        raise _ToolDenied("No verified caller identity for this request.")
    return identity


def _enforce_rbac(identity: Identity, requested: set[str], *, kind: str) -> None:
    allowed = identity.datasets(settings)
    if requested and not requested.issubset(allowed):
        denied = sorted(requested - allowed)
        raise _ToolDenied(
            f"Role(s) {sorted(identity.roles)} may not access {kind} {denied}."
        )


def _audit(tool: str, decision: str, timer: Timer, detail: dict | None = None) -> None:
    identity = _identity_var.get()
    AuditEvent(
        request_id=_request_id_var.get(),
        subject=identity.subject if identity else "unknown",
        auth_method=identity.auth_method if identity else "none",
        tool=tool,
        decision=decision,
        latency_ms=timer.elapsed_ms(),
        detail=detail or {},
    ).emit()


@mcp.tool()
def execute_readonly_sql(sql: str) -> dict:
    """Run a single, read-only BigQuery SELECT query against approved datasets.

    The gateway rejects writes, multiple statements, unapproved datasets, over-budget queries,
    results exceeding the configured response cap, and datasets outside the caller's RBAC role.
    """

    timer = Timer()
    try:
        identity = _current_identity()
        rate_limiter.check_request_rate(identity.subject)
        _enforce_rbac(identity, extract_datasets(sql), kind="dataset(s)")

        result = bigquery_service.execute_readonly_query(sql)
        rate_limiter.charge_bytes(identity.subject, result.get("bytes_estimated", 0))
        masked_rows, masking_report = mask_rows(result["rows"], enabled=settings.mask_pii)
        result["rows"] = masked_rows
        result["masking"] = masking_report.as_dict()

        _audit(
            "execute_readonly_sql",
            "allowed",
            timer,
            {
                "row_count": result["row_count"],
                "bytes_estimated": result.get("bytes_estimated"),
                "masked_fields": masking_report.as_dict()["fields_masked"],
            },
        )
        return result
    except (QueryPolicyError, ValueError) as error:
        logger.warning("Rejected MCP query: %s", error)
        _audit("execute_readonly_sql", "error", timer, {"reason": str(error)})
        return {"error": str(error)}
    except (_ToolDenied, RateLimitExceeded, DailyBudgetExceeded) as error:
        _audit("execute_readonly_sql", "denied", timer, {"reason": str(error)})
        return {"error": str(error)}


@mcp.tool()
def execute_readonly_sql_postgres(sql: str) -> dict:
    """Run a single, read-only Postgres SELECT query against approved schemas.

    Returns an error if the deployment has not configured POSTGRES_DSN. Applies the
    same RBAC, rate-limit, and PII-masking layers as the BigQuery tool.
    """

    timer = Timer()
    try:
        if postgres_service is None:
            raise _ToolDenied("The Postgres connector is not configured on this deployment.")

        identity = _current_identity()
        rate_limiter.check_request_rate(identity.subject)
        _enforce_rbac(identity, extract_schemas(sql), kind="schema(s)")

        result = postgres_service.execute_readonly_query(sql)
        masked_rows, masking_report = mask_rows(result["rows"], enabled=settings.mask_pii)
        result["rows"] = masked_rows
        result["masking"] = masking_report.as_dict()

        _audit(
            "execute_readonly_sql_postgres",
            "allowed",
            timer,
            {"row_count": result["row_count"], "masked_fields": masking_report.as_dict()["fields_masked"]},
        )
        return result
    except (PostgresQueryPolicyError, ValueError) as error:
        logger.warning("Rejected MCP Postgres query: %s", error)
        _audit("execute_readonly_sql_postgres", "error", timer, {"reason": str(error)})
        return {"error": str(error)}
    except (_ToolDenied, RateLimitExceeded, DailyBudgetExceeded) as error:
        _audit("execute_readonly_sql_postgres", "denied", timer, {"reason": str(error)})
        return {"error": str(error)}


@mcp.tool()
def call_allowed_rest_api(url: str) -> dict:
    """Call an https:// URL whose host is on the deployment's REST allowlist.

    The gateway never forwards a caller-supplied credential to the target host, and never
    returns one either; add per-host authentication server-side in rest_connector.py if a
    specific integration needs it.
    """

    timer = Timer()
    try:
        identity = _current_identity()
        if not identity.roles & settings.rest_allowed_role_set:
            raise _ToolDenied(f"Role(s) {sorted(identity.roles)} may not use the REST connector.")
        rate_limiter.check_request_rate(identity.subject)

        result = rest_connector.get(url)
        _audit(
            "call_allowed_rest_api",
            "allowed",
            timer,
            {"host": result["host"], "status_code": result["status_code"]},
        )
        return result
    except RestConnectorError as error:
        _audit("call_allowed_rest_api", "error", timer, {"reason": str(error)})
        return {"error": str(error)}
    except (_ToolDenied, RateLimitExceeded, DailyBudgetExceeded) as error:
        _audit("call_allowed_rest_api", "denied", timer, {"reason": str(error)})
        return {"error": str(error)}


@mcp.tool()
def gateway_capabilities() -> dict:
    """Describe the fixed security limits and connectors available on this deployment."""

    identity = _identity_var.get()
    return {
        "mode": "read-only",
        "allowed_datasets": sorted(settings.allowed_dataset_set),
        "maximum_bytes_billed": settings.maximum_bytes_billed,
        "maximum_rows": settings.maximum_rows,
        "query_timeout_seconds": settings.query_timeout_seconds,
        "postgres_configured": postgres_service is not None,
        "rest_hosts_allowed": sorted(settings.rest_allowed_host_set),
        "oidc_enabled": identity_verifier.oidc_enabled,
        "pii_masking_enabled": settings.mask_pii,
        "caller_roles": sorted(identity.roles) if identity else [],
        "caller_datasets": sorted(identity.datasets(settings)) if identity else [],
    }


class IdentityMiddleware:
    """Verifies the caller (OIDC when configured, static bearer token otherwise) and
    publishes the resulting `Identity` to tool calls via a contextvar, since FastMCP
    tool functions don't receive the Starlette request directly.

    Supersedes the original build's `BearerTokenMiddleware`: same public entry points
    (`/healthz` and `/` are exempt), but now backed by `identity.IdentityVerifier` so
    RBAC and audit logging have a real subject and role set to work with.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self,
        scope: dict,
        receive: Callable[[], Awaitable[dict]],
        send: Callable[[dict], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http" or scope.get("path") in {"/healthz", "/"}:
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        headers = {key.decode(): value.decode() for key, value in scope.get("headers", [])}
        request_id_token = _request_id_var.set(request_id_from_headers(headers))
        try:
            identity = identity_verifier.verify(request.headers.get("authorization", ""))
        except IdentityError as error:
            response = JSONResponse({"detail": str(error)}, status_code=401)
            await response(scope, receive, send)
            _request_id_var.reset(request_id_token)
            return

        identity_token = _identity_var.set(identity)
        try:
            await self.app(scope, receive, send)
        finally:
            _identity_var.reset(identity_token)
            _request_id_var.reset(request_id_token)


async def healthz(_: Request) -> Response:
    return JSONResponse({"status": "ok", "service": "secure-bigquery-mcp-gateway"})


@asynccontextmanager
async def lifespan(_: Starlette):
    async with mcp.session_manager.run():
        yield


base_app = Starlette(
    routes=[Route("/healthz", healthz), Mount("/", app=mcp.streamable_http_app())],
    lifespan=lifespan,
)
app = IdentityMiddleware(base_app)


if __name__ == "__main__":
    import os

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
