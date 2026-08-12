import hmac
import logging
from contextlib import asynccontextmanager
from collections.abc import Awaitable, Callable

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.types import ASGIApp

from .bigquery_service import BigQueryService
from .query_policy import QueryPolicyError
from .settings import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

settings = get_settings()
bigquery_service = BigQueryService(settings)
mcp = FastMCP(
    "Secure BigQuery Gateway",
    instructions=(
        "Run read-only analytics queries only. Use fully-qualified, backtick-enclosed table or view "
        "references from the approved analytics dataset."
    ),
    stateless_http=True,
    json_response=True,
)


@mcp.tool()
def execute_readonly_sql(sql: str) -> dict:
    """Run a single, read-only BigQuery SELECT query against approved datasets.

    The gateway rejects writes, multiple statements, unapproved datasets, over-budget queries,
    and results exceeding the configured response cap.
    """

    try:
        return bigquery_service.execute_readonly_query(sql)
    except (QueryPolicyError, ValueError) as error:
        logger.warning("Rejected MCP query: %s", error)
        return {"error": str(error)}


@mcp.tool()
def gateway_capabilities() -> dict:
    """Describe the fixed security limits applied by this MCP gateway."""

    return {
        "mode": "read-only",
        "allowed_datasets": sorted(settings.allowed_dataset_set),
        "maximum_bytes_billed": settings.maximum_bytes_billed,
        "maximum_rows": settings.maximum_rows,
        "query_timeout_seconds": settings.query_timeout_seconds,
    }


class BearerTokenMiddleware:
    """Protects the remote MCP endpoint without sharing GCP credentials with callers.

    The sample uses a Secret Manager-injected bearer token for simple machine-to-machine callers.
    Replace this layer with an OAuth/OIDC token verifier when the selected MCP client supports it.
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self.token = token

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
        authorization = request.headers.get("authorization", "")
        supplied_token = authorization.removeprefix("Bearer ").strip()
        if not supplied_token or not hmac.compare_digest(supplied_token, self.token):
            response = JSONResponse({"detail": "Unauthorized"}, status_code=401)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


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
app = BearerTokenMiddleware(base_app, settings.mcp_bearer_token)


if __name__ == "__main__":
    import os

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
