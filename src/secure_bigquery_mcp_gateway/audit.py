"""Structured, one-line-per-event audit logging.

Cloud Run ships stdout to Cloud Logging automatically; emitting JSON here means
each audit event becomes a structured, queryable Cloud Logging entry with no
extra plumbing. Nothing in this module writes credentials, raw SQL parameters,
or row contents to the log — only shape (row counts, byte estimates, masking
counts), matching the "audit-friendly, not a data leak" goal in the README.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

audit_logger = logging.getLogger("secure_bigquery_mcp_gateway.audit")


@dataclass
class AuditEvent:
    request_id: str
    subject: str
    auth_method: str
    tool: str
    decision: str  # "allowed" | "denied" | "error"
    latency_ms: float
    detail: dict = field(default_factory=dict)

    def emit(self) -> None:
        payload = {
            "event": "mcp_tool_call",
            "request_id": self.request_id,
            "subject": self.subject,
            "auth_method": self.auth_method,
            "tool": self.tool,
            "decision": self.decision,
            "latency_ms": round(self.latency_ms, 2),
            **self.detail,
        }
        audit_logger.info(json.dumps(payload, default=str))


class Timer:
    """Tiny context-free stopwatch so call sites don't import `time` directly."""

    def __init__(self) -> None:
        self._start = time.monotonic()

    def elapsed_ms(self) -> float:
        return (time.monotonic() - self._start) * 1000
