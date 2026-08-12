"""Per-identity request rate limiting and a rolling daily byte budget.

In-memory and per-instance: correct for the reference build's single Cloud Run
instance, and explicitly called out in the README's production checklist as
needing to move to Memorystore/Redis once the service scales past one instance.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


class RateLimitExceeded(Exception):
    pass


class DailyBudgetExceeded(Exception):
    pass


@dataclass
class _IdentityState:
    request_timestamps: list[float] = field(default_factory=list)
    bytes_used_today: int = 0
    budget_day: str = ""


class RateLimiter:
    def __init__(self, requests_per_minute: int, daily_byte_budget: int) -> None:
        self.requests_per_minute = requests_per_minute
        self.daily_byte_budget = daily_byte_budget
        self._state: dict[str, _IdentityState] = {}
        self._lock = threading.Lock()

    def check_request_rate(self, subject: str, *, now: float | None = None) -> None:
        now = now if now is not None else time.monotonic()
        with self._lock:
            state = self._state.setdefault(subject, _IdentityState())
            window_start = now - 60
            state.request_timestamps = [t for t in state.request_timestamps if t >= window_start]
            if len(state.request_timestamps) >= self.requests_per_minute:
                raise RateLimitExceeded(
                    f"Rate limit of {self.requests_per_minute} requests/minute exceeded."
                )
            state.request_timestamps.append(now)

    def charge_bytes(self, subject: str, byte_count: int) -> None:
        today = time.strftime("%Y-%m-%d", time.gmtime())
        with self._lock:
            state = self._state.setdefault(subject, _IdentityState())
            if state.budget_day != today:
                state.budget_day = today
                state.bytes_used_today = 0
            if state.bytes_used_today + byte_count > self.daily_byte_budget:
                raise DailyBudgetExceeded(
                    f"Daily byte budget of {self.daily_byte_budget} exceeded for this identity."
                )
            state.bytes_used_today += byte_count
