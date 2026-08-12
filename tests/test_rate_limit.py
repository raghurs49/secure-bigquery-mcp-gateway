import unittest

from secure_bigquery_mcp_gateway.rate_limit import (
    DailyBudgetExceeded,
    RateLimiter,
    RateLimitExceeded,
)


class RateLimiterTests(unittest.TestCase):
    def test_allows_requests_under_the_limit(self) -> None:
        limiter = RateLimiter(requests_per_minute=3, daily_byte_budget=1000)
        for _ in range(3):
            limiter.check_request_rate("alice")  # should not raise

    def test_rejects_the_request_that_exceeds_the_limit(self) -> None:
        limiter = RateLimiter(requests_per_minute=2, daily_byte_budget=1000)
        limiter.check_request_rate("alice")
        limiter.check_request_rate("alice")
        with self.assertRaises(RateLimitExceeded):
            limiter.check_request_rate("alice")

    def test_identities_have_independent_limits(self) -> None:
        limiter = RateLimiter(requests_per_minute=1, daily_byte_budget=1000)
        limiter.check_request_rate("alice")
        limiter.check_request_rate("bob")  # different identity, should not raise

    def test_old_requests_fall_out_of_the_one_minute_window(self) -> None:
        limiter = RateLimiter(requests_per_minute=1, daily_byte_budget=1000)
        limiter.check_request_rate("alice", now=0.0)
        limiter.check_request_rate("alice", now=61.0)  # window has rolled forward

    def test_charges_within_budget_succeed(self) -> None:
        limiter = RateLimiter(requests_per_minute=10, daily_byte_budget=1000)
        limiter.charge_bytes("alice", 400)
        limiter.charge_bytes("alice", 400)

    def test_charge_beyond_daily_budget_raises(self) -> None:
        limiter = RateLimiter(requests_per_minute=10, daily_byte_budget=1000)
        limiter.charge_bytes("alice", 900)
        with self.assertRaises(DailyBudgetExceeded):
            limiter.charge_bytes("alice", 200)

    def test_byte_budgets_are_independent_per_identity(self) -> None:
        limiter = RateLimiter(requests_per_minute=10, daily_byte_budget=500)
        limiter.charge_bytes("alice", 500)
        limiter.charge_bytes("bob", 500)  # separate identity, separate budget


if __name__ == "__main__":
    unittest.main()
