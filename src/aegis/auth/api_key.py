"""API key authentication and per-client rate limiting."""

from __future__ import annotations

import secrets
import time

from fastapi import Header, HTTPException, Request, status

from aegis.core.config import get_settings
from aegis.core.limits import RateLimiter

settings = get_settings()


async def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """Require a shared key only when one is configured."""
    expected = settings.api_key
    if not expected:
        return
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )


class ApiRateLimiter:
    """Per-client limiter backed by non-blocking token checks."""

    def __init__(self, rate_per_minute: int) -> None:
        self.rate = rate_per_minute
        self._limiters: dict[str, RateLimiter] = {}

    def allow(self, client: str) -> bool:
        limiter = self._limiters.setdefault(client, RateLimiter(self.rate, clock=time.monotonic))
        return limiter.try_acquire()


api_limiter = ApiRateLimiter(settings.rate_limit_per_minute)


async def enforce_rate_limit(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    if not api_limiter.allow(client):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )
