"""Tests for scan limit enforcement."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from aegis.checks._http import safe_get
from aegis.core.exceptions import ScanLimitExceededError
from aegis.core.limits import RateLimiter
from aegis.core.models import ScanStatus
from aegis.scanner.engine import ScanEngine


async def test_rate_limiter_blocks_after_limit():
    clock = [0.0]
    limiter = RateLimiter(2, clock=lambda: clock[0])
    await limiter.acquire()
    await limiter.acquire()
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(limiter.acquire(), timeout=0.05)


@respx.mock
async def test_request_budget_is_enforced():
    respx.get("https://example.com/").mock(return_value=httpx.Response(200))
    context = {"request_count": 1, "budget": 1}
    async with httpx.AsyncClient() as client:
        with pytest.raises(ScanLimitExceededError):
            await safe_get(client, "https://example.com/", "example.com", context=context)


async def test_engine_enforces_scan_timeout(monkeypatch):
    engine = ScanEngine()
    engine.settings.scan_timeout_seconds = 0.01

    async def slow(*args: object, **kwargs: object) -> None:
        await asyncio.sleep(1)

    monkeypatch.setattr(engine, "_run_scan_inner", slow)
    result = await engine.run_scan("example.com", authorized=True)
    assert result.status == ScanStatus.FAILED
    assert "timed out" in (result.error_message or "")
