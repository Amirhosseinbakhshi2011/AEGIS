"""Tests for API key authentication and rate limiting."""

from __future__ import annotations

import httpx

from aegis.api.main import app, verifier
from aegis.auth.api_key import api_limiter, settings as auth_settings
from aegis.workers.tasks import run_scan_task

BODY = {
    "domain": "example.com",
    "profile": "safe",
    "authorized": True,
    "verified": True,
}


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _allow(monkeypatch) -> None:
    async def fake_verify(domain: str) -> None:
        return None

    monkeypatch.setattr(verifier, "verify_or_raise", fake_verify)
    monkeypatch.setattr(run_scan_task, "apply_async", lambda *a, **k: None)
    api_limiter._limiters.clear()


async def test_missing_api_key_is_rejected(monkeypatch):
    monkeypatch.setattr(auth_settings, "api_key", "correct-key")
    await _allow(monkeypatch)
    async with _client() as client:
        response = await client.post("/api/v1/scans", json=BODY)
    assert response.status_code == 401


async def test_wrong_api_key_is_rejected(monkeypatch):
    monkeypatch.setattr(auth_settings, "api_key", "correct-key")
    await _allow(monkeypatch)
    async with _client() as client:
        response = await client.post(
            "/api/v1/scans", json=BODY, headers={"X-API-Key": "wrong"}
        )
    assert response.status_code == 401


async def test_valid_api_key_is_accepted(monkeypatch):
    monkeypatch.setattr(auth_settings, "api_key", "correct-key")
    await _allow(monkeypatch)
    async with _client() as client:
        response = await client.post(
            "/api/v1/scans", json=BODY, headers={"X-API-Key": "correct-key"}
        )
    assert response.status_code == 202


async def test_rate_limit_returns_429(monkeypatch):
    monkeypatch.setattr(auth_settings, "api_key", "")
    await _allow(monkeypatch)
    monkeypatch.setattr(api_limiter, "rate", 1)
    api_limiter._limiters.clear()
    async with _client() as client:
        first = await client.post("/api/v1/scans", json=BODY)
        second = await client.post("/api/v1/scans", json=BODY)
    assert first.status_code == 202
    assert second.status_code == 429
