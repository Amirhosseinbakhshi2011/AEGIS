"""Tests for non-blocking scan dispatch in the API."""

from __future__ import annotations

import asyncio

import httpx

from aegis.api.main import app, engine, verifier
from aegis.workers.tasks import run_scan_task

VALID_BODY = {
    "domain": "example.com",
    "profile": "safe",
    "authorized": True,
    "verified": True,
}


async def test_create_scan_queues_task_and_returns_202(monkeypatch):
    async def fake_verify(domain: str) -> None:
        return None

    queued: list[tuple] = []
    monkeypatch.setattr(verifier, "verify_or_raise", fake_verify)
    monkeypatch.setattr(run_scan_task, "apply_async", lambda *a, **k: queued.append((a, k)))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/api/v1/scans", json=VALID_BODY)

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "pending"
    assert "Celery" in body["message"]
    assert queued and queued[0][1]["task_id"] == body["scan_id"]


async def test_create_scan_rejects_missing_authorization():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/scans", json={**VALID_BODY, "authorized": False}
        )
    assert response.status_code == 403


async def test_create_scan_falls_back_to_in_process(monkeypatch):
    async def fake_verify(domain: str) -> None:
        return None

    async def fake_run(*args: object, **kwargs: object) -> None:
        return None

    def broker_down(*args: object, **kwargs: object) -> None:
        raise OSError("broker unavailable")

    monkeypatch.setattr(verifier, "verify_or_raise", fake_verify)
    monkeypatch.setattr(run_scan_task, "apply_async", broker_down)
    monkeypatch.setattr(engine, "run_scan", fake_run)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/api/v1/scans", json=VALID_BODY)

    assert response.status_code == 202
    assert "in-process" in response.json()["message"]
    await asyncio.sleep(0)
