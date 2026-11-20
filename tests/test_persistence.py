"""Tests for scan result persistence."""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool

from aegis.core.models import ScanResult, ScanStatus
from aegis.database.models import Base
from aegis.database.repository import get_result, list_results, save_result
from aegis.scanner.engine import ScanEngine


@pytest.fixture
async def session():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSession(engine, expire_on_commit=False) as db:
        yield db
    await engine.dispose()


async def test_save_and_reload_result(session):
    result = ScanResult(
        target_domain="example.com",
        status=ScanStatus.COMPLETED,
        risk_score=88.5,
    )
    await save_result(session, result)

    loaded = await get_result(session, result.scan_id)
    assert loaded is not None
    assert loaded.target_domain == "example.com"
    assert loaded.risk_score == 88.5
    assert loaded.status == ScanStatus.COMPLETED


async def test_missing_result_returns_none(session):
    assert await get_result(session, "does-not-exist") is None


async def test_engine_saves_completed_scan(session, monkeypatch):
    engine = ScanEngine()
    result = ScanResult(target_domain="persisted.com", status=ScanStatus.COMPLETED)

    async def fake_inner(*args: object, **kwargs: object) -> ScanResult:
        return result

    @asynccontextmanager
    async def fake_session():
        yield session

    monkeypatch.setattr(engine, "_run_scan_inner", fake_inner)
    monkeypatch.setattr("aegis.scanner.engine.get_session", fake_session)

    returned = await engine.run_scan("persisted.com", authorized=True)
    assert returned.scan_id == result.scan_id
    assert await get_result(session, result.scan_id) is not None


async def test_list_results_newest_first(session):
    first = ScanResult(target_domain="first.com", status=ScanStatus.COMPLETED)
    await save_result(session, first)
    second = ScanResult(target_domain="second.com", status=ScanStatus.COMPLETED)
    await save_result(session, second)

    records = await list_results(session)
    assert len(records) == 2
    assert {record.scan_id for record in records} == {first.scan_id, second.scan_id}
