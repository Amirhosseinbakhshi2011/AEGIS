"""Persistence helpers for scan results."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.models import ScanResult
from aegis.database.models import ScanRecord


async def save_result(session: AsyncSession, result: ScanResult) -> None:
    record = ScanRecord(
        scan_id=result.scan_id,
        target_domain=result.target_domain,
        status=result.status.value,
        profile=result.profile.value,
        risk_score=result.risk_score,
        started_at=result.started_at,
        finished_at=result.finished_at,
        result_json=result.model_dump_json(),
    )
    await session.merge(record)
    await session.commit()


async def get_result(session: AsyncSession, scan_id: str) -> ScanResult | None:
    record = await session.get(ScanRecord, scan_id)
    if record is None:
        return None
    return ScanResult.model_validate_json(record.result_json)


async def list_results(session: AsyncSession, limit: int = 50) -> list[ScanRecord]:
    result = await session.execute(
        select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit)
    )
    return list(result.scalars().all())
