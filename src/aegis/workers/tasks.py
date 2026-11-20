"""Celery tasks for background scan execution.

Falls back to in-process execution from the API when no broker is reachable,
so local development does not require Redis.
"""

from __future__ import annotations

import asyncio

from celery import Celery

from aegis.core.config import get_settings
from aegis.core.models import ScanProfile
from aegis.scanner.engine import ScanEngine

settings = get_settings()

celery_app = Celery("aegis", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
)


@celery_app.task(name="aegis.run_scan")
def run_scan_task(
    scan_id: str,
    domain: str,
    profile: str,
    authorized: bool,
    verified: bool,
) -> dict[str, object]:
    """Run one assessment in a worker process."""
    result = asyncio.run(
        ScanEngine().run_scan(
            domain,
            profile=ScanProfile(profile),
            authorized=authorized,
            verified=verified,
            scan_id=scan_id,
        )
    )
    return result.model_dump(mode="json")
