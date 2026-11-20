"""FastAPI application entrypoint for AEGIS."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from aegis import __version__
from aegis.core.config import get_settings
from aegis.core.exceptions import AegisError, DomainNotVerifiedError, SecurityViolationError
from aegis.core.logging import setup_logging
from aegis.core.models import ScanProfile, ScanResult, ScanStatus
from aegis.core.security import normalize_domain
from aegis.database.repository import get_result, list_results
from aegis.database.session import get_session, init_db
from aegis.scanner.engine import ScanEngine
from aegis.core.verification import DomainVerifier
from aegis.workers.tasks import celery_app, run_scan_task

setup_logging()
settings = get_settings()
engine = ScanEngine()
verifier = DomainVerifier()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="AEGIS",
    description="AI-Powered Cybersecurity Intelligence Platform",
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    domain: str = Field(..., examples=["example.com"])
    profile: ScanProfile = ScanProfile.SAFE
    authorized: bool = Field(
        ...,
        description="Must be true. Confirms explicit authorization to assess the domain.",
    )
    verified: bool = Field(
        False,
        description="Confirms domain ownership verification has been completed.",
    )


class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    message: str


class HealthResponse(BaseModel):
    status: str
    version: str


@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


@app.get(f"{settings.aegis_api_prefix}/health", response_model=HealthResponse, tags=["system"])
async def api_health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


@app.post(
    f"{settings.aegis_api_prefix}/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["scans"],
    summary="Queue a security assessment",
)
async def create_scan(body: ScanRequest) -> ScanResponse:
    """
    Queue a safe security scan and return immediately.

    Poll `GET /api/v1/scans/{scan_id}` for the result. Authorization and domain
    verification are checked before the scan is queued.
    """
    if not body.authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Explicit authorization (authorized=true) is required.",
        )
    try:
        if settings.require_domain_verification:
            await verifier.verify_or_raise(body.domain)
        domain = normalize_domain(body.domain)
    except DomainNotVerifiedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=e.message) from e
    except SecurityViolationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    scan_id = str(uuid4())
    args = (scan_id, domain, body.profile.value, body.authorized, body.verified)
    try:
        run_scan_task.apply_async(args=args, task_id=scan_id)
        message = "Scan queued in Celery worker"
    except Exception as exc:
        logger.warning("Broker unavailable (%s); running scan in-process", exc)
        asyncio.create_task(_run_in_process(*args))
        message = "Scan started in-process"

    return ScanResponse(scan_id=scan_id, status=ScanStatus.PENDING, message=message)


async def _run_in_process(
    scan_id: str,
    domain: str,
    profile: str,
    authorized: bool,
    verified: bool,
) -> None:
    try:
        await engine.run_scan(
            domain,
            profile=ScanProfile(profile),
            authorized=authorized,
            verified=verified,
            scan_id=scan_id,
        )
    except Exception as exc:
        logger.exception("In-process scan %s failed: %s", scan_id, exc)


@app.get(
    f"{settings.aegis_api_prefix}/scans/{{scan_id}}",
    response_model=ScanResult,
    tags=["scans"],
)
async def get_scan(scan_id: str) -> ScanResult:
    result = engine.get_status(scan_id)
    if result:
        return result
    async with get_session() as session:
        stored = await get_result(session, scan_id)
    if not stored:
        raise HTTPException(status_code=404, detail="Scan not found")
    return stored


@app.get(f"{settings.aegis_api_prefix}/scans", tags=["scans"])
async def list_scans(limit: int = 50) -> list[ScanResult]:
    """List recently stored scan results."""
    async with get_session() as session:
        records = await list_results(session, limit=limit)
    return [ScanResult.model_validate_json(record.result_json) for record in records]


@app.post(
    f"{settings.aegis_api_prefix}/scans/{{scan_id}}/cancel",
    tags=["scans"],
)
async def cancel_scan(scan_id: str) -> dict[str, Any]:
    try:
        celery_app.control.revoke(scan_id, terminate=True)
    except Exception as exc:
        logger.debug("Could not revoke Celery task %s: %s", scan_id, exc)
    ok = engine.cancel(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Scan not found or already finished")
    return {"scan_id": scan_id, "cancelled": True}
