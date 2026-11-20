"""FastAPI application entrypoint for AEGIS."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from aegis import __version__
from aegis.core.config import get_settings
from aegis.core.exceptions import AegisError, DomainNotVerifiedError, SecurityViolationError
from aegis.core.logging import setup_logging
from aegis.core.models import ScanProfile, ScanResult, ScanStatus
from aegis.database.repository import get_result, list_results
from aegis.database.session import get_session, init_db
from aegis.scanner.engine import ScanEngine

setup_logging()
settings = get_settings()
engine = ScanEngine()


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
    response_model=ScanResult,
    tags=["scans"],
    summary="Start a security assessment",
)
async def create_scan(body: ScanRequest) -> ScanResult:
    """
    Start a safe security scan.

    **Authorization is mandatory.** Set `authorized=true` only when you own the domain
    or hold explicit written permission. When `require_domain_verification` is enabled,
    `verified` must also be true.
    """
    if not body.authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Explicit authorization (authorized=true) is required.",
        )
    try:
        result = await engine.run_scan(
            body.domain,
            profile=body.profile,
            authorized=body.authorized,
            verified=body.verified,
        )
        return result
    except DomainNotVerifiedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=e.message) from e
    except SecurityViolationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e
    except AegisError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from e
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


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
    ok = engine.cancel(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Scan not found or already finished")
    return {"scan_id": scan_id, "cancelled": True}
