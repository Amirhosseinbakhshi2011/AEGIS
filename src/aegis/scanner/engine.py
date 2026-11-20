"""Scan orchestration engine — safe, limited, evidence-based assessments."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import httpx

from aegis.checks.cookies import CookieCheck
from aegis.checks.headers import SecurityHeadersCheck
from aegis.checks.tls import TLSCheck
from aegis.core.config import get_settings
from aegis.core.exceptions import (
    DomainNotVerifiedError,
    ScanCancelledError,
    SecurityViolationError,
)
from aegis.core.limits import RateLimiter
from aegis.core.logging import get_logger
from aegis.core.models import (
    ScanProfile,
    ScanResult,
    ScanStatus,
)
from aegis.core.security import SSRFProtectedTransport, normalize_domain, resolve_and_validate
from aegis.core.verification import DomainVerifier
from aegis.database.repository import save_result
from aegis.database.session import get_session
from aegis.domains.intelligence import DomainIntelligence
from aegis.risk.engine import RiskEngine

logger = get_logger(__name__)


class ScanEngine:
    """Coordinates domain intelligence + web security checks under strict safety limits."""

    def __init__(self, verifier: DomainVerifier | None = None) -> None:
        self.settings = get_settings()
        self.domain_intel = DomainIntelligence(timeout=self.settings.request_timeout_seconds)
        self.risk_engine = RiskEngine()
        self.verifier = verifier or DomainVerifier()
        self._cancelled: set[str] = set()
        self._active_scans: dict[str, ScanResult] = {}
        self._semaphore = asyncio.Semaphore(max(1, self.settings.max_concurrent_scans))
        self._limiter = RateLimiter(self.settings.rate_limit_per_minute)

        self.checks = [
            SecurityHeadersCheck(),
            TLSCheck(),
            CookieCheck(),
        ]

    def cancel(self, scan_id: str) -> bool:
        """Request cancellation of a running scan."""
        if scan_id in self._active_scans:
            self._cancelled.add(scan_id)
            return True
        return False

    def get_status(self, scan_id: str) -> ScanResult | None:
        return self._active_scans.get(scan_id)

    async def run_scan(
        self,
        domain: str,
        *,
        profile: ScanProfile = ScanProfile.SAFE,
        authorized: bool = False,
        verified: bool = False,
        metadata: dict[str, Any] | None = None,
        scan_id: str | None = None,
    ) -> ScanResult:
        """Execute a full safe assessment under all configured safety limits."""
        async with self._semaphore:
            await self._limiter.acquire()
            scan_id = scan_id or str(uuid4())
            try:
                async with asyncio.timeout(self.settings.scan_timeout_seconds):
                    result = await self._run_scan_inner(
                        domain,
                        profile=profile,
                        authorized=authorized,
                        verified=verified,
                        metadata=metadata,
                        scan_id=scan_id,
                    )
            except TimeoutError:
                result = ScanResult(
                    scan_id=scan_id,
                    target_domain=normalize_domain(domain),
                    status=ScanStatus.FAILED,
                    error_message=f"Scan timed out after {self.settings.scan_timeout_seconds}s",
                )
                result.finished_at = datetime.now(UTC)
                self._active_scans[scan_id] = result

            await self._persist(result)
            return result

    async def _persist(self, result: ScanResult) -> None:
        """Store the result; persistence problems must never fail a scan."""
        try:
            async with get_session() as session:
                await save_result(session, result)
        except Exception as exc:
            logger.warning("Could not persist scan %s: %s", result.scan_id, exc)

    async def _run_scan_inner(
        self,
        domain: str,
        *,
        profile: ScanProfile = ScanProfile.SAFE,
        authorized: bool = False,
        verified: bool = False,
        metadata: dict[str, Any] | None = None,
        scan_id: str | None = None,
    ) -> ScanResult:
        """Authorization and domain verification must be confirmed by the caller."""
        if self.settings.require_domain_verification and not verified:
            raise DomainNotVerifiedError(domain)

        if verified and self.settings.require_domain_verification:
            await self.verifier.verify_or_raise(domain)

        if not authorized:
            raise SecurityViolationError(
                "Explicit authorization is required before any scan can start."
            )

        domain = normalize_domain(domain)
        scan_id = scan_id or str(uuid4())
        result = ScanResult(
            scan_id=scan_id,
            target_domain=domain,
            status=ScanStatus.RUNNING,
            profile=profile,
            started_at=datetime.now(UTC),
            metadata=metadata or {},
        )
        self._active_scans[scan_id] = result

        try:
            public_ips = resolve_and_validate(domain)
            result.metadata["resolved_ips"] = public_ips
            logger.info("Scan %s started for %s (ips=%s)", scan_id, domain, public_ips)

            self._check_cancelled(scan_id)

            domain_info, dns_findings = await self.domain_intel.analyze(domain)
            result.domain_info = domain_info
            result.findings.extend(dns_findings)

            self._check_cancelled(scan_id)

            base_url = f"https://{domain}/"
            timeout = httpx.Timeout(self.settings.request_timeout_seconds)
            limits = httpx.Limits(max_connections=5, max_keepalive_connections=2)

            context: dict[str, Any] = {
                "request_count": 0,
                "budget": self.settings.max_requests_per_scan,
            }

            async with httpx.AsyncClient(
                timeout=timeout,
                limits=limits,
                transport=SSRFProtectedTransport(verify=True),
                headers={"User-Agent": "AEGIS-Security-Scanner/0.1 (+https://github.com/Amirhosseinbakhshi2011/AEGIS)"},
            ) as client:
                for check in self.checks:
                    self._check_cancelled(scan_id)
                    if context["request_count"] >= context["budget"]:
                        logger.warning("Scan %s hit request budget", scan_id)
                        break
                    try:
                        findings = await asyncio.wait_for(
                            check.run(client, base_url, domain, context),
                            timeout=self.settings.request_timeout_seconds + 5,
                        )
                        result.findings.extend(findings)
                    except TimeoutError:
                        logger.warning("Check %s timed out", check.check_id)
                    except Exception:
                        logger.exception("Check %s failed", check.check_id)

            result.risk_score, result.risk_summary = self.risk_engine.score(result.findings)
            result.status = ScanStatus.COMPLETED
            result.finished_at = datetime.now(UTC)
            logger.info(
                "Scan %s completed: %d findings, score=%.1f",
                scan_id,
                len(result.findings),
                result.risk_score or 0,
            )

        except ScanCancelledError:
            result.status = ScanStatus.CANCELLED
            result.finished_at = datetime.now(UTC)
            result.error_message = "Scan cancelled by user"
        except SecurityViolationError as exc:
            result.status = ScanStatus.FAILED
            result.finished_at = datetime.now(UTC)
            result.error_message = str(exc)
            logger.warning("Scan %s blocked by security policy: %s", scan_id, exc)
        except Exception as exc:
            result.status = ScanStatus.FAILED
            result.finished_at = datetime.now(UTC)
            result.error_message = str(exc)
            logger.exception("Scan %s failed", scan_id)
        finally:
            self._cancelled.discard(scan_id)

        return result

    def _check_cancelled(self, scan_id: str) -> None:
        if scan_id in self._cancelled:
            raise ScanCancelledError(scan_id)
