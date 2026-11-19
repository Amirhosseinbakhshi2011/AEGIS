"""Scan orchestration engine — safe, limited, evidence-based assessments."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
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
from aegis.core.logging import get_logger
from aegis.core.models import (
    Finding,
    ScanProfile,
    ScanResult,
    ScanStatus,
)
from aegis.core.security import normalize_domain, resolve_and_validate
from aegis.domains.intelligence import DomainIntelligence
from aegis.risk.engine import RiskEngine

logger = get_logger(__name__)


class ScanEngine:
    """Coordinates domain intelligence + web security checks under strict safety limits."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.domain_intel = DomainIntelligence(timeout=self.settings.request_timeout_seconds)
        self.risk_engine = RiskEngine()
        self._cancelled: set[str] = set()
        self._active_scans: dict[str, ScanResult] = {}

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
    ) -> ScanResult:
        """
        Execute a full safe assessment.

        Authorization and domain verification must be confirmed by the caller.
        """
        if self.settings.require_domain_verification and not verified:
            raise DomainNotVerifiedError(domain)

        if not authorized:
            raise SecurityViolationError(
                "Explicit authorization is required before any scan can start."
            )

        domain = normalize_domain(domain)
        scan_id = str(uuid4())
        result = ScanResult(
            scan_id=scan_id,
            target_domain=domain,
            status=ScanStatus.RUNNING,
            profile=profile,
            started_at=datetime.now(timezone.utc),
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

            async with httpx.AsyncClient(
                timeout=timeout,
                limits=limits,
                follow_redirects=False,
                headers={"User-Agent": "AEGIS-Security-Scanner/0.1 (+https://github.com/Amirhosseinbakhshi2011/AEGIS)"},
                verify=True,
            ) as client:
                request_count = 0
                max_req = self.settings.max_requests_per_scan

                for check in self.checks:
                    self._check_cancelled(scan_id)
                    if request_count >= max_req:
                        logger.warning("Scan %s hit request budget", scan_id)
                        break
                    try:
                        findings = await asyncio.wait_for(
                            check.run(client, base_url, domain),
                            timeout=self.settings.request_timeout_seconds + 5,
                        )
                        result.findings.extend(findings)
                        request_count += 1
                    except asyncio.TimeoutError:
                        logger.warning("Check %s timed out", check.check_id)
                    except Exception as exc:
                        logger.exception("Check %s failed: %s", check.check_id, exc)

            result.risk_score, result.risk_summary = self.risk_engine.score(result.findings)
            result.status = ScanStatus.COMPLETED
            result.finished_at = datetime.now(timezone.utc)
            logger.info(
                "Scan %s completed: %d findings, score=%.1f",
                scan_id,
                len(result.findings),
                result.risk_score or 0,
            )

        except ScanCancelledError:
            result.status = ScanStatus.CANCELLED
            result.finished_at = datetime.now(timezone.utc)
            result.error_message = "Scan cancelled by user"
        except SecurityViolationError as exc:
            result.status = ScanStatus.FAILED
            result.finished_at = datetime.now(timezone.utc)
            result.error_message = str(exc)
            logger.warning("Scan %s blocked by security policy: %s", scan_id, exc)
        except Exception as exc:
            result.status = ScanStatus.FAILED
            result.finished_at = datetime.now(timezone.utc)
            result.error_message = str(exc)
            logger.exception("Scan %s failed", scan_id)
        finally:
            self._cancelled.discard(scan_id)

        return result

    def _check_cancelled(self, scan_id: str) -> None:
        if scan_id in self._cancelled:
            raise ScanCancelledError(scan_id)
