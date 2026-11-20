"""TLS / certificate checks."""

from __future__ import annotations

import ssl
from datetime import datetime, timezone
from typing import Any

import httpx

from aegis.checks._http import _record, safe_get
from aegis.checks.base import BaseCheck
from aegis.core.exceptions import ScanLimitExceededError, SecurityViolationError
from aegis.core.models import Confidence, Finding, FindingCategory, Severity
from aegis.core.security import resolve_and_validate


class TLSCheck(BaseCheck):
    check_id = "tls.certificate"
    name = "TLS Certificate"
    description = "Validate HTTPS availability and certificate properties."

    async def run(
        self,
        client: httpx.AsyncClient,
        url: str,
        domain: str,
        context: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        https_url = url if url.startswith("https://") else f"https://{domain}/"

        try:
            resp = await safe_get(client, https_url, domain, context=context)
            if resp.status_code >= 500:
                findings.append(
                    Finding(
                        title="HTTPS endpoint returned server error",
                        description=f"HTTPS request returned HTTP {resp.status_code}.",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.TLS,
                        evidence={"status_code": resp.status_code},
                        check_id="tls.https_error",
                        affected_url=https_url,
                    )
                )
        except httpx.ConnectError:
            findings.append(
                Finding(
                    title="HTTPS not available",
                    description="Could not establish a TLS connection to the target.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.TLS,
                    evidence={},
                    remediation="Enable HTTPS and obtain a valid certificate from a trusted CA.",
                    check_id="tls.https_unavailable",
                    affected_url=https_url,
                )
            )
            return findings
        except SecurityViolationError as exc:
            findings.append(
                Finding(
                    title="Redirect escaped authorized scope",
                    description=str(exc),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.TLS,
                    evidence={"error": str(exc)},
                    remediation="Keep all redirects within the authorized domain.",
                    check_id="tls.redirect_scope_violation",
                    affected_url=https_url,
                )
            )
            return findings
        except Exception as exc:
            if isinstance(exc, ScanLimitExceededError):
                raise
            findings.append(
                Finding(
                    title="TLS connection problem",
                    description=str(exc),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category=FindingCategory.TLS,
                    evidence={"error": str(exc)},
                    check_id="tls.connection_error",
                    affected_url=https_url,
                )
            )
            return findings

        try:
            cert_info = await self._get_cert_info(domain)
            if cert_info:
                findings.extend(self._analyze_cert(cert_info, https_url))
        except Exception:
            pass

        http_url = f"http://{domain}/"
        try:
            _record(context)
            http_resp = await client.get(http_url, follow_redirects=False)
            location = http_resp.headers.get("location", "")
            if location:
                from urllib.parse import urljoin

                validate_redirect_target(domain, urljoin(http_url, location))
            if http_resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
                pass
            elif http_resp.status_code < 400:
                findings.append(
                    Finding(
                        title="HTTP does not redirect to HTTPS",
                        description=(
                            "The HTTP endpoint is reachable and does not issue a redirect "
                            "to the HTTPS version of the site."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.TLS,
                        evidence={
                            "status_code": http_resp.status_code,
                            "location": location or None,
                        },
                        remediation="Configure a permanent redirect from HTTP to HTTPS.",
                        check_id="tls.no_https_redirect",
                        affected_url=http_url,
                    )
                )
        except Exception:
            pass

        return findings

    async def _get_cert_info(self, domain: str) -> dict[str, Any] | None:
        import asyncio
        import socket

        try:
            ips = await asyncio.to_thread(resolve_and_validate, domain)
        except Exception:
            return None
        ip = ips[0]

        def _fetch() -> dict[str, Any] | None:
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(
                    socket.create_connection((ip, 443), timeout=8),
                    server_hostname=domain,
                ) as sock:
                    return sock.getpeercert()  # type: ignore[return-value]
            except Exception:
                return None

        return await asyncio.to_thread(_fetch)

    def _analyze_cert(self, cert: dict[str, Any], url: str) -> list[Finding]:
        findings: list[Finding] = []
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days_left = (exp - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append(
                        Finding(
                            title="TLS certificate has expired",
                            description=f"Certificate expired on {not_after}.",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.TLS,
                            evidence={"notAfter": not_after, "days_left": days_left},
                            remediation="Renew the certificate immediately.",
                            check_id="tls.cert_expired",
                            affected_url=url,
                        )
                    )
                elif days_left < 14:
                    findings.append(
                        Finding(
                            title="TLS certificate expires soon",
                            description=f"Certificate expires in {days_left} days ({not_after}).",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.TLS,
                            evidence={"notAfter": not_after, "days_left": days_left},
                            remediation="Plan certificate renewal.",
                            check_id="tls.cert_expiring",
                            affected_url=url,
                        )
                    )
                elif days_left < 30:
                    findings.append(
                        Finding(
                            title="TLS certificate expires within 30 days",
                            description=f"Certificate expires in {days_left} days.",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.TLS,
                            evidence={"notAfter": not_after, "days_left": days_left},
                            remediation="Schedule renewal.",
                            check_id="tls.cert_expiring_30",
                            affected_url=url,
                        )
                    )
            except ValueError:
                pass
        return findings
