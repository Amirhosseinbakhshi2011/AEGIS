"""HTTP security headers checks."""

from __future__ import annotations

from typing import Any, ClassVar

import httpx

from aegis.checks._http import safe_get
from aegis.checks.base import BaseCheck
from aegis.core.exceptions import ScanLimitExceededError, SecurityViolationError
from aegis.core.models import Confidence, Finding, FindingCategory, Severity


class SecurityHeadersCheck(BaseCheck):
    check_id = "headers.security"
    name = "Security Headers"
    description = "Inspect common HTTP security response headers."

    EXPECTED: ClassVar[dict[str, dict[str, object]]] = {
        "strict-transport-security": {
            "severity": Severity.MEDIUM,
            "remediation": (
                "Add Strict-Transport-Security header, e.g. "
                "'max-age=31536000; includeSubDomains; preload'."
            ),
        },
        "content-security-policy": {
            "severity": Severity.MEDIUM,
            "remediation": "Deploy a Content-Security-Policy tailored to the application.",
        },
        "x-frame-options": {
            "severity": Severity.LOW,
            "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN (or use CSP frame-ancestors).",
        },
        "x-content-type-options": {
            "severity": Severity.LOW,
            "remediation": "Set X-Content-Type-Options: nosniff.",
        },
        "referrer-policy": {
            "severity": Severity.LOW,
            "remediation": "Set a Referrer-Policy such as strict-origin-when-cross-origin.",
        },
        "permissions-policy": {
            "severity": Severity.INFORMATIONAL,
            "remediation": "Consider a Permissions-Policy to restrict browser features.",
        },
    }

    async def run(
        self,
        client: httpx.AsyncClient,
        url: str,
        domain: str,
        context: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await safe_get(client, url, domain, context=context)
        except SecurityViolationError as exc:
            return [
                Finding(
                    title="Redirect escaped authorized scope",
                    description=str(exc),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.MISCONFIGURATION,
                    evidence={"error": str(exc)},
                    check_id="headers.redirect_scope_violation",
                    affected_url=url,
                )
            ]
        except Exception as exc:
            if isinstance(exc, ScanLimitExceededError):
                raise
            return [
                Finding(
                    title="Failed to fetch headers",
                    description=f"Could not retrieve response headers: {exc}",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.LOW,
                    category=FindingCategory.HEADERS,
                    evidence={"error": str(exc)},
                    check_id=self.check_id,
                    affected_url=url,
                )
            ]

        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, meta in self.EXPECTED.items():
            if header not in headers:
                findings.append(
                    Finding(
                        title=f"Missing security header: {header}",
                        description=f"The response does not include the '{header}' header.",
                        severity=meta["severity"],
                        confidence=Confidence.HIGH,
                        category=FindingCategory.HEADERS,
                        evidence={"present_headers": list(headers.keys())},
                        remediation=meta["remediation"],
                        check_id=f"headers.missing.{header}",
                        affected_url=url,
                    )
                )

        csp = headers.get("content-security-policy", "").lower()
        if "frame-ancestors" in csp:
            findings = [f for f in findings if f.check_id != "headers.missing.x-frame-options"]

        if "server" in headers:
            findings.append(
                Finding(
                    title="Server header discloses software",
                    description=(
                        f"The Server header is present and set to '{headers['server']}'. "
                        "This can help attackers fingerprint the stack."
                    ),
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.EXPOSURE,
                    evidence={"server": headers["server"]},
                    remediation="Remove or genericize the Server header.",
                    check_id="headers.server_leak",
                    affected_url=url,
                )
            )

        if "x-powered-by" in headers:
            findings.append(
                Finding(
                    title="X-Powered-By header present",
                    description=f"X-Powered-By: {headers['x-powered-by']}",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.EXPOSURE,
                    evidence={"x-powered-by": headers["x-powered-by"]},
                    remediation="Remove the X-Powered-By header.",
                    check_id="headers.x_powered_by",
                    affected_url=url,
                )
            )

        return findings
