"""Cookie attribute security checks."""

from __future__ import annotations

from typing import Any

import httpx

from aegis.checks._http import safe_get
from aegis.checks.base import BaseCheck
from aegis.core.exceptions import ScanLimitExceededError
from aegis.core.models import Confidence, Finding, FindingCategory, Severity


class CookieCheck(BaseCheck):
    check_id = "cookies.attributes"
    name = "Cookie Security Attributes"
    description = "Inspect Set-Cookie attributes for Secure, HttpOnly and SameSite."

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
        except Exception as exc:
            if isinstance(exc, ScanLimitExceededError):
                raise
            return findings

        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not set_cookie_headers:
            sc = resp.headers.get("set-cookie")
            if sc:
                set_cookie_headers = [sc]

        for raw in set_cookie_headers:
            lower = raw.lower()
            name = raw.split("=", 1)[0].strip() if "=" in raw else "unknown"

            if "secure" not in lower:
                findings.append(
                    Finding(
                        title=f"Cookie '{name}' missing Secure attribute",
                        description=(
                            "The cookie is not marked Secure and may be transmitted over HTTP."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.COOKIES,
                        evidence={"set_cookie": raw[:200]},
                        remediation="Add the Secure attribute to all cookies.",
                        check_id="cookies.missing_secure",
                        affected_url=url,
                    )
                )
            if "httponly" not in lower:
                findings.append(
                    Finding(
                        title=f"Cookie '{name}' missing HttpOnly attribute",
                        description=(
                            "Without HttpOnly the cookie is accessible to JavaScript, "
                            "increasing XSS impact."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.COOKIES,
                        evidence={"set_cookie": raw[:200]},
                        remediation="Add the HttpOnly attribute where JavaScript access is not required.",
                        check_id="cookies.missing_httponly",
                        affected_url=url,
                    )
                )
            if "samesite" not in lower:
                findings.append(
                    Finding(
                        title=f"Cookie '{name}' missing SameSite attribute",
                        description="SameSite helps mitigate CSRF attacks.",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.COOKIES,
                        evidence={"set_cookie": raw[:200]},
                        remediation="Set SameSite=Lax or SameSite=Strict as appropriate.",
                        check_id="cookies.missing_samesite",
                        affected_url=url,
                    )
                )

        return findings
