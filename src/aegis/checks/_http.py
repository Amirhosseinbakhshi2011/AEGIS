"""Shared, SSRF-safe HTTP request helper for all checks."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

from aegis.core.exceptions import ScanLimitExceededError, SecurityViolationError
from aegis.core.security import is_safe_url_for_scan, validate_redirect_target

REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _record(context: dict[str, Any] | None) -> None:
    if context is not None:
        context["request_count"] = context.get("request_count", 0) + 1


async def safe_get(
    client: httpx.AsyncClient,
    url: str,
    domain: str,
    *,
    context: dict[str, Any] | None = None,
    max_redirects: int = 3,
) -> httpx.Response:
    """GET a URL while validating every redirect hop against the authorized scope."""
    current = url
    for _ in range(max_redirects + 1):
        budget = context.get("budget") if context else None
        if (
            budget is not None
            and context is not None
            and context.get("request_count", 0) >= budget
        ):
            raise ScanLimitExceededError(f"Request budget of {budget} exhausted")
        if not is_safe_url_for_scan(current, domain):
            raise SecurityViolationError(f"URL is outside the authorized scope: {current}")
        _record(context)
        response = await client.get(current, follow_redirects=False)
        location = response.headers.get("location")
        if response.status_code in REDIRECT_STATUSES and location:
            target = urljoin(current, location)
            validate_redirect_target(domain, target)
            current = target
            continue
        return response
    raise SecurityViolationError(f"Too many redirects while requesting {url}")
