"""Base class for individual security checks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx

from aegis.core.models import Finding


class BaseCheck(ABC):
    """Independent, testable security check."""

    check_id: str
    name: str
    description: str

    @abstractmethod
    async def run(
        self,
        client: httpx.AsyncClient,
        url: str,
        domain: str,
        context: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Execute the check and return zero or more findings."""
        ...
