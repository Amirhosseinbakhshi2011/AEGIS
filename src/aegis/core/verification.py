"""Domain ownership verification through DNS TXT records.

The token is derived from the domain and the application secret, so it is
stable across runs and cannot be forged without the secret.
"""

from __future__ import annotations

import hashlib
import hmac

import dns.asyncresolver
import dns.exception

from aegis.core.config import get_settings
from aegis.core.exceptions import DomainNotVerifiedError
from aegis.core.logging import get_logger
from aegis.core.security import normalize_domain

logger = get_logger(__name__)


def generate_token(domain: str, secret: str) -> str:
    """Return a deterministic verification token for the domain."""
    message = f"aegis:domain-verification:{normalize_domain(domain)}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()[:32]


def build_txt_value(domain: str, secret: str, prefix: str) -> str:
    """Return the exact TXT value the domain owner must publish."""
    return f"{prefix}{generate_token(domain, secret)}"


class DomainVerifier:
    """Issue and check DNS TXT ownership proofs."""

    def __init__(self, resolver: dns.asyncresolver.Resolver | None = None) -> None:
        settings = get_settings()
        self.secret = settings.aegis_secret_key
        self.prefix = settings.verification_txt_prefix
        self.resolver = resolver or dns.asyncresolver.Resolver()

    def record_value(self, domain: str) -> str:
        return build_txt_value(normalize_domain(domain), self.secret, self.prefix)

    async def verify(self, domain: str) -> bool:
        """Return True when the expected TXT record is published."""
        domain = normalize_domain(domain)
        expected = self.record_value(domain)
        try:
            answers = await self.resolver.resolve(domain, "TXT")
        except (dns.exception.DNSException, Exception) as exc:
            logger.debug("Verification TXT lookup failed for %s: %s", domain, exc)
            return False
        for answer in answers:
            value = "".join(part.decode() if isinstance(part, bytes) else str(part) for part in answer.strings)
            if value.strip() == expected:
                return True
        return False

    async def verify_or_raise(self, domain: str) -> None:
        if not await self.verify(domain):
            raise DomainNotVerifiedError(domain)
