"""Security utilities: SSRF protection, private IP blocking, domain validation."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from urllib.parse import urlparse

import httpx

from aegis.core.exceptions import SecurityViolationError

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

BLOCKED_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "169.254.169.254",
    "metadata",
    "instance-data",
}

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def normalize_domain(domain: str) -> str:
    """Normalize and validate a domain name."""
    domain = domain.strip().lower()
    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.hostname or domain
    domain = domain.split("/")[0].rstrip(".")
    if not DOMAIN_REGEX.match(domain):
        raise ValueError(f"Invalid domain format: {domain}")
    if domain in BLOCKED_HOSTS or domain.endswith(".localhost") or domain == "localhost":
        raise SecurityViolationError(f"Domain is blocked for security reasons: {domain}")
    return domain


def is_private_or_blocked_ip(ip_str: str) -> bool:
    """Return True if the IP belongs to a private, reserved, or blocked range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    # ``is_global`` also catches IPv4-mapped IPv6 addresses such as
    # ::ffff:127.0.0.1, which would otherwise evade an IPv4-only denylist.
    if not ip.is_global:
        return True
    return any(ip in network for network in BLOCKED_NETWORKS)


def resolve_and_validate(domain: str) -> list[str]:
    """
    Resolve domain to A/AAAA records and ensure none point to private/blocked ranges.
    Returns list of validated public IP strings.
    Raises SecurityViolationError on any blocked destination.
    """
    domain = normalize_domain(domain)
    try:
        results = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for {domain}: {exc}") from exc

    public_ips: list[str] = []
    for family, _, _, _, sockaddr in results:
        ip = sockaddr[0]
        if is_private_or_blocked_ip(ip):
            raise SecurityViolationError(
                f"Resolved address {ip} for {domain} is in a blocked/private range. "
                "SSRF protection triggered."
            )
        public_ips.append(ip)

    if not public_ips:
        raise ValueError(f"No public IP addresses resolved for {domain}")
    return list(dict.fromkeys(public_ips))


def validate_redirect_target(original_domain: str, redirect_url: str) -> str:
    """
    Ensure a redirect stays within the authorized domain scope.
    Returns the normalized hostname of the redirect target.
    """
    parsed = urlparse(redirect_url)
    if parsed.scheme not in ("http", "https"):
        raise SecurityViolationError(f"Redirect uses a disallowed scheme: {parsed.scheme}")
    target_host = parsed.hostname
    if not target_host:
        raise SecurityViolationError("Redirect target has no hostname")
    target_host = target_host.lower().rstrip(".")
    try:
        original = normalize_domain(original_domain)
        normalized_target = normalize_domain(target_host)
    except ValueError as exc:
        raise SecurityViolationError(f"Invalid redirect target: {target_host}") from exc

    if normalized_target == original or normalized_target.endswith("." + original):
        resolve_and_validate(normalized_target)
        return normalized_target

    raise SecurityViolationError(
        f"Redirect to {target_host} escapes authorized scope of {original}"
    )


def is_safe_url_for_scan(url: str, authorized_domain: str) -> bool:
    """Quick check that a URL is safe to request under the authorized domain."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False
        host = normalize_domain(host)
        auth = normalize_domain(authorized_domain)
        return host == auth or host.endswith("." + auth)
    except (ValueError, SecurityViolationError):
        return False


class SSRFProtectedTransport(httpx.AsyncHTTPTransport):
    """Connect only to an IP that was just validated for the requested hostname.

    This closes the DNS-rebinding gap between validation and connection: httpx
    would otherwise resolve the hostname a second time on its own.
    """

    def __init__(self, *args: object, cache_seconds: float = 10.0, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._cache_seconds = cache_seconds
        self._cache: dict[str, tuple[float, list[str]]] = {}

    async def _validated_ip(self, host: str) -> str:
        now = time.monotonic()
        cached = self._cache.get(host)
        if cached and now - cached[0] < self._cache_seconds:
            return cached[1][0]
        ips = await asyncio.to_thread(resolve_and_validate, host)
        self._cache[host] = (now, ips)
        return ips[0]

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise SecurityViolationError(f"Direct requests to IP addresses are blocked: {host}")

            ip = await self._validated_ip(host)
            extensions = dict(request.extensions)
            # httpcore expects a str here; it is used for SNI *and* certificate
            # hostname verification against the original domain, not the IP.
            extensions["sni_hostname"] = host
            pinned = httpx.Request(
                request.method,
                request.url.copy_with(host=ip),
                headers=request.headers,
                stream=request.stream,
                extensions=extensions,
            )
            return await super().handle_async_request(pinned)
        return await super().handle_async_request(request)
