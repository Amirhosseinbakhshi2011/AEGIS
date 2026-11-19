"""Security utilities: SSRF protection, private IP blocking, domain validation."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

from aegis.core.exceptions import SecurityViolationError

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

BLOCKED_HOSTS = {
    "metadata.google.internal",
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
    for network in BLOCKED_NETWORKS:
        if ip in network:
            return True
    return False


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
    target_host = parsed.hostname
    if not target_host:
        raise SecurityViolationError("Redirect target has no hostname")
    target_host = target_host.lower().rstrip(".")
    original = normalize_domain(original_domain)

    if target_host == original or target_host.endswith("." + original):
        resolve_and_validate(target_host)
        return target_host

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
        host = host.lower().rstrip(".")
        auth = normalize_domain(authorized_domain)
        if host != auth and not host.endswith("." + auth):
            return False
        return True
    except Exception:
        return False
