"""Tests for SSRF protection and domain validation."""

from __future__ import annotations

import pytest

from aegis.core.exceptions import SecurityViolationError
from aegis.core.security import (
    is_private_or_blocked_ip,
    normalize_domain,
    resolve_and_validate,
)


def test_normalize_domain_basic():
    assert normalize_domain("Example.COM") == "example.com"
    assert normalize_domain("https://example.com/path") == "example.com"
    assert normalize_domain("example.com.") == "example.com"


def test_normalize_domain_rejects_localhost():
    # localhost fails domain format regex; *.localhost is caught by explicit block list
    with pytest.raises((SecurityViolationError, ValueError)):
        normalize_domain("localhost")
    with pytest.raises(SecurityViolationError):
        normalize_domain("foo.localhost")


def test_normalize_domain_invalid():
    with pytest.raises(ValueError):
        normalize_domain("not a domain")
    with pytest.raises(ValueError):
        normalize_domain("")


def test_private_ip_detection():
    assert is_private_or_blocked_ip("127.0.0.1") is True
    assert is_private_or_blocked_ip("10.0.0.5") is True
    assert is_private_or_blocked_ip("192.168.1.1") is True
    assert is_private_or_blocked_ip("169.254.169.254") is True
    assert is_private_or_blocked_ip("8.8.8.8") is False
    assert is_private_or_blocked_ip("1.1.1.1") is False


def test_resolve_blocks_private(monkeypatch):
    """Simulate resolution to a private IP and expect SecurityViolationError."""
    import socket

    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(SecurityViolationError):
        resolve_and_validate("evil.example")
