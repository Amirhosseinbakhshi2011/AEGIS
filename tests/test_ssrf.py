"""Regression tests for SSRF, redirect and DNS-rebinding protections."""

from __future__ import annotations

import socket

import httpx
import pytest
import respx

from aegis.checks._http import safe_get
from aegis.core.exceptions import SecurityViolationError
from aegis.core.security import (
    SSRFProtectedTransport,
    is_private_or_blocked_ip,
    is_safe_url_for_scan,
    validate_redirect_target,
)


def test_ipv4_mapped_ipv6_is_blocked():
    assert is_private_or_blocked_ip("::ffff:127.0.0.1") is True
    assert is_private_or_blocked_ip("::ffff:169.254.169.254") is True
    assert is_private_or_blocked_ip("2001:4860:4860::8888") is False


def test_public_ipv6_is_allowed():
    assert is_private_or_blocked_ip("2001:4860:4860::8888") is False


def test_redirect_to_external_host_is_blocked(monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(SecurityViolationError):
        validate_redirect_target("example.com", "https://evil.com/steal")


def test_redirect_to_subdomain_is_allowed(monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert validate_redirect_target("example.com", "https://www.example.com/") == "www.example.com"


def test_redirect_to_metadata_ip_is_blocked():
    with pytest.raises(SecurityViolationError):
        validate_redirect_target("example.com", "http://169.254.169.254/latest/meta-data/")


def test_is_safe_url_for_scan_rejects_other_domains():
    assert is_safe_url_for_scan("https://example.com/a", "example.com") is True
    assert is_safe_url_for_scan("https://api.example.com/a", "example.com") is True
    assert is_safe_url_for_scan("https://evil.com/a", "example.com") is False
    assert is_safe_url_for_scan("file:///etc/passwd", "example.com") is False


@respx.mock
async def test_safe_get_blocks_external_redirect():
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(302, headers={"Location": "https://evil.com/"})
    )
    async with httpx.AsyncClient() as client:
        with pytest.raises(SecurityViolationError):
            await safe_get(client, "https://example.com/", "example.com")


@respx.mock
async def test_safe_get_counts_requests(monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(302, headers={"Location": "https://www.example.com/"})
    )
    respx.get("https://www.example.com/").mock(return_value=httpx.Response(200))
    context: dict = {"request_count": 0}
    async with httpx.AsyncClient() as client:
        await safe_get(client, "https://example.com/", "example.com", context=context)
    assert context["request_count"] == 2


async def test_transport_rejects_ip_literal():
    async with httpx.AsyncClient(transport=SSRFProtectedTransport()) as client:
        with pytest.raises(SecurityViolationError):
            await client.get("http://127.0.0.1/")
