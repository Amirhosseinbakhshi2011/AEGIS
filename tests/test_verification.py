"""Tests for DNS TXT domain ownership verification."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aegis.core.exceptions import DomainNotVerifiedError
from aegis.core.verification import DomainVerifier, build_txt_value, generate_token
from aegis.scanner.engine import ScanEngine


class FakeResolver:
    def __init__(self, records: list[str]) -> None:
        self.records = records

    async def resolve(self, domain: str, rdtype: str):
        return [SimpleNamespace(strings=[value.encode()]) for value in self.records]


def test_token_is_stable_and_domain_specific():
    assert generate_token("example.com", "secret") == generate_token("EXAMPLE.COM", "secret")
    assert generate_token("example.com", "secret") != generate_token("other.com", "secret")
    assert len(generate_token("example.com", "secret")) == 32


def test_txt_value_uses_configured_prefix():
    value = build_txt_value("example.com", "secret", "aegis-verification=")
    assert value.startswith("aegis-verification=")
    assert value == f"aegis-verification={generate_token('example.com', 'secret')}"


async def test_verification_succeeds_when_record_published():
    verifier = DomainVerifier()
    expected = verifier.record_value("example.com")
    verifier.resolver = FakeResolver([expected])
    assert await verifier.verify("example.com") is True


async def test_verification_fails_when_record_missing():
    verifier = DomainVerifier()
    verifier.resolver = FakeResolver(["v=spf1 -all"])
    assert await verifier.verify("example.com") is False


async def test_engine_requires_real_proof_when_verified_flag_set():
    verifier = DomainVerifier()
    verifier.resolver = FakeResolver([])
    engine = ScanEngine(verifier=verifier)
    with pytest.raises(DomainNotVerifiedError):
        await engine.run_scan("example.com", authorized=True, verified=True)
