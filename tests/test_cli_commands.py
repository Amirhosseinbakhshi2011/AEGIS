"""Tests for CLI commands."""

from __future__ import annotations

from typer.testing import CliRunner

from aegis.cli import app
from aegis.core.models import DomainInfo

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "AEGIS v0.1.0" in result.output


def test_config_command_redacts_secrets():
    result = runner.invoke(app, ["config"])
    assert result.exit_code == 0
    assert "aegis_secret_key" in result.output
    assert "***REDACTED***" in result.output


def test_domain_command_uses_intelligence(monkeypatch):
    class FakeIntel:
        async def analyze(self, domain: str):
            return DomainInfo(domain=domain, normalized=domain, a_records=["93.184.215.14"]), []

    monkeypatch.setattr("aegis.domains.intelligence.DomainIntelligence", FakeIntel)
    result = runner.invoke(app, ["domain", "example.com"])
    assert result.exit_code == 0
    assert "example.com" in result.output
    assert "93.184.215.14" in result.output


def test_verify_command_prints_txt_value(monkeypatch):
    class FakeVerifier:
        def record_value(self, domain: str) -> str:
            return "aegis-verification=abc123"

        async def verify(self, domain: str) -> bool:
            return True

    monkeypatch.setattr("aegis.cli.DomainVerifier", FakeVerifier)
    result = runner.invoke(app, ["verify", "example.com"])
    assert result.exit_code == 0
    assert "aegis-verification=abc123" in result.output


def test_verify_check_command_reports_failure(monkeypatch):
    class FakeVerifier:
        def record_value(self, domain: str) -> str:
            return "aegis-verification=abc123"

        async def verify(self, domain: str) -> bool:
            return False

    monkeypatch.setattr("aegis.cli.DomainVerifier", FakeVerifier)
    result = runner.invoke(app, ["verify", "example.com", "--check"])
    assert result.exit_code == 1
    assert "Not verified" in result.output
