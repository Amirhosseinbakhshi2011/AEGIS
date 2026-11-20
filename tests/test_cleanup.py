"""Tests for provider adapters and CLI input validation."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import respx
from typer.testing import CliRunner

from aegis.ai.analyst import AISecurityAnalyst
from aegis.ai.providers import AnthropicProvider, OpenAIProvider
from aegis.cli import app
from aegis.core.models import ScanResult

runner = CliRunner()


@respx.mock
async def test_openai_provider_parses_response():
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(
            200, json={"choices": [{"message": {"content": "A concise summary"}}]}
        )
    )
    provider = OpenAIProvider("key", "gpt-4o-mini")
    assert await provider.analyze("Summarize", {}) == "A concise summary"


@respx.mock
async def test_anthropic_provider_parses_response():
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(
            200, json={"content": [{"type": "text", "text": "Another summary"}]}
        )
    )
    provider = AnthropicProvider("key")
    assert await provider.analyze("Summarize", {}) == "Another summary"


async def test_analyst_uses_configured_provider(monkeypatch):
    settings = SimpleNamespace(
        ai_provider="openai",
        openai_api_key="key",
        openai_model="gpt-4o-mini",
        anthropic_api_key="",
    )
    monkeypatch.setattr("aegis.ai.analyst.get_settings", lambda: settings)
    analyst = AISecurityAnalyst()

    class FakeProvider:
        async def analyze(self, prompt: str, context: dict[str, object]) -> str:
            return "provider summary"

    analyst._external = FakeProvider()  # type: ignore[assignment]
    assert await analyst.executive_summary(ScanResult(target_domain="example.com")) == "provider summary"


async def test_analyst_falls_back_when_provider_fails(monkeypatch):
    settings = SimpleNamespace(
        ai_provider="openai",
        openai_api_key="key",
        openai_model="gpt-4o-mini",
        anthropic_api_key="",
    )
    monkeypatch.setattr("aegis.ai.analyst.get_settings", lambda: settings)
    analyst = AISecurityAnalyst()

    class BrokenProvider:
        async def analyze(self, prompt: str, context: dict[str, object]) -> str:
            raise RuntimeError("offline")

    analyst._external = BrokenProvider()  # type: ignore[assignment]
    summary = await analyst.executive_summary(ScanResult(target_domain="example.com"))
    assert "example.com" in summary


def test_cli_rejects_unknown_profile():
    result = runner.invoke(app, ["scan", "example.com", "--profile", "bogus"])
    assert result.exit_code == 2


def test_cli_rejects_unknown_report_format(tmp_path):
    scan_file = tmp_path / "result.json"
    scan_file.write_text("{}", encoding="utf-8")
    result = runner.invoke(app, ["report", str(scan_file), "--format", "xml"])
    assert result.exit_code == 2
