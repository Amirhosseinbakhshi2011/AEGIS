"""Tests for report generation."""

from __future__ import annotations

import json

from aegis.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    ScanResult,
    ScanStatus,
    Severity,
)
from aegis.reports.generator import ReportGenerator


def _result() -> ScanResult:
    return ScanResult(
        target_domain="example.com",
        status=ScanStatus.COMPLETED,
        risk_score=64.0,
        findings=[
            Finding(
                title="Missing HSTS header",
                description="The response has no Strict-Transport-Security header.",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=FindingCategory.HEADERS,
                remediation="Add an HSTS header.",
                check_id="headers.missing.strict-transport-security",
            )
        ],
    )


async def test_json_report_round_trips():
    content = await ReportGenerator().generate(_result(), fmt="json")
    parsed = json.loads(content)
    assert parsed["target_domain"] == "example.com"
    assert ScanResult.model_validate(parsed).risk_score == 64.0


async def test_markdown_report_contains_finding_and_score():
    content = await ReportGenerator().generate(_result(), fmt="markdown")
    assert "example.com" in content
    assert "Missing HSTS header" in content
    assert "64.0" in content
    assert "Prioritized Action Plan" in content


async def test_markdown_report_without_ai_section():
    content = await ReportGenerator().generate(_result(), fmt="markdown", include_ai=False)
    assert "Prioritized Action Plan" not in content
    assert "Missing HSTS header" in content


async def test_html_report_is_well_formed():
    content = await ReportGenerator().generate(_result(), fmt="html")
    assert content.startswith("<!DOCTYPE html>")
    assert "AEGIS Report — example.com" in content
    assert "Missing HSTS header" in content
