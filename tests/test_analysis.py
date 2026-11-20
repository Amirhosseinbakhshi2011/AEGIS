"""Tests for improved DNS and header analysis."""

from __future__ import annotations

import httpx
import respx

from aegis.checks.headers import SecurityHeadersCheck
from aegis.core.models import Confidence, Finding, FindingCategory, Severity
from aegis.domains.intelligence import DomainIntelligence
from aegis.risk.engine import RiskEngine


class FakeResolver:
    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self.records = records

    async def resolve(self, domain: str, rdtype: str):
        return self.records.get((domain, rdtype), [])


def _intel(records: dict[tuple[str, str], list[str]]) -> DomainIntelligence:
    intel = DomainIntelligence()
    intel.resolver = FakeResolver(records)
    return intel


async def test_multiple_spf_records_are_detected():
    records = {("example.com", "TXT"): ["v=spf1 -all", "v=spf1 include:other.com ~all"]}
    _, findings = await _intel(records).analyze("example.com")
    assert any(f.check_id == "dns.spf.multiple" for f in findings)


async def test_dmarc_without_policy_tag_is_flagged():
    records = {("_dmarc.example.com", "TXT"): ["v=DMARC1; rua=mailto:dmarc@example.com"]}
    _, findings = await _intel(records).analyze("example.com")
    assert any(f.check_id == "dns.dmarc.no_policy" for f in findings)


async def test_missing_dkim_selectors_are_flagged():
    _, findings = await _intel({}).analyze("example.com")
    assert any(f.check_id == "dns.dkim.missing" for f in findings)


def test_risk_score_caps_duplicate_checks():
    findings = [
        Finding(
            title=f"Duplicate {index}",
            description="test",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=FindingCategory.OTHER,
            check_id="same.check",
        )
        for index in range(5)
    ]
    score, summary = RiskEngine().score(findings)
    assert score == 70.0
    assert [deduction["capped"] for deduction in summary["deductions"]] == [
        False,
        False,
        False,
        True,
        True,
    ]


@respx.mock
async def test_csp_frame_ancestors_suppresses_x_frame_options_finding():
    headers = {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
    }
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, headers=headers))
    async with httpx.AsyncClient() as client:
        findings = await SecurityHeadersCheck().run(client, "https://example.com/", "example.com")
    assert not any(f.check_id == "headers.missing.x-frame-options" for f in findings)
