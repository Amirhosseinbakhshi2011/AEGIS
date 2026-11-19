"""Risk engine tests."""

from __future__ import annotations

from aegis.core.models import Confidence, Finding, FindingCategory, Severity
from aegis.risk.engine import RiskEngine


def test_empty_findings_score_100():
    engine = RiskEngine()
    score, summary = engine.score([])
    assert score == 100.0
    assert summary["final_score"] == 100.0


def test_critical_finding_lowers_score():
    engine = RiskEngine()
    findings = [
        Finding(
            title="Expired cert",
            description="test",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.TLS,
            check_id="tls.cert_expired",
        )
    ]
    score, summary = engine.score(findings)
    assert score < 70
    assert summary["finding_count"] == 1
    assert summary["deductions"][0]["deduction"] == 35.0


def test_informational_has_small_impact():
    engine = RiskEngine()
    findings = [
        Finding(
            title="Info",
            description="test",
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.OTHER,
            check_id="test",
        )
    ]
    score, _ = engine.score(findings)
    assert score == 99.0
