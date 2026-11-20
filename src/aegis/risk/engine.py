"""Transparent risk scoring engine.

Score ranges from 0 (critical posture) to 100 (excellent).
Every deduction is tied to concrete findings with severity and confidence weights.
"""

from __future__ import annotations

from typing import Any

from aegis.core.models import Confidence, Finding, Severity

SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 35.0,
    Severity.HIGH: 20.0,
    Severity.MEDIUM: 10.0,
    Severity.LOW: 4.0,
    Severity.INFORMATIONAL: 1.0,
}

CONFIDENCE_MULTIPLIER: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.7,
    Confidence.LOW: 0.4,
}


class RiskEngine:
    """Calculate an explainable security posture score."""

    def score(self, findings: list[Finding]) -> tuple[float, dict[str, Any]]:
        """
        Returns (score 0-100, summary dict).
        Higher score = better (safer) posture.
        """
        if not findings:
            return 100.0, {
                "base": 100.0,
                "deductions": [],
                "final_score": 100.0,
                "methodology": (
                    "Start at 100. Subtract weighted severity × confidence for each finding. "
                    "Floor at 0. Informational findings have minimal impact."
                ),
            }

        deductions: list[dict[str, Any]] = []
        total_deduction = 0.0
        seen: dict[str, int] = {}
        max_per_check = 3

        for f in findings:
            count = seen.get(f.check_id, 0) + 1
            seen[f.check_id] = count
            capped = count > max_per_check
            weight = SEVERITY_WEIGHT.get(f.severity, 5.0)
            mult = CONFIDENCE_MULTIPLIER.get(f.confidence, 0.5)
            amount = 0.0 if capped else weight * mult
            total_deduction += amount
            deductions.append(
                {
                    "finding_id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "deduction": round(amount, 2),
                    "capped": capped,
                }
            )

        score = max(0.0, 100.0 - total_deduction)
        score = round(score, 1)

        summary = {
            "base": 100.0,
            "total_deduction": round(total_deduction, 2),
            "final_score": score,
            "finding_count": len(findings),
            "max_findings_per_check": max_per_check,
            "by_severity": self._count_by_severity(findings),
            "deductions": deductions[:50],
            "methodology": (
                "Score starts at 100. Each finding deducts "
                "(severity_weight × confidence_multiplier). "
                "Critical=35, High=20, Medium=10, Low=4, Info=1. "
                "Confidence: high=1.0, medium=0.7, low=0.4. "
                "At most 3 findings per check_id are deducted to avoid score saturation. "
                "This is an AEGIS-specific posture indicator, not an industry standard score."
            ),
        }
        return score, summary

    def _count_by_severity(self, findings: list[Finding]) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] += 1
        return counts
