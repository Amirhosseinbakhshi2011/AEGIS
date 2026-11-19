"""AI-assisted security analyst with deterministic local fallback."""

from __future__ import annotations

from typing import Any, Protocol

from aegis.core.config import get_settings
from aegis.core.logging import get_logger
from aegis.core.models import Finding, ScanResult, Severity

logger = get_logger(__name__)


class AIProvider(Protocol):
    async def analyze(self, prompt: str, context: dict[str, Any]) -> str: ...


class LocalFallbackAnalyst:
    """Deterministic, rule-based explanations when no external AI is configured."""

    def generate_executive_summary(self, result: ScanResult) -> str:
        counts = result.finding_counts
        score = result.risk_score if result.risk_score is not None else 0.0
        critical = counts.get("critical", 0)
        high = counts.get("high", 0)

        parts = [
            f"Security assessment of {result.target_domain} completed with posture score {score}/100."
        ]
        if critical:
            parts.append(
                f"There are {critical} critical finding(s) that require immediate attention."
            )
        if high:
            parts.append(f"{high} high-severity issue(s) should be prioritized next.")
        if not critical and not high:
            parts.append(
                "No critical or high-severity issues were identified by the current safe checks."
            )
        parts.append(
            "All findings are evidence-based. Review each item and its remediation guidance. "
            "This assessment uses passive and non-destructive checks only."
        )
        return " ".join(parts)

    def explain_finding(self, finding: Finding) -> str:
        base = f"{finding.title}. {finding.description}"
        if finding.remediation:
            base += f" Recommended action: {finding.remediation}"
        if finding.confidence == "low":
            base += " (Note: confidence in this finding is low; verify manually.)"
        return base

    def prioritized_actions(self, result: ScanResult) -> list[str]:
        order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]
        actions: list[str] = []
        for sev in order:
            for f in result.findings:
                if f.severity == sev and f.remediation:
                    actions.append(f"[{sev.value.upper()}] {f.title}: {f.remediation}")
        return actions[:15]


class AISecurityAnalyst:
    """Provider-independent analyst. Uses local fallback when no API key is set."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.local = LocalFallbackAnalyst()
        self._external: AIProvider | None = None

    async def executive_summary(self, result: ScanResult) -> str:
        if not self.settings.ai_provider:
            return self.local.generate_executive_summary(result)
        logger.info("External AI provider configured but local summary used for safety in this version")
        return self.local.generate_executive_summary(result)

    async def explain(self, finding: Finding) -> str:
        return self.local.explain_finding(finding)

    async def action_plan(self, result: ScanResult) -> list[str]:
        return self.local.prioritized_actions(result)
