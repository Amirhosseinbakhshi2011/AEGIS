"""Professional security report generation (JSON, Markdown, HTML)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from aegis.ai.analyst import AISecurityAnalyst
from aegis.core.models import ScanResult


class ReportGenerator:
    def __init__(self) -> None:
        self.analyst = AISecurityAnalyst()

    async def generate(
        self,
        result: ScanResult,
        fmt: str = "markdown",
        *,
        include_ai: bool = True,
    ) -> str:
        fmt = fmt.lower()
        if fmt == "json":
            return self._json(result)
        if fmt == "html":
            return await self._html(result, include_ai=include_ai)
        return await self._markdown(result, include_ai=include_ai)

    def _json(self, result: ScanResult) -> str:
        return json.dumps(result.model_dump(mode="json"), indent=2, default=str)

    async def _markdown(self, result: ScanResult, *, include_ai: bool) -> str:
        lines: list[str] = []
        lines.append("# AEGIS Security Assessment Report")
        lines.append("")
        lines.append(f"**Target:** `{result.target_domain}`  ")
        lines.append(f"**Scan ID:** `{result.scan_id}`  ")
        lines.append(f"**Status:** {result.status.value}  ")
        lines.append(f"**Profile:** {result.profile.value}  ")
        if result.started_at:
            lines.append(f"**Started:** {result.started_at.isoformat()}  ")
        if result.finished_at:
            lines.append(f"**Finished:** {result.finished_at.isoformat()}  ")
        lines.append(f"**Generated:** {datetime.now(UTC).isoformat()}  ")
        lines.append("")

        lines.append("## Authorization & Scope")
        lines.append("")
        lines.append(
            "This assessment was performed only after explicit authorization for the target domain. "
            "AEGIS uses passive analysis and safe, non-destructive active checks. "
            "No exploitation, brute-force, or denial-of-service testing is performed."
        )
        lines.append("")

        lines.append("## Executive Summary")
        lines.append("")
        if include_ai:
            summary = await self.analyst.executive_summary(result)
            lines.append(summary)
        else:
            lines.append(
                f"Assessment completed with {len(result.findings)} findings. "
                f"Posture score: {result.risk_score}/100."
            )
        lines.append("")

        lines.append("## Overall Security Posture")
        lines.append("")
        score = result.risk_score if result.risk_score is not None else "N/A"
        lines.append(f"**Score:** {score} / 100  ")
        lines.append("")
        if result.risk_summary.get("methodology"):
            lines.append(f"*Methodology:* {result.risk_summary['methodology']}")
            lines.append("")

        counts = result.finding_counts
        lines.append("## Finding Statistics")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|------:|")
        for sev in ("critical", "high", "medium", "low", "informational"):
            lines.append(f"| {sev.capitalize()} | {counts.get(sev, 0)} |")
        lines.append("")

        for sev_label, sev_key in [
            ("Critical Findings", "critical"),
            ("High Findings", "high"),
            ("Medium Findings", "medium"),
            ("Low Findings", "low"),
            ("Informational Observations", "informational"),
        ]:
            group = [f for f in result.findings if f.severity.value == sev_key]
            if not group:
                continue
            lines.append(f"## {sev_label}")
            lines.append("")
            for f in group:
                lines.append(f"### {f.title}")
                lines.append("")
                lines.append(f"- **Severity:** {f.severity.value}")
                lines.append(f"- **Confidence:** {f.confidence.value}")
                lines.append(f"- **Category:** {f.category.value}")
                lines.append(f"- **Check:** `{f.check_id}`")
                if f.affected_url:
                    lines.append(f"- **URL:** {f.affected_url}")
                lines.append("")
                lines.append(f.description)
                lines.append("")
                if f.evidence:
                    lines.append("**Evidence:**")
                    lines.append("```json")
                    lines.append(json.dumps(f.evidence, indent=2, default=str)[:1500])
                    lines.append("```")
                    lines.append("")
                if f.remediation:
                    lines.append(f"**Remediation:** {f.remediation}")
                    lines.append("")
                if f.references:
                    lines.append("**References:**")
                    for ref in f.references:
                        lines.append(f"- {ref}")
                    lines.append("")

        if include_ai:
            actions = await self.analyst.action_plan(result)
            if actions:
                lines.append("## Prioritized Action Plan")
                lines.append("")
                for i, a in enumerate(actions, 1):
                    lines.append(f"{i}. {a}")
                lines.append("")

        if result.domain_info:
            di = result.domain_info
            lines.append("## Domain Intelligence Summary")
            lines.append("")
            lines.append(f"- **A records:** {', '.join(di.a_records) or 'none'}")
            lines.append(f"- **AAAA records:** {', '.join(di.aaaa_records) or 'none'}")
            lines.append(f"- **NS:** {', '.join(di.ns_records) or 'none'}")
            lines.append(f"- **MX:** {', '.join(di.mx_records) or 'none'}")
            if di.spf:
                lines.append(f"- **SPF:** `{di.spf.get('raw', '')}`")
            if di.dmarc:
                lines.append(f"- **DMARC:** `{di.dmarc.get('raw', '')}`")
            lines.append(f"- **DNSSEC indicated:** {di.dnssec_enabled}")
            lines.append("")

        lines.append("## Scan Limitations")
        lines.append("")
        lines.append(
            "- Only safe, non-destructive checks were performed.\n"
            "- No authentication to the target application was used.\n"
            "- Subdomain enumeration is limited to passive sources in this version.\n"
            "- Absence of a finding does not guarantee absence of a vulnerability.\n"
            "- Results depend on the state of the target at the time of the scan."
        )
        lines.append("")
        lines.append("## Disclaimer")
        lines.append("")
        lines.append(
            "This report is provided for defensive security purposes under authorized assessment only. "
            "AEGIS and its maintainers accept no liability for actions taken based on this report. "
            "Always validate findings in your own environment before making production changes."
        )
        lines.append("")
        lines.append("---")
        lines.append("*Generated by AEGIS — AI-Powered Cybersecurity Intelligence Platform*")
        lines.append("*Built and maintained by Amirhossein Bakhshi*")

        return "\n".join(lines)

    async def _html(self, result: ScanResult, *, include_ai: bool) -> str:
        md = await self._markdown(result, include_ai=include_ai)
        try:
            import markdown as md_lib

            body = md_lib.markdown(md, extensions=["tables", "fenced_code"])
        except ImportError:
            body = f"<pre>{md}</pre>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>AEGIS Report — {result.target_domain}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; color: #1a1a1a; }}
    h1, h2, h3 {{ color: #0f172a; }}
    code, pre {{ background: #f1f5f9; padding: 0.2em 0.4em; border-radius: 4px; }}
    pre {{ padding: 1rem; overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 0.5rem 0.75rem; text-align: left; }}
    th {{ background: #e2e8f0; }}
  </style>
</head>
<body>
{body}
</body>
</html>"""
