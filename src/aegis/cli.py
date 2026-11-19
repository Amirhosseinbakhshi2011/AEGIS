"""AEGIS command-line interface."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aegis import __version__
from aegis.core.config import get_settings
from aegis.core.exceptions import AegisError
from aegis.core.logging import setup_logging
from aegis.core.models import ScanProfile
from aegis.core.security import normalize_domain
from aegis.reports.generator import ReportGenerator
from aegis.scanner.engine import ScanEngine

app = typer.Typer(
    name="aegis",
    help="AEGIS — AI-Powered Cybersecurity Intelligence Platform",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _run(coro):
    return asyncio.run(coro)


@app.command()
def version() -> None:
    """Show AEGIS version."""
    console.print(f"AEGIS v{__version__}")


@app.command("domain")
def domain_check(
    domain: str = typer.Argument(..., help="Domain to inspect"),
) -> None:
    """Quick domain intelligence check (DNS, SPF, DMARC)."""
    setup_logging()
    from aegis.domains.intelligence import DomainIntelligence

    async def _go():
        try:
            d = normalize_domain(domain)
        except ValueError as e:
            console.print(f"[red]Invalid domain:[/red] {e}")
            raise typer.Exit(2)
        intel = DomainIntelligence()
        info, findings = await intel.analyze(d)
        console.print(Panel(f"[bold]Domain Intelligence[/bold] — {info.normalized}"))
        table = Table(show_header=True)
        table.add_column("Record")
        table.add_column("Value")
        table.add_row("A", ", ".join(info.a_records) or "—")
        table.add_row("AAAA", ", ".join(info.aaaa_records) or "—")
        table.add_row("NS", ", ".join(info.ns_records) or "—")
        table.add_row("MX", ", ".join(info.mx_records) or "—")
        if info.spf:
            table.add_row("SPF", info.spf.get("raw", "—"))
        if info.dmarc:
            table.add_row("DMARC", info.dmarc.get("raw", "—"))
        table.add_row("DNSSEC", str(info.dnssec_enabled))
        console.print(table)
        if findings:
            console.print(f"\n[yellow]{len(findings)} configuration finding(s):[/yellow]")
            for f in findings:
                console.print(f"  • [{f.severity.value}] {f.title}")

    _run(_go())


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Authorized domain to assess"),
    profile: str = typer.Option("safe", help="Scan profile: safe | standard"),
    authorize: bool = typer.Option(
        False,
        "--authorize",
        help="Explicit confirmation that you are authorized to scan this domain",
    ),
    verified: bool = typer.Option(
        False,
        "--verified",
        help="Confirm domain ownership has been verified (DNS TXT or equivalent)",
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write full JSON result"),
) -> None:
    """
    Run a safe security assessment against an authorized domain.

    You MUST pass --authorize and, when required by policy, --verified.
    """
    setup_logging()
    settings = get_settings()

    if not authorize:
        console.print(
            "[red]Authorization required.[/red] "
            "Re-run with --authorize to confirm you own or have explicit written permission "
            "to assess this domain."
        )
        raise typer.Exit(3)

    if settings.require_domain_verification and not verified:
        console.print(
            "[red]Domain verification required.[/red] "
            "Complete ownership verification (e.g. DNS TXT record) and pass --verified."
        )
        raise typer.Exit(3)

    try:
        prof = ScanProfile(profile.lower())
    except ValueError:
        console.print(f"[red]Unknown profile:[/red] {profile}")
        raise typer.Exit(2)

    engine = ScanEngine()

    async def _go():
        console.print(f"[bold]Starting AEGIS scan[/bold] of [cyan]{domain}[/cyan] (profile={prof.value})")
        result = await engine.run_scan(
            domain,
            profile=prof,
            authorized=True,
            verified=verified or not settings.require_domain_verification,
        )
        return result

    try:
        result = _run(_go())
    except AegisError as e:
        console.print(f"[red]{e.message}[/red]")
        raise typer.Exit(1)

    style = "green" if (result.risk_score or 0) >= 70 else "yellow" if (result.risk_score or 0) >= 40 else "red"
    console.print(
        Panel(
            f"Status: [bold]{result.status.value}[/bold]\n"
            f"Findings: {len(result.findings)}\n"
            f"Posture score: [{style}]{result.risk_score}/100[/{style}]\n"
            f"Scan ID: {result.scan_id}",
            title="Scan Complete",
        )
    )

    if result.findings:
        table = Table(title="Findings")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Check")
        for f in sorted(
            result.findings,
            key=lambda x: ["critical", "high", "medium", "low", "informational"].index(x.severity.value),
        ):
            table.add_row(f.severity.value, f.title, f.check_id)
        console.print(table)

    if output:
        output.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"Full result written to {output}")

    if result.status.value == "failed":
        raise typer.Exit(1)


@app.command("report")
def report_generate(
    scan_file: Path = typer.Argument(..., help="Path to scan result JSON"),
    format: str = typer.Option("markdown", "--format", "-f", help="markdown | json | html"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Generate a professional report from a previous scan result JSON."""
    setup_logging()
    if not scan_file.exists():
        console.print(f"[red]File not found:[/red] {scan_file}")
        raise typer.Exit(2)

    from aegis.core.models import ScanResult

    data = json.loads(scan_file.read_text(encoding="utf-8"))
    result = ScanResult.model_validate(data)
    gen = ReportGenerator()

    async def _go():
        return await gen.generate(result, fmt=format)

    content = _run(_go())
    if output:
        output.write_text(content, encoding="utf-8")
        console.print(f"Report written to {output}")
    else:
        console.print(content)


@app.command("config")
def config_show() -> None:
    """Show effective configuration (secrets redacted)."""
    settings = get_settings()
    data = settings.model_dump()
    for key in list(data.keys()):
        if any(s in key.lower() for s in ("secret", "key", "password", "token")):
            if data[key]:
                data[key] = "***REDACTED***"
    console.print_json(data=data)


if __name__ == "__main__":
    app()
