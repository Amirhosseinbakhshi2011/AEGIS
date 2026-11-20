# AEGIS

**See threats before they become incidents.**

AEGIS is an open-source, AI-assisted cybersecurity intelligence platform that performs authorized, non-destructive security assessments of websites and domains. It collects domain intelligence, inspects TLS and HTTP security configuration, scores risk transparently, and produces professional reports.

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

---

## Why AEGIS exists

Most free scanners either produce noisy results, require sending targets to third-party SaaS, or focus on offensive exploitation. AEGIS aims for authorized-only, evidence-based, locally controllable, and explainable assessments. Every finding includes the check that produced it, the evidence observed, a confidence level, and concrete remediation guidance.

## What it does

| Module | Capability |
|--------|------------|
| **Domain Intelligence** | DNS records (A/AAAA/MX/NS/TXT/CAA/SOA), SPF, DMARC, DNSSEC indicators |
| **Web Security Scanner** | HTTPS/TLS availability, certificate expiry, security headers, cookie attributes |
| **Risk Engine** | Transparent 0–100 posture score with severity × confidence weighting |
| **AI Analyst** | Deterministic local explanations + optional external provider interface |
| **Reporting** | Markdown, HTML, and JSON reports |
| **CLI & API** | Typer CLI; FastAPI under `/api/v1` |

All active checks are **non-destructive**. No exploitation, credential attacks, or denial-of-service testing is performed.

## Security & authorization model

1. Explicit authorization required before any scan.
2. Domain verification supported (DNS TXT ownership proof).
3. SSRF protection blocks private, loopback, link-local, and cloud-metadata ranges.
4. Redirects constrained to authorized domain scope.
5. Request budgets, timeouts, and concurrency limits enforced.

See SECURITY.md for the full policy.

## Quick start

```bash
git clone https://github.com/Amirhosseinbakhshi2011/AEGIS.git
cd AEGIS
./install.sh          # macOS / Linux
```

On Windows, run `install.bat` (CMD) or `.\install.ps1` (PowerShell).

Each installer creates `.venv`, installs the project with dev dependencies, and
copies `.env.example` to `.env` if needed. To do it manually instead:

```bash
python -m venv .venv
source .venv/bin/activate          # .venv\Scripts\activate.bat on Windows
pip install -e ".[dev]"
cp .env.example .env
```

### CLI

```bash
aegis --help
aegis version
aegis verify example.com
aegis verify example.com --check
aegis domain example.com
aegis scan example.com --authorize --verified --profile safe -o result.json
aegis report result.json --format markdown -o report.md
aegis config
```

For the full command, API, configuration, and exit-code reference, see [docs/COMMANDS.md](docs/COMMANDS.md).

**Important:** The `--authorize` flag confirms you are allowed to assess the target. Do not scan systems you do not own or lack permission for.

### API

```bash
uvicorn aegis.api.main:app --reload --port 8000
```

Open http://localhost:8000/docs

Scans are queued in Celery (set `REDIS_URL`) and return `202` with a `scan_id`; poll `GET /api/v1/scans/{scan_id}` for the result. If Redis is unavailable, the API falls back to in-process execution. Set `API_KEY` to require the `X-API-Key` header.

### Docker

```bash
docker compose up --build
```

## Risk score methodology

Start at 100. Each finding deducts severity_weight × confidence_multiplier.
Weights: Critical 35 · High 20 · Medium 10 · Low 4 · Informational 1.
Confidence: High 1.0 · Medium 0.7 · Low 0.4.
This is an AEGIS-specific posture indicator, fully auditable from the report.

## Testing

```bash
pytest -q
ruff check src tests
```

## Project status

AEGIS v0.1 focuses on solid authorization/SSRF foundations, domain intelligence, core web checks, transparent risk scoring, reports, CLI and REST API.

Not yet complete: full multi-user auth (shared API key only), broad CVE correlation, PDF export, production dashboard UI.

## License

MIT — see LICENSE.