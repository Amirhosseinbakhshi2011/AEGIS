# AEGIS Command Reference

Complete reference for the AEGIS CLI, REST API, configuration, and exit codes.

> Version: 0.1.0 · Requires Python 3.12+

---

## Contents

- [Getting started](#getting-started)
- [CLI conventions](#cli-conventions)
- [`aegis version`](#aegis-version)
- [`aegis verify`](#aegis-verify)
- [`aegis domain`](#aegis-domain)
- [`aegis scan`](#aegis-scan)
- [`aegis report`](#aegis-report)
- [`aegis config`](#aegis-config)
- [Scan profiles](#scan-profiles)
- [Authorization and verification](#authorization-and-verification)
- [REST API](#rest-api)
- [Configuration reference](#configuration-reference)
- [Exit codes](#exit-codes)
- [Troubleshooting](#troubleshooting)

---

## Getting started

From the repository root:

```cmd
.venv\Scripts\activate.bat        # Windows CMD
.venv\Scripts\Activate.ps1        # Windows PowerShell
source .venv/bin/activate         # macOS / Linux
```

Install (one time):

```bash
pip install -e ".[dev]"
```

Copy the environment template and adjust it:

```bash
cp .env.example .env
```

Verify the install:

```bash
aegis --help
aegis version
```

> Note: `python -m aegis` is **not** supported in this version (there is no `aegis/__main__.py`). Use the `aegis` executable created by `pip install -e .`.

---

## CLI conventions

- Get top-level help with `aegis --help` or `aegis -h`.
- Get command help with `aegis <command> --help`, e.g. `aegis scan --help`.
- Running `aegis` with no arguments prints the help and exits.
- Commands and options are lowercase; values such as profile names are case-insensitive where noted.
- All commands that produce a file use `-o` / `--output` for the destination path.

Top-level commands:

| Command | Purpose |
|---------|---------|
| `version` | Print the AEGIS version. |
| `verify` | Issue or check a DNS TXT domain ownership proof. |
| `domain` | Quick DNS / email-authentication intelligence for a domain. |
| `scan` | Run a safe, non-destructive assessment of an authorized domain. |
| `report` | Render a saved scan result as Markdown, HTML, or JSON. |
| `config` | Print effective configuration with secrets redacted. |

---

## `aegis version`

Print the installed AEGIS version. No arguments or options.

**Synopsis**

```text
aegis version
```

**Example**

```text
$ aegis version
AEGIS v0.1.0
```

---

## `aegis verify`

Issue or check a DNS TXT ownership proof. Required before `scan --verified`
when `REQUIRE_DOMAIN_VERIFICATION=true` (the default).

**Synopsis**

```text
aegis verify <domain> [--check]
```

Running without `--check` prints the exact TXT value to publish on the domain.
With `--check`, AEGIS queries DNS and confirms the value is live.

**Examples**

```bash
aegis verify example.com
aegis verify example.com --check
```

**Exit codes:** `0` verified/issued, `1` not verified, `2` invalid domain.

---

## `aegis domain`

Perform a quick, passive domain intelligence check: DNS records (A, AAAA, NS, MX), SPF, DMARC, DNSSEC indicator, and basic configuration findings. This command does **not** perform an active web scan and does not require authorization flags.

**Synopsis**

```text
aegis domain <domain>
```

> The domain is a direct positional argument. There is no `check` subcommand: use `aegis domain example.com`, **not** `aegis domain check example.com`.

**Arguments**

| Argument | Required | Description |
|----------|:--------:|-------------|
| `<domain>` | yes | Domain to inspect, e.g. `example.com`. A URL, scheme, port, or path is normalized/rejected by the security layer. |

**Example**

```text
$ aegis domain example.com
+---------------------------+
| Domain Intelligence — example.com |
+---------------------------+
| Record | Value            |
| A      | 93.184.215.14    |
| NS     | ...              |
+---------------------------+
4 configuration finding(s):
  • [low] No SPF record found
```

**Exit codes:** `0` success, `2` invalid domain.

---

## `aegis scan`

Run a full, safe assessment: domain intelligence, TLS/certificate checks, security-header checks, cookie-attribute checks, and transparent risk scoring. All checks are non-destructive — no exploitation, credential attacks, or denial-of-service testing.

**Synopsis**

```text
aegis scan <domain> [--profile safe|standard] [--authorize] [--verified] [--output PATH]
```

**Arguments**

| Argument | Required | Description |
|----------|:--------:|-------------|
| `<domain>` | yes | Authorized domain to assess. |

**Options**

| Option | Default | Description |
|--------|---------|-------------|
| `--profile TEXT` | `safe` | Scan profile: `safe` or `standard` (case-insensitive). |
| `--authorize` | off | Mandatory confirmation that you own the domain or hold explicit written permission. |
| `--verified` | off | Mandatory when `REQUIRE_DOMAIN_VERIFICATION=true` (the default). AEGIS checks the live DNS TXT proof issued by `aegis verify`. |
| `--output`, `-o PATH` | none | Write the complete result as JSON to this path. |

**Examples**

```bash
# Publish the proof first (see aegis verify), then run a full scan
aegis verify example.com
aegis verify example.com --check
aegis scan example.com --authorize --verified --profile safe -o result.json

# If domain verification is disabled in .env
aegis scan example.com --authorize
```

**Authorization gates**

1. Without `--authorize`, the command exits with code `3`.
2. With `REQUIRE_DOMAIN_VERIFICATION=true` (default) and no `--verified`, it exits with code `3`.
3. With `--verified`, the DNS TXT proof must actually resolve; otherwise the scan is refused.
4. An unknown profile exits with code `2` (validated by Typer before execution).

The command prints a summary panel (status, finding count, posture score, scan ID) and a table of findings. If `--output` is given, the full `ScanResult` JSON is written to that file — this is the input for `aegis report`.

**Exit codes:** `0` completed, `1` scan failed, `2` invalid profile, `3` authorization/verification missing.

---

## `aegis report`

Generate a professional report from a saved scan-result JSON file.

**Synopsis**

```text
aegis report <scan_file> [--format markdown|json|html] [--output PATH] [--ai|--no-ai]
```

**Arguments**

| Argument | Required | Description |
|----------|:--------:|-------------|
| `<scan_file>` | yes | Path to a JSON file produced by `aegis scan -o`. |

**Options**

| Option | Default | Description |
|--------|---------|-------------|
| `--format`, `-f TEXT` | `markdown` | Output format: `markdown`, `html`, or `json`. |
| `--output`, `-o PATH` | none | Write to file; if omitted, print to stdout. |
| `--ai` / `--no-ai` | `--ai` | Include the generated summary and action plan in Markdown/HTML reports. |

**Examples**

```bash
aegis report result.json --format markdown -o report.md
aegis report result.json --format html -o report.html
aegis report result.json --format json -o pretty.json
aegis report result.json                       # print Markdown to terminal
```

**Exit codes:** `0` success, `2` file not found or invalid input.

---

## `aegis config`

Print the effective configuration with secret-like values redacted (`secret`, `key`, `password`, `token` fields). Helpful for confirming which `.env` values are active.

**Synopsis**

```text
aegis config
```

> `config` takes no subcommand: use `aegis config`, **not** `aegis config show`.

**Example output**

```json
{
  "aegis_env": "development",
  "aegis_debug": true,
  "aegis_secret_key": "***REDACTED***",
  "aegis_api_prefix": "/api/v1",
  "require_domain_verification": true,
  "cors_origins": ["http://localhost:3000", "http://localhost:8000"]
}
```

**Exit codes:** `0` success.

---

## Scan profiles

Defined in `aegis.core.models.ScanProfile`.

| Profile | Behavior |
|---------|----------|
| `safe` | Default. Non-destructive checks only: DNS/email-auth intelligence, TLS certificate inspection, security headers, cookie attributes. |
| `standard` | Same check set in v0.1; reserved for expanded checks in later releases. |

Safety limits are enforced regardless of profile (see [Configuration reference](#configuration-reference)): request budget, timeouts, redirect policy, and SSRF blocking of private/loopback/link-local/cloud-metadata ranges.

---

## Authorization and verification

AEGIS is an authorized-only tool. Before scanning you must:

1. Own the target or hold explicit written permission (`--authorize`).
2. Prove ownership when verification is enabled (`REQUIRE_DOMAIN_VERIFICATION=true` by default) by publishing a DNS TXT record using the configured prefix, then pass `--verified`.
   - Default prefix: `aegis-verification=`
3. Respect scope. The scanner blocks non-public addresses and constrains redirects to the authorized domain.

Only scan systems you are permitted to assess.

---

## REST API

Start the server:

```bash
uvicorn aegis.api.main:app --reload --port 8000
```

Interactive docs: <http://localhost:8000/docs> · ReDoc: <http://localhost:8000/redoc>

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness; returns `status` and `version`. |
| `GET` | `/api/v1/health` | Versioned health endpoint. |
| `POST` | `/api/v1/scans` | Queue a scan. Body: `ScanRequest`. Returns `202` with `scan_id`, `status`, `message`. |
| `GET` | `/api/v1/scans` | List recently stored scan results. |
| `GET` | `/api/v1/scans/{scan_id}` | Fetch a scan result (memory first, then database). |
| `POST` | `/api/v1/scans/{scan_id}/cancel` | Revoke/cancel a running scan. |

`ScanRequest` body:

```json
{
  "domain": "example.com",
  "profile": "safe",
  "authorized": true,
  "verified": false
}
```

- `authorized` must be `true` or the API returns `403`.
- `verified` must be `true` when domain verification is required; the live DNS TXT proof is checked before queuing (`403` otherwise).
- Security policy violations and other errors return `400`.
- Scan endpoints require the `X-API-Key` header when `API_KEY` is configured (`401` otherwise).
- Scan endpoints are rate limited per client (`429` when exceeded).
- The API prefix is configurable via `AEGIS_API_PREFIX`.
- Scans run in a Celery worker when Redis is reachable; otherwise they run in-process. Poll `GET /api/v1/scans/{scan_id}` for completion.

Example:

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key-if-configured" \
  -d '{"domain":"example.com","profile":"safe","authorized":true,"verified":true}'
```

---

## Configuration reference

Settings are read from environment variables or a `.env` file in the working directory. Run `aegis config` to see the currently effective values.

| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_ENV` | `development` | `development`, `staging`, or `production`. |
| `AEGIS_DEBUG` | `false` | Debug mode. |
| `AEGIS_SECRET_KEY` | dev placeholder | App secret (min 32 chars). Change in production. |
| `AEGIS_API_PREFIX` | `/api/v1` | Prefix for versioned API routes. |
| `API_KEY` | empty | Optional shared key for scan endpoints (`X-API-Key` header). |
| `DATABASE_URL` | `sqlite+aiosqlite:///./aegis.db` | SQLAlchemy database URL. |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL (used by Celery). |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm. |
| `JWT_EXPIRE_MINUTES` | `60` | JWT lifetime. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access-token lifetime. |
| `MAX_CONCURRENT_SCANS` | `3` | Concurrency cap. |
| `SCAN_TIMEOUT_SECONDS` | `120` | Overall scan timeout. |
| `MAX_REQUESTS_PER_SCAN` | `50` | Hard request budget per scan. |
| `REQUEST_TIMEOUT_SECONDS` | `10` | Per-request HTTP timeout. |
| `RATE_LIMIT_PER_MINUTE` | `30` | Rate-limit setting. |
| `REQUIRE_DOMAIN_VERIFICATION` | `true` | Require `--verified` / `verified=true`. |
| `VERIFICATION_TXT_PREFIX` | `aegis-verification=` | Required DNS TXT prefix for ownership proof. |
| `DKIM_SELECTORS` | `["selector1","selector2","google","default"]` | Selectors checked for DKIM keys. |
| `AI_PROVIDER` | empty | Optional external provider: `openai` or `anthropic`. |
| `OPENAI_API_KEY` | empty | OpenAI key (optional). |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model name. |
| `ANTHROPIC_API_KEY` | empty | Anthropic key (optional). |
| `LOG_LEVEL` | `INFO` | Logging level. |
| `LOG_FORMAT` | `json` | `json` or `text`. |
| `CORS_ORIGINS` | `["http://localhost:3000","http://localhost:8000"]` | Allowed CORS origins (JSON array or comma-separated). |

Notes:

- The `.env` file is loaded automatically from the current working directory.
- `aegis config` redacts fields containing `secret`, `key`, `password`, or `token`.
- In production, always set a strong `AEGIS_SECRET_KEY` and review CORS origins.

---

## Exit codes

| Code | Meaning |
|-----:|---------|
| `0` | Success / completed. |
| `1` | Scan failed (see error message or `error_message` in JSON). |
| `2` | Invalid input (bad domain, unknown profile, missing file). |
| `3` | Authorization or domain verification missing. |

API-only status codes: `401` missing/invalid API key, `403` authorization or verification failure, `429` rate limit exceeded, `202` scan accepted.

---

## Troubleshooting

**`aegis` is not recognized**
Activate the virtual environment first (`.venv\Scripts\activate.bat`), or reinstall with `pip install -e .`. Check with `pip show aegis`.

**`python -m aegis` does nothing useful**
Not supported in v0.1. Use the `aegis` command.

**`require_domain_verification` blocks my scan**
Run `aegis verify <domain>` to get the TXT value, publish it, confirm with `aegis verify <domain> --check`, then pass `--verified`. For local testing only, set `REQUIRE_DOMAIN_VERIFICATION=false` in `.env`.

**`No A or AAAA records` / empty DNS output**
Confirm the domain resolves and that outbound DNS works from your machine. Some networks block DNS or only allow public resolvers.

**API returns `403`**
Set `authorized: true` in the JSON body, publish the TXT proof, and set `verified: true`.

**API returns `401` or `429`**
Set the `X-API-Key` header when `API_KEY` is configured, and respect `RATE_LIMIT_PER_MINUTE`.

**Scans never finish via the API**
Check Redis/Celery. If the broker is unavailable the API logs a warning and runs the scan in-process; poll `GET /api/v1/scans/{scan_id}` for the result.

**Unicode/garbled characters in Windows console**
Set `chcp 65001` or use Windows Terminal with UTF-8. This is a terminal display issue, not a scan failure.

---

## See also

- [README.md](../README.md) — overview and quick start
- [SECURITY.md](../SECURITY.md) — authorization and security policy
- [CONTRIBUTING.md](../CONTRIBUTING.md) — development workflow
