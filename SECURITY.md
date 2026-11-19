# Security Policy

## Authorized Use Only

AEGIS is a defensive security assessment platform. It must only be used against domains and systems you own or for which you have explicit written authorization.

Unauthorized scanning may violate computer misuse laws.

## Reporting a Vulnerability

If you discover a security issue in AEGIS itself, do not open a public issue. Contact the maintainer privately.

## Design Principles

- Explicit authorization required before any scan
- Domain ownership verification supported
- SSRF protection blocks private and cloud-metadata destinations
- Redirects constrained to authorized scope
- Non-destructive checks only
- Secrets in environment variables only
