# Contributing to AEGIS

Thanks for your interest in improving AEGIS.

## Development Setup

```bash
git clone https://github.com/Amirhosseinbakhshi2011/AEGIS.git
cd AEGIS
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest -q
```

## Code Style

- Python 3.12+
- Type hints on public functions
- Ruff for linting
- Keep modules focused and independently testable

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Add tests for new behavior
4. Ensure tests pass
5. Open a PR with a clear description of the change

## Security Contributions

Improvements to SSRF protection, authorization flows, and safe-scanning guarantees are especially welcome. Please read SECURITY.md first.
