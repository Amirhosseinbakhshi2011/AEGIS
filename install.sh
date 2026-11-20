#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "== AEGIS installer (bash) =="

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "[ERROR] python3 was not found on PATH." >&2
    exit 1
fi

if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
    echo "[ERROR] Python 3.12 or newer is required." >&2
    exit 1
fi
echo "Python $("$PY" --version)"

if [ ! -x ".venv/bin/python" ]; then
    echo "Creating virtual environment..."
    "$PY" -m venv .venv
fi

VENV_PY=".venv/bin/python"

echo "Upgrading pip..."
"$VENV_PY" -m pip install --upgrade pip

echo "Installing AEGIS and development dependencies..."
"$VENV_PY" -m pip install -e ".[dev]"

if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from .env.example"
else
    echo ".env already exists; leaving it unchanged."
fi

echo
echo "Done. Next steps:"
echo "  source .venv/bin/activate"
echo "  aegis --help"
