.PHONY: install test lint run

install:
	pip install -e ".[dev]"

test:
	pytest -q --tb=short

lint:
	ruff check src tests

run:
	uvicorn aegis.api.main:app --reload --host 0.0.0.0 --port 8000
