"""Configuration tests."""

from __future__ import annotations

from aegis.core.config import Settings, get_settings


def test_settings_defaults():
    s = Settings(
        aegis_secret_key="x" * 32,
        _env_file=None,  # type: ignore[call-arg]
    )
    assert s.aegis_env == "development"
    assert s.max_concurrent_scans == 3
    assert s.require_domain_verification is True


def test_get_settings_cached():
    a = get_settings()
    b = get_settings()
    assert a is b
