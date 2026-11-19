"""Central configuration for AEGIS using pydantic-settings."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Application
    aegis_env: Literal["development", "staging", "production"] = "development"
    aegis_debug: bool = False
    aegis_secret_key: str = Field(
        default="dev-secret-change-in-production-min-32-chars",
        min_length=32,
    )
    aegis_api_prefix: str = "/api/v1"

    # Database
    database_url: str = "sqlite+aiosqlite:///./aegis.db"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Auth
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    access_token_expire_minutes: int = 30

    # Scan safety limits
    max_concurrent_scans: int = 3
    scan_timeout_seconds: int = 120
    max_requests_per_scan: int = 50
    request_timeout_seconds: float = 10.0
    rate_limit_per_minute: int = 30

    # Domain verification
    require_domain_verification: bool = True
    verification_txt_prefix: str = "aegis-verification="

    # AI (optional)
    ai_provider: str = ""
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    anthropic_api_key: str = ""

    # Logging
    log_level: str = "INFO"
    log_format: Literal["json", "text"] = "json"

    # CORS
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000", "http://localhost:8000"])

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v: object) -> list[str]:
        if isinstance(v, str):
            import json

            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [item.strip() for item in v.split(",") if item.strip()]
        if isinstance(v, list):
            return v
        return ["http://localhost:3000"]

    @property
    def is_production(self) -> bool:
        return self.aegis_env == "production"

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
