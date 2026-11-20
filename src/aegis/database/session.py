"""Async database engine and session management."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

from aegis.core.config import get_settings
from aegis.database.models import Base

_engine: AsyncEngine | None = None
_initialized = False


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        url = get_settings().database_url
        options: dict[str, object] = {}
        if url.startswith("sqlite"):
            options["connect_args"] = {"check_same_thread": False}
        _engine = create_async_engine(url, **options)
    return _engine


async def init_db() -> None:
    """Create tables if they do not exist."""
    global _initialized
    async with get_engine().begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    _initialized = True


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    if not _initialized:
        await init_db()
    async with AsyncSession(get_engine(), expire_on_commit=False) as session:
        yield session
