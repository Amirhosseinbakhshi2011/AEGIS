"""SQLAlchemy models for persisted scan records."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scan_records"

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target_domain: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32))
    profile: Mapped[str] = mapped_column(String(32))
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now()
    )
