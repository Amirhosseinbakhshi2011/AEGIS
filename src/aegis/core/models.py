"""Shared domain models and finding structures used across modules."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingCategory(str, Enum):
    TLS = "tls"
    HEADERS = "headers"
    COOKIES = "cookies"
    DNS = "dns"
    EMAIL_AUTH = "email_auth"
    MISCONFIGURATION = "misconfiguration"
    EXPOSURE = "exposure"
    BEHAVIOR = "behavior"
    VULNERABILITY = "vulnerability"
    OTHER = "other"


class Finding(BaseModel):
    """A single evidence-based security finding."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: FindingCategory
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    cwe_id: str | None = None
    cve_id: str | None = None
    affected_url: str | None = None
    check_id: str

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanProfile(str, Enum):
    SAFE = "safe"
    STANDARD = "standard"


class DomainInfo(BaseModel):
    """Normalized domain intelligence result."""

    domain: str
    normalized: str
    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    caa_records: list[str] = Field(default_factory=list)
    soa: dict[str, Any] | None = None
    dnssec_enabled: bool | None = None
    dkim_selectors: list[str] = Field(default_factory=list)
    spf: dict[str, Any] | None = None
    dmarc: dict[str, Any] | None = None
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanResult(BaseModel):
    """Complete result of a security assessment."""

    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    target_domain: str
    status: ScanStatus = ScanStatus.PENDING
    profile: ScanProfile = ScanProfile.SAFE
    started_at: datetime | None = None
    finished_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    domain_info: DomainInfo | None = None
    risk_score: float | None = None
    risk_summary: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None

    @property
    def finding_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
