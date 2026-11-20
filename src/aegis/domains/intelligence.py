"""Domain intelligence: DNS records, SPF, DMARC, DNSSEC indicators."""

from __future__ import annotations

from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype

from aegis.core.config import get_settings
from aegis.core.logging import get_logger
from aegis.core.models import Confidence, DomainInfo, Finding, FindingCategory, Severity
from aegis.core.security import normalize_domain

logger = get_logger(__name__)


class DomainIntelligence:
    """Collect and analyze public DNS configuration for a domain."""

    def __init__(self, timeout: float = 5.0) -> None:
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    async def collect(self, domain: str) -> DomainInfo:
        domain = normalize_domain(domain)
        info = DomainInfo(domain=domain, normalized=domain)

        info.a_records = await self._query(domain, "A")
        info.aaaa_records = await self._query(domain, "AAAA")
        info.mx_records = await self._query_mx(domain)
        info.ns_records = await self._query(domain, "NS")
        info.txt_records = await self._query(domain, "TXT")
        info.caa_records = await self._query(domain, "CAA")
        info.soa = await self._query_soa(domain)
        info.dnssec_enabled = await self._check_dnssec(domain)
        info.dkim_selectors = await self._check_dkim(domain)
        info.spf = self._parse_spf(info.txt_records)
        info.dmarc = await self._parse_dmarc(domain)

        return info

    async def analyze(self, domain: str) -> tuple[DomainInfo, list[Finding]]:
        """Collect domain info and produce findings for weak configurations."""
        info = await self.collect(domain)
        findings: list[Finding] = []

        if info.spf is None:
            findings.append(
                Finding(
                    title="No SPF record found",
                    description=(
                        "The domain has no SPF (Sender Policy Framework) TXT record. "
                        "This allows attackers to more easily spoof email from this domain."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.EMAIL_AUTH,
                    evidence={"txt_records": info.txt_records},
                    remediation=(
                        "Publish an SPF record, e.g. 'v=spf1 include:_spf.example.com ~all'. "
                        "Start with a soft-fail (~all) and move to hard-fail (-all) after validation."
                    ),
                    references=["https://datatracker.ietf.org/doc/html/rfc7208"],
                    check_id="dns.spf.missing",
                )
            )
        elif info.spf.get("all_mechanism") == "+all":
            findings.append(
                Finding(
                    title="SPF record uses +all (permits any sender)",
                    description=(
                        "The SPF record ends with '+all', which effectively allows any host "
                        "to send mail as this domain. This defeats the purpose of SPF."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.EMAIL_AUTH,
                    evidence={"spf": info.spf},
                    remediation="Change the final mechanism to '~all' or '-all'.",
                    check_id="dns.spf.permissive",
                )
            )

        spf_records = [record for record in info.txt_records if record.lower().startswith("v=spf1")]
        if len(spf_records) > 1:
            findings.append(
                Finding(
                    title="Multiple SPF records found",
                    description=(
                        "The domain publishes more than one SPF TXT record. SPF permits "
                        "only one record per domain, so evaluation is undefined."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.EMAIL_AUTH,
                    evidence={"spf_records": spf_records},
                    remediation="Merge all SPF mechanisms into a single TXT record.",
                    references=["https://datatracker.ietf.org/doc/html/rfc7208"],
                    check_id="dns.spf.multiple",
                )
            )

        if info.dmarc is None:
            findings.append(
                Finding(
                    title="No DMARC policy found",
                    description=(
                        "No DMARC record was found at _dmarc.<domain>. "
                        "Without DMARC, receiving servers cannot apply a consistent policy "
                        "for messages that fail SPF/DKIM alignment."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.EMAIL_AUTH,
                    evidence={},
                    remediation=(
                        "Publish a DMARC record starting with 'v=DMARC1; p=none; rua=mailto:dmarc@yourdomain' "
                        "to monitor, then move to quarantine or reject."
                    ),
                    references=["https://datatracker.ietf.org/doc/html/rfc7489"],
                    check_id="dns.dmarc.missing",
                )
            )
        else:
            if "p" not in info.dmarc:
                findings.append(
                    Finding(
                        title="DMARC record has no policy tag",
                        description="The DMARC TXT record is missing the required 'p=' policy tag.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.EMAIL_AUTH,
                        evidence={"dmarc": info.dmarc},
                        remediation="Add a policy such as 'p=none', 'p=quarantine' or 'p=reject'.",
                        references=["https://datatracker.ietf.org/doc/html/rfc7489"],
                        check_id="dns.dmarc.no_policy",
                    )
                )
            policy = info.dmarc.get("p", "none")
            if policy == "none":
                findings.append(
                    Finding(
                        title="DMARC policy is set to 'none'",
                        description=(
                            "DMARC is in monitoring mode only (p=none). "
                            "No enforcement is applied to failing messages."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.EMAIL_AUTH,
                        evidence={"dmarc": info.dmarc},
                        remediation="After reviewing aggregate reports, set p=quarantine or p=reject.",
                        check_id="dns.dmarc.none",
                    )
                )

        if not info.dkim_selectors:
            findings.append(
                Finding(
                    title="No DKIM record found for common selectors",
                    description=(
                        "None of the configured common DKIM selectors publish a key. "
                        "A custom selector may still be in use; verify manually."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    category=FindingCategory.EMAIL_AUTH,
                    evidence={"selectors_checked": get_settings().dkim_selectors},
                    remediation="Publish a DKIM key or confirm the selector your mail provider uses.",
                    references=["https://datatracker.ietf.org/doc/html/rfc6376"],
                    check_id="dns.dkim.missing",
                )
            )

        if not info.caa_records:
            findings.append(
                Finding(
                    title="No CAA records published",
                    description=(
                        "Certificate Authority Authorization (CAA) records are not present. "
                        "CAA allows domain owners to restrict which CAs may issue certificates."
                    ),
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.DNS,
                    evidence={},
                    remediation="Consider publishing CAA records to limit certificate issuance.",
                    references=["https://datatracker.ietf.org/doc/html/rfc8659"],
                    check_id="dns.caa.missing",
                )
            )

        if not info.a_records and not info.aaaa_records:
            findings.append(
                Finding(
                    title="No A or AAAA records",
                    description="The domain does not resolve to any IPv4 or IPv6 address.",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.DNS,
                    evidence={},
                    check_id="dns.no_address",
                )
            )

        return info, findings

    async def _query(self, domain: str, rdtype: str) -> list[str]:
        try:
            answers = await self.resolver.resolve(domain, rdtype)
            return [str(r).strip('"') for r in answers]
        except (dns.exception.DNSException, Exception) as exc:
            logger.debug("DNS %s query failed for %s: %s", rdtype, domain, exc)
            return []

    async def _query_mx(self, domain: str) -> list[str]:
        try:
            answers = await self.resolver.resolve(domain, "MX")
            return [f"{r.preference} {r.exchange}" for r in answers]
        except Exception:
            return []

    async def _query_soa(self, domain: str) -> dict[str, Any] | None:
        try:
            answers = await self.resolver.resolve(domain, "SOA")
            if answers:
                r = answers[0]
                return {
                    "mname": str(r.mname),
                    "rname": str(r.rname),
                    "serial": r.serial,
                    "refresh": r.refresh,
                    "retry": r.retry,
                    "expire": r.expire,
                    "minimum": r.minimum,
                }
        except Exception as exc:
            logger.debug("SOA query failed for %s: %s", domain, exc)
        return None

    async def _check_dnssec(self, domain: str) -> bool | None:
        """Best-effort DNSSEC presence check via DS/DNSKEY."""
        try:
            await self.resolver.resolve(domain, "DNSKEY")
            return True
        except dns.resolver.NoAnswer:
            return False
        except Exception:
            return None

    async def _check_dkim(self, domain: str) -> list[str]:
        """Check a small set of well-known DKIM selectors."""
        found: list[str] = []
        for selector in get_settings().dkim_selectors:
            records = await self._query(f"{selector}._domainkey.{domain}", "TXT")
            if any(record.replace(" ", "").lower().startswith("v=dkim1") for record in records):
                found.append(selector)
        return found

    def _parse_spf(self, txt_records: list[str]) -> dict[str, Any] | None:
        for rec in txt_records:
            if rec.lower().startswith("v=spf1"):
                mechanisms = rec.split()
                all_mech = None
                for m in mechanisms:
                    if m in ("+all", "-all", "~all", "?all"):
                        all_mech = m
                        break
                return {"raw": rec, "all_mechanism": all_mech, "mechanisms": mechanisms}
        return None

    async def _parse_dmarc(self, domain: str) -> dict[str, Any] | None:
        dmarc_domain = f"_dmarc.{domain}"
        records = await self._query(dmarc_domain, "TXT")
        for rec in records:
            if rec.upper().startswith("V=DMARC1"):
                tags: dict[str, str] = {}
                for part in rec.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        tags[k.strip().lower()] = v.strip()
                return {"raw": rec, **tags}
        return None
