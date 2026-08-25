"""Application use cases for Argus.

This layer coordinates authorization and passive-recon domain services without
depending on Typer, console output, or concrete network clients.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from olympus.argus.ct import CertificateTransparencyClient
from olympus.argus.dns_records import RECORD_TYPES, DnsRecordReport, resolve_records
from olympus.argus.email_osint import (
    EmailIntel,
    analyze_email,
    build_email_asset,
    build_email_findings,
    enrich_email,
)
from olympus.argus.fronting import FrontingReport, assess_fronting
from olympus.argus.recon import DomainRecon, scan_domain
from olympus.argus.resolver import DnsResolver
from olympus.argus.scope import enforce_scope
from olympus.argus.web import (
    WebIntel,
    WebReconError,
    build_web_asset,
    build_web_findings,
    fetch_web,
    host_of,
)
from olympus.argus.whois import WhoisReport, lookup_domain
from olympus.core.http import HttpClient


class AuthorizationRequiredError(PermissionError):
    """Raised when a privacy-sensitive use case lacks explicit authorization."""


@dataclass(frozen=True)
class DomainScanRequest:
    """Validated command-independent input for one scoped domain scan."""

    domain: str
    scope_path: Path
    audit_log_path: Path


@dataclass(frozen=True)
class DomainScanService:
    """Authorize and execute passive domain reconnaissance."""

    resolver: DnsResolver
    ct_client: CertificateTransparencyClient

    def run(self, request: DomainScanRequest) -> DomainRecon:
        """Enforce scope before invoking either network-capable dependency."""
        enforce_scope(request.domain, request.scope_path, request.audit_log_path)
        return scan_domain(request.domain, self.resolver, self.ct_client)


@dataclass(frozen=True)
class EmailAnalysisRequest:
    """Command-independent input for offline analysis and optional enrichment."""

    address: str
    enrich: bool = False
    authorized: bool = False
    scope_path: Path | None = None
    audit_log_path: Path | None = None


@dataclass(frozen=True)
class EmailAnalysisService:
    """Analyze email locally and safely coordinate opt-in network enrichment."""

    resolver: DnsResolver
    http: HttpClient

    def run(self, request: EmailAnalysisRequest) -> EmailIntel:
        """Build shared contracts, authorizing scope before network access."""
        report = analyze_email(request.address)
        enrichment = None
        if request.enrich:
            if not request.authorized:
                raise AuthorizationRequiredError(
                    "email enrichment requires explicit documented authorization"
                )
            if request.scope_path is None or request.audit_log_path is None:
                raise ValueError("scope_path and audit_log_path are required for email enrichment")
            enforce_scope(report.domain, request.scope_path, request.audit_log_path)
            enrichment = enrich_email(report, self.resolver, self.http)
        asset = build_email_asset(report, enrichment)
        return EmailIntel(
            report=report,
            asset=asset,
            enrichment=enrichment,
            findings=build_email_findings(asset.asset_id, report, enrichment),
        )


@dataclass(frozen=True)
class FrontingAssessmentRequest:
    """Command-independent input for one scoped fronting assessment."""

    domain: str
    scope_path: Path
    audit_log_path: Path
    max_subdomains: int = 50


@dataclass(frozen=True)
class FrontingAssessmentService:
    """Authorize and coordinate passive CDN/WAF fronting assessment."""

    resolver: DnsResolver
    ct_client: CertificateTransparencyClient

    def run(self, request: FrontingAssessmentRequest) -> FrontingReport:
        """Validate policy and scope before invoking network-capable ports."""
        if request.max_subdomains < 0:
            raise ValueError("max_subdomains must be zero or greater")
        enforce_scope(request.domain, request.scope_path, request.audit_log_path)
        return assess_fronting(
            request.domain,
            self.resolver,
            self.ct_client,
            max_subdomains=request.max_subdomains,
        )


@dataclass(frozen=True)
class DnsLookupRequest:
    """Command-independent input for one scoped DNS record lookup."""

    domain: str
    scope_path: Path
    audit_log_path: Path
    record_types: tuple[str, ...] = RECORD_TYPES


@dataclass(frozen=True)
class DnsLookupService:
    """Authorize and execute DNS-over-HTTPS record enumeration."""

    http: HttpClient

    def run(self, request: DnsLookupRequest) -> DnsRecordReport:
        """Enforce scope before invoking the injected network transport."""
        if not request.record_types:
            raise ValueError("record_types must contain at least one DNS record type")
        record_types = tuple(record_type.strip().upper() for record_type in request.record_types)
        if any(not record_type for record_type in record_types):
            raise ValueError("record_types cannot contain empty values")
        enforce_scope(request.domain, request.scope_path, request.audit_log_path)
        return resolve_records(request.domain, self.http, record_types)


@dataclass(frozen=True)
class WhoisLookupRequest:
    """Command-independent input for one scoped RDAP lookup."""

    domain: str
    scope_path: Path
    audit_log_path: Path


@dataclass(frozen=True)
class WhoisLookupService:
    """Authorize and execute domain-registration intelligence via RDAP."""

    http: HttpClient

    def run(self, request: WhoisLookupRequest) -> WhoisReport:
        """Enforce scope before invoking the injected network transport."""
        enforce_scope(request.domain, request.scope_path, request.audit_log_path)
        return lookup_domain(request.domain, self.http)


class InvalidWebTargetError(ValueError):
    """Raised when a web target cannot be normalized to a scoped hostname."""


def authorize_web_url(url: str, scope_path: Path, audit_log_path: Path) -> None:
    """Validate and authorize a web URL, including redirect destinations."""
    try:
        host = host_of(url)
    except WebReconError as exc:
        raise InvalidWebTargetError(str(exc)) from exc
    enforce_scope(host, scope_path, audit_log_path)


@dataclass(frozen=True)
class WebReconRequest:
    """Command-independent input for one scoped passive HTTP assessment."""

    url: str
    scope_path: Path
    audit_log_path: Path


@dataclass(frozen=True)
class WebReconService:
    """Authorize, fetch, and map passive HTTP posture to shared contracts."""

    http: HttpClient

    def run(self, request: WebReconRequest) -> WebIntel:
        """Validate and authorize the host before invoking HTTP."""
        authorize_web_url(request.url, request.scope_path, request.audit_log_path)
        report = fetch_web(request.url, self.http)
        asset = build_web_asset(report)
        return WebIntel(
            report=report,
            asset=asset,
            findings=build_web_findings(asset.asset_id, report),
        )
