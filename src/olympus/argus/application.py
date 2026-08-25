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
from olympus.argus.enrichment import (
    EnrichmentError,
    MessagingPresence,
    MessagingPresenceClient,
    PhoneEnrichment,
    PhoneEnrichmentClient,
)
from olympus.argus.fronting import FrontingReport, assess_fronting
from olympus.argus.mac import (
    MacIntel,
    analyze_mac,
    build_mac_asset,
    build_mac_findings,
    lookup_vendor,
)
from olympus.argus.mac_scope import enforce_mac_scope
from olympus.argus.myip import MyIpResult, build_result, discover_public_ip
from olympus.argus.phone import (
    PhoneIntel,
    PhoneParseError,
    analyze_phone,
    build_phone_asset,
    build_phone_findings,
)
from olympus.argus.phone_scope import PhoneOutOfScopeError, enforce_phone_scope
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
class MacAnalysisRequest:
    """Command-independent input for offline MAC analysis and OUI enrichment."""

    address: str
    vendor: bool = False
    authorized: bool = False
    scope_path: Path | None = None
    audit_log_path: Path | None = None


@dataclass(frozen=True)
class MacAnalysisService:
    """Analyze a MAC locally and safely coordinate opt-in vendor lookup."""

    http: HttpClient

    def run(self, request: MacAnalysisRequest) -> MacIntel:
        """Authorize OUI scope before sending it to the third-party registry."""
        report = analyze_mac(request.address)
        vendor_name = None
        if request.vendor:
            if not request.authorized:
                raise AuthorizationRequiredError(
                    "MAC vendor lookup requires explicit documented authorization"
                )
            if request.scope_path is None or request.audit_log_path is None:
                raise ValueError("scope_path and audit_log_path are required for vendor lookup")
            enforce_mac_scope(report.mac, request.scope_path, request.audit_log_path)
            vendor_name = lookup_vendor(report, self.http)
        asset = build_mac_asset(report, vendor_name)
        return MacIntel(
            report=report,
            asset=asset,
            vendor=vendor_name,
            findings=build_mac_findings(asset.asset_id, report),
        )


@dataclass(frozen=True)
class MyIpDiscoveryRequest:
    """Command-independent options for public-IP discovery."""

    geolocate: bool = False


@dataclass(frozen=True)
class MyIpDiscoveryService:
    """Discover self egress and optionally enrich it through a separate port."""

    discovery_http: HttpClient
    geo_http: HttpClient

    def run(self, request: MyIpDiscoveryRequest) -> MyIpResult:
        """Keep provider and optional geolocation traffic independently injectable."""
        public_ip = discover_public_ip(self.discovery_http)
        return build_result(public_ip, self.geo_http if request.geolocate else None)


@dataclass(frozen=True)
class PhoneProfileRequest:
    """Command-independent input for one scoped phone profile."""

    number: str
    scope_path: Path
    audit_log_path: Path
    region: str | None = None
    enrich: bool = False
    breach: bool = False
    messaging: bool = False
    authorized: bool = False


@dataclass(frozen=True)
class PhoneProfileOutcome:
    """One phone profile plus non-fatal adapter availability warnings."""

    intel: PhoneIntel
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class PhoneBatchProfileResult:
    """Batch result with successful profiles and explicit skipped-target warnings."""

    intels: tuple[PhoneIntel, ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class PhoneProfileService:
    """Authorize, scope, enrich, and map phone intelligence without Typer."""

    carrier_client: PhoneEnrichmentClient | None = None
    breach_client: PhoneEnrichmentClient | None = None
    messaging_client: MessagingPresenceClient | None = None

    @staticmethod
    def _require_authorization(request: PhoneProfileRequest) -> None:
        if (request.enrich or request.breach or request.messaging) and not request.authorized:
            raise AuthorizationRequiredError(
                "phone enrichment requires explicit documented authorization"
            )

    def run(self, request: PhoneProfileRequest) -> PhoneProfileOutcome:
        """Profile one number, refusing unauthorized/out-of-scope network activity."""
        self._require_authorization(request)
        report = analyze_phone(request.number, request.region)
        enforce_phone_scope(
            report.e164 or request.number, request.scope_path, request.audit_log_path
        )

        warnings: list[str] = []
        carrier_result: PhoneEnrichment | None = None
        breach_result: PhoneEnrichment | None = None
        messaging_result: MessagingPresence | None = None
        if report.e164 is not None:
            if request.enrich:
                if self.carrier_client is None:
                    warnings.append("--enrich skipped (set OLYMPUS_NUMVERIFY_KEY to enable)")
                else:
                    try:
                        carrier_result = self.carrier_client.enrich(report.e164)
                    except EnrichmentError:
                        warnings.append("carrier enrichment failed (third-party service error)")
            if request.breach:
                if self.breach_client is None:
                    warnings.append("--breach skipped (breach adapter unavailable)")
                else:
                    try:
                        breach_result = self.breach_client.enrich(report.e164)
                    except EnrichmentError:
                        warnings.append("breach lookup failed (third-party service error)")
            if request.messaging:
                if self.messaging_client is None:
                    warnings.append("--messaging skipped (set OLYMPUS_RAPIDAPI_KEY to enable)")
                else:
                    try:
                        messaging_result = self.messaging_client.lookup(report.e164)
                    except EnrichmentError:
                        warnings.append("messaging lookup failed (third-party service error)")

        enrichment_result = self._merge_enrichment(carrier_result, breach_result)
        asset = build_phone_asset(report, enrichment_result, messaging_result)
        intel = PhoneIntel(
            report=report,
            asset=asset,
            enrichment=enrichment_result,
            messaging=messaging_result,
            findings=build_phone_findings(
                asset.asset_id, report, enrichment_result, messaging_result
            ),
        )
        return PhoneProfileOutcome(intel=intel, warnings=tuple(warnings))

    def run_many(self, requests: tuple[PhoneProfileRequest, ...]) -> PhoneBatchProfileResult:
        """Profile a batch, recording parse/scope skips while preserving fatal scope errors."""
        intels: list[PhoneIntel] = []
        warnings: list[str] = []
        for request in requests:
            try:
                outcome = self.run(request)
            except PhoneParseError:
                warnings.append(f"skipping unparseable number {request.number!r}")
            except PhoneOutOfScopeError:
                warnings.append(f"skipping out-of-scope number {request.number!r} (logged)")
            else:
                intels.append(outcome.intel)
                warnings.extend(outcome.warnings)
        return PhoneBatchProfileResult(intels=tuple(intels), warnings=tuple(warnings))

    @staticmethod
    def _merge_enrichment(
        carrier: PhoneEnrichment | None,
        breach: PhoneEnrichment | None,
    ) -> PhoneEnrichment | None:
        if carrier is None and breach is None:
            return None
        return PhoneEnrichment(
            carrier=carrier.carrier if carrier is not None else "",
            line_type=carrier.line_type if carrier is not None else "",
            breach_count=breach.breach_count if breach is not None else 0,
            breach_sources=breach.breach_sources if breach is not None else (),
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
