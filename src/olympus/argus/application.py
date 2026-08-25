"""Application use cases for Argus.

This layer coordinates authorization and passive-recon domain services without
depending on Typer, console output, or concrete network clients.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from olympus.argus.ct import CertificateTransparencyClient
from olympus.argus.fronting import FrontingReport, assess_fronting
from olympus.argus.recon import DomainRecon, scan_domain
from olympus.argus.resolver import DnsResolver
from olympus.argus.scope import enforce_scope


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
