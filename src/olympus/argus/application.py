"""Application use cases for Argus.

This layer coordinates authorization and passive-recon domain services without
depending on Typer, console output, or concrete network clients.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from olympus.argus.ct import CertificateTransparencyClient
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
