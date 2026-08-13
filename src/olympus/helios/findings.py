"""Convert Helios recon results into the shared `olympus.core` contract.

Each scanned host becomes an Asset; each open port on it becomes a Finding
attached to that asset, so downstream modules (Vulcan, Apollo) consume the
same objects regardless of which tool produced them.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
from pathlib import Path

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.helios.recon import HostRecon

# Ports considered high-risk when exposed (used to set Finding severity).
HIGH_RISK_PORTS: frozenset[int] = frozenset({21, 23, 445, 3389})

_PORT_SERVICE_NAMES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    8080: "http-alt",
    8443: "https-alt",
}


def _service_name(port: int) -> str:
    """Return the well-known service name for ``port``, or ``"unknown"``."""
    return _PORT_SERVICE_NAMES.get(port, "unknown")


def _severity_for_port(port: int) -> Severity:
    """Return HIGH for well-known high-risk services, MEDIUM otherwise."""
    return Severity.HIGH if port in HIGH_RISK_PORTS else Severity.MEDIUM


def _asset_for_host(host: str) -> Asset:
    """Build the Asset representing a single scanned host."""
    ip_addresses: list[str] = []
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(host)
        ip_addresses = [host]
    return Asset(
        asset_type=AssetType.HOST,
        hostname=host,
        ip_addresses=ip_addresses,
        source=Source.HELIOS,
        tags=["helios", "port-scan"],
    )


def build_findings(recons: list[HostRecon]) -> tuple[list[Asset], list[Finding]]:
    """Convert Helios recon snapshots into Assets plus one Finding per open port."""
    assets: list[Asset] = []
    findings: list[Finding] = []
    for recon in recons:
        asset = _asset_for_host(recon.host)
        assets.append(asset)
        findings.extend(
            Finding(
                asset_id=asset.asset_id,
                source=Source.HELIOS,
                title=f"Open port {port}/tcp ({_service_name(port)})",
                description=f"TCP port {port} ({_service_name(port)}) is open on {recon.host}.",
                severity=_severity_for_port(port),
            )
            for port in recon.open_ports
        )
    return assets, findings


def export_findings(assets: list[Asset], findings: list[Finding], path: Path) -> None:
    """Write ``assets``/``findings`` as a JSON object conforming to core models."""
    payload = {
        "assets": [json.loads(asset.model_dump_json()) for asset in assets],
        "findings": [json.loads(finding.model_dump_json()) for finding in findings],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_findings(path: Path) -> tuple[list[Asset], list[Finding]]:
    """Read and validate a previously exported ``helios-findings.json`` file."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a JSON object with 'assets' and 'findings'")
    assets = [Asset.model_validate(item) for item in raw.get("assets", [])]
    findings = [Finding.model_validate(item) for item in raw.get("findings", [])]
    return assets, findings
