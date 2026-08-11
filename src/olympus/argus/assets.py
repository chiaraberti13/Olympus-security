"""Convert Argus recon results into the shared `olympus.core` Asset contract.

Every hostname Argus observes (the scanned domain and any subdomain found
through Certificate Transparency) becomes a `core.Asset`, so downstream
modules consume the same object regardless of which tool produced it.
"""

from __future__ import annotations

import json
from pathlib import Path

from olympus.argus.ct import CtRecon
from olympus.argus.recon import DomainRecon
from olympus.core.enums import AssetType, Source
from olympus.core.models import Asset


def build_assets(dns_result: DomainRecon, ct_result: CtRecon) -> list[Asset]:
    """Convert a DNS + CT recon pass into a list of `core.Asset` (one per hostname)."""
    metadata: dict[str, str] = {}
    if dns_result.spf is not None:
        metadata["spf"] = dns_result.spf
    if dns_result.dmarc is not None:
        metadata["dmarc"] = dns_result.dmarc
    if dns_result.mx_records:
        metadata["mx_records"] = ", ".join(dns_result.mx_records)

    assets = [
        Asset(
            asset_type=AssetType.DOMAIN,
            hostname=dns_result.domain,
            ip_addresses=[*dns_result.a_records, *dns_result.aaaa_records],
            source=Source.ARGUS,
            tags=["argus", "dns-recon"],
            metadata=metadata,
        )
    ]

    for subdomain in ct_result.subdomains:
        if subdomain == dns_result.domain:
            continue  # already represented by the primary asset above
        assets.append(
            Asset(
                asset_type=AssetType.DOMAIN,
                hostname=subdomain,
                source=Source.ARGUS,
                tags=["argus", "certificate-transparency"],
            )
        )
    return assets


def export_assets(assets: list[Asset], path: Path) -> None:
    """Write ``assets`` as a JSON array conforming to `core.Asset` to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [json.loads(asset.model_dump_json()) for asset in assets]
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_assets(path: Path) -> list[Asset]:
    """Read and validate a previously exported ``argus-assets.json`` file."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"{path} must contain a JSON array of assets")
    return [Asset.model_validate(item) for item in raw]
