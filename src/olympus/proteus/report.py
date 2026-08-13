"""Convert Proteus campaign results into the shared `olympus.core` contract.

Each recipient becomes an Asset (tagged, not a real infrastructure
asset); every recipient who "clicked" the simulated link gets a Finding
(LOW severity — this is an awareness signal, not a vulnerability). No
credential, real or simulated, ever appears anywhere in this output.
"""

from __future__ import annotations

import json
from pathlib import Path

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.proteus.campaign import CampaignResult


def build_report(
    campaign_name: str, results: list[CampaignResult]
) -> tuple[list[Asset], list[Finding]]:
    """Build one Asset per recipient, plus one Finding per recipient who clicked."""
    assets: list[Asset] = []
    findings: list[Finding] = []
    for result in results:
        asset = Asset(
            asset_type=AssetType.OTHER,
            source=Source.PROTEUS,
            tags=["proteus", "campaign-recipient"],
            metadata={
                "email": result.recipient.email,
                "display_name": result.recipient.display_name,
            },
        )
        assets.append(asset)
        if result.clicked:
            findings.append(
                Finding(
                    asset_id=asset.asset_id,
                    source=Source.PROTEUS,
                    title=f"Recipient clicked simulated phishing link ({campaign_name})",
                    description=(
                        f"{result.recipient.email} clicked the simulated phishing link in "
                        f"campaign {campaign_name!r}. No real credentials were requested or "
                        "collected; a training-disclosure page was shown instead."
                    ),
                    severity=Severity.LOW,
                )
            )
    return assets, findings


def export_report(
    campaign_name: str, assets: list[Asset], findings: list[Finding], path: Path
) -> None:
    """Write ``assets``/``findings`` as a JSON object conforming to core models."""
    payload = {
        "campaign": campaign_name,
        "recipient_count": len(assets),
        "clicked_count": len(findings),
        "assets": [json.loads(asset.model_dump_json()) for asset in assets],
        "findings": [json.loads(finding.model_dump_json()) for finding in findings],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_report(path: Path) -> tuple[str, list[Asset], list[Finding]]:
    """Read and validate a previously exported campaign report."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a JSON object with 'assets' and 'findings'")
    campaign_name = str(raw.get("campaign", ""))
    assets = [Asset.model_validate(item) for item in raw.get("assets", [])]
    findings = [Finding.model_validate(item) for item in raw.get("findings", [])]
    return campaign_name, assets, findings
