"""Export/import the aggregated Vulcan report as JSON, alongside the Markdown."""

from __future__ import annotations

import json
from pathlib import Path

from olympus.core.models import Alert, Asset, Finding


def export_vulcan_report(
    engagement: str,
    assets: list[Asset],
    findings: list[Finding],
    alerts: list[Alert],
    path: Path,
) -> None:
    """Write ``assets``/``findings``/``alerts`` as a JSON object conforming to core models."""
    payload = {
        "engagement": engagement,
        "assets": [json.loads(asset.model_dump_json()) for asset in assets],
        "findings": [json.loads(finding.model_dump_json()) for finding in findings],
        "alerts": [json.loads(alert.model_dump_json()) for alert in alerts],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_vulcan_report(path: Path) -> tuple[str, list[Asset], list[Finding], list[Alert]]:
    """Read and validate a previously exported Vulcan report."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a JSON object with 'assets'/'findings'/'alerts'")
    engagement = str(raw.get("engagement", ""))
    assets = [Asset.model_validate(item) for item in raw.get("assets", [])]
    findings = [Finding.model_validate(item) for item in raw.get("findings", [])]
    alerts = [Alert.model_validate(item) for item in raw.get("alerts", [])]
    return engagement, assets, findings, alerts
