"""Unit tests for Vulcan's JSON report export/import round trip."""

from __future__ import annotations

from pathlib import Path

import pytest

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Alert, Asset, Finding
from olympus.vulcan.report_export import export_vulcan_report, load_vulcan_report

ENGAGEMENT = "olympus-demo-corp-2026"


def test_export_and_load_round_trip(tmp_path: Path) -> None:
    assets = [Asset(asset_type=AssetType.HOST, source=Source.HELIOS)]
    findings = [
        Finding(
            asset_id=assets[0].asset_id,
            source=Source.HELIOS,
            title="Open port 3389/tcp (rdp)",
            severity=Severity.HIGH,
        )
    ]
    alerts = [Alert(title="Brute force detected", source=Source.APOLLO, rule_id="RULE-001")]
    output_path = tmp_path / "nested" / "vulcan-report.json"

    export_vulcan_report(ENGAGEMENT, assets, findings, alerts, output_path)
    loaded_engagement, loaded_assets, loaded_findings, loaded_alerts = load_vulcan_report(
        output_path
    )

    assert loaded_engagement == ENGAGEMENT
    assert loaded_assets == assets
    assert loaded_findings == findings
    assert loaded_alerts == alerts


def test_export_empty_report_round_trips(tmp_path: Path) -> None:
    output_path = tmp_path / "vulcan-report.json"
    export_vulcan_report(ENGAGEMENT, [], [], [], output_path)

    engagement, assets, findings, alerts = load_vulcan_report(output_path)

    assert engagement == ENGAGEMENT
    assert assets == []
    assert findings == []
    assert alerts == []


def test_load_vulcan_report_rejects_non_object_payload(tmp_path: Path) -> None:
    path = tmp_path / "vulcan-report.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a JSON object"):
        load_vulcan_report(path)
