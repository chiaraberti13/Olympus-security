"""Unit tests for Proteus campaign report generation and round trip."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from olympus.core.enums import Severity
from olympus.proteus.campaign import CampaignResult, Recipient
from olympus.proteus.report import build_report, export_report, load_report

CAMPAIGN_NAME = "Q3 Awareness Campaign"


def _result(email: str, clicked: bool) -> CampaignResult:
    return CampaignResult(
        recipient=Recipient(email=email), clicked=clicked, simulated_at=datetime.now(UTC)
    )


def test_build_report_creates_one_asset_per_recipient() -> None:
    results = [_result("alice@olympusdemocorp.example", False), _result("bob@x.example", True)]
    assets, _findings = build_report(CAMPAIGN_NAME, results)

    assert len(assets) == 2
    assert assets[0].metadata["email"] == "alice@olympusdemocorp.example"


def test_build_report_creates_finding_only_for_clicked_recipients() -> None:
    results = [
        _result("alice@olympusdemocorp.example", False),
        _result("bob@olympusdemocorp.example", True),
    ]
    assets, findings = build_report(CAMPAIGN_NAME, results)

    assert len(findings) == 1
    assert findings[0].asset_id == assets[1].asset_id
    assert findings[0].severity == Severity.LOW
    assert CAMPAIGN_NAME in findings[0].title


def test_build_report_finding_never_mentions_a_credential() -> None:
    results = [_result("bob@olympusdemocorp.example", True)]
    _assets, findings = build_report(CAMPAIGN_NAME, results)

    description = findings[0].description.lower()
    assert "no real credentials" in description
    assert "password" not in description


def test_build_report_no_clicks_yields_no_findings() -> None:
    results = [_result("alice@olympusdemocorp.example", False)]
    _assets, findings = build_report(CAMPAIGN_NAME, results)
    assert findings == []


def test_export_and_load_report_round_trip(tmp_path: Path) -> None:
    results = [
        _result("alice@olympusdemocorp.example", False),
        _result("bob@olympusdemocorp.example", True),
    ]
    original_assets, original_findings = build_report(CAMPAIGN_NAME, results)
    output_path = tmp_path / "nested" / "proteus-report.json"

    export_report(CAMPAIGN_NAME, original_assets, original_findings, output_path)
    loaded_name, loaded_assets, loaded_findings = load_report(output_path)

    assert loaded_name == CAMPAIGN_NAME
    assert loaded_assets == original_assets
    assert loaded_findings == original_findings


def test_export_report_includes_summary_counts(tmp_path: Path) -> None:
    results = [
        _result("alice@olympusdemocorp.example", False),
        _result("bob@olympusdemocorp.example", True),
    ]
    assets, findings = build_report(CAMPAIGN_NAME, results)
    output_path = tmp_path / "report.json"

    export_report(CAMPAIGN_NAME, assets, findings, output_path)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["recipient_count"] == 2
    assert payload["clicked_count"] == 1


def test_load_report_rejects_non_object_payload(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a JSON object"):
        load_report(path)
