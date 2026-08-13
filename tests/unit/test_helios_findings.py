"""Unit tests for Helios -> core.Asset/Finding conversion and JSON round trip."""

from __future__ import annotations

from pathlib import Path

import pytest

from olympus.core.enums import AssetType, Severity, Source
from olympus.helios.findings import build_findings, export_findings, load_findings
from olympus.helios.recon import HostRecon

HOST = "203.0.113.10"


def test_build_findings_creates_one_asset_per_host() -> None:
    recon = HostRecon(host=HOST, open_ports=[22, 443])
    assets, _findings = build_findings([recon])

    assert len(assets) == 1
    asset = assets[0]
    assert asset.asset_type == AssetType.HOST
    assert asset.hostname == HOST
    assert asset.ip_addresses == [HOST]
    assert asset.source == Source.HELIOS


def test_build_findings_creates_one_finding_per_open_port() -> None:
    recon = HostRecon(host=HOST, open_ports=[22, 3389])
    assets, findings = build_findings([recon])

    assert len(findings) == 2
    assert all(f.asset_id == assets[0].asset_id for f in findings)
    titles = {f.title for f in findings}
    assert "Open port 22/tcp (ssh)" in titles
    assert "Open port 3389/tcp (rdp)" in titles


def test_build_findings_flags_high_risk_ports_as_high_severity() -> None:
    recon = HostRecon(host=HOST, open_ports=[80, 3389])
    _assets, findings = build_findings([recon])

    by_port = {int(f.title.split("/")[0].removeprefix("Open port ")): f for f in findings}
    assert by_port[3389].severity == Severity.HIGH
    assert by_port[80].severity == Severity.MEDIUM


def test_build_findings_no_open_ports_yields_no_findings() -> None:
    recon = HostRecon(host=HOST, open_ports=[])
    assets, findings = build_findings([recon])

    assert len(assets) == 1
    assert findings == []


def test_build_findings_handles_hostname_without_ip_parsing() -> None:
    recon = HostRecon(host="demo-host.olympusdemocorp.example", open_ports=[443])
    assets, _findings = build_findings([recon])

    assert assets[0].hostname == "demo-host.olympusdemocorp.example"
    assert assets[0].ip_addresses == []


def test_export_and_load_findings_round_trip(tmp_path: Path) -> None:
    recon = HostRecon(host=HOST, open_ports=[22, 443])
    original_assets, original_findings = build_findings([recon])
    output_path = tmp_path / "nested" / "helios-findings.json"

    export_findings(original_assets, original_findings, output_path)
    loaded_assets, loaded_findings = load_findings(output_path)

    assert loaded_assets == original_assets
    assert loaded_findings == original_findings
    for asset in loaded_assets:
        assert asset.schema_name == "olympus.asset"
    for finding in loaded_findings:
        assert finding.schema_name == "olympus.finding"


def test_load_findings_rejects_non_object_payload(tmp_path: Path) -> None:
    path = tmp_path / "helios-findings.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a JSON object"):
        load_findings(path)
