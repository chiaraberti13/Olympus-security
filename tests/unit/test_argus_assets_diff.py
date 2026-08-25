"""Tests for Argus core asset export and snapshot change monitoring."""

import json
from pathlib import Path

import pytest

from olympus.argus.assets import export_assets, recon_to_assets
from olympus.argus.diff import SnapshotValidationError, diff_snapshots
from olympus.argus.recon import DomainRecon
from olympus.core.models import Asset


def _export(path: Path, subdomains: list[str]) -> None:
    recon = DomainRecon(
        domain="olympusdemocorp.example",
        a_records=["203.0.113.10"],
        subdomains=subdomains,
    )
    export_assets(recon_to_assets(recon), path)


def test_export_round_trips_through_core_asset(tmp_path: Path) -> None:
    output = tmp_path / "argus-assets.json"
    _export(output, ["portal.olympusdemocorp.example"])
    payload = json.loads(output.read_text(encoding="utf-8"))

    assets = [Asset.model_validate(item) for item in payload["assets"]]
    assert payload["schema_name"] == "olympus.argus-assets"
    assert [asset.hostname for asset in assets] == [
        "olympusdemocorp.example",
        "portal.olympusdemocorp.example",
    ]


def test_diff_reports_added_removed_and_unchanged(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _export(before, ["old.olympusdemocorp.example"])
    _export(after, ["new.olympusdemocorp.example"])

    result = diff_snapshots(before, after)

    assert result.added == ["new.olympusdemocorp.example"]
    assert result.removed == ["old.olympusdemocorp.example"]
    assert result.unchanged == ["olympusdemocorp.example"]


def test_diff_rejects_unversioned_or_wrong_schema(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(json.dumps({"assets": []}), encoding="utf-8")
    _export(after, [])

    with pytest.raises(SnapshotValidationError, match="schema"):
        diff_snapshots(before, after)


def test_diff_rejects_malformed_assets_instead_of_silently_skipping(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    payload = {
        "schema_name": "olympus.argus-assets",
        "schema_version": "1.0.0",
        "assets": [{"hostname": "missing-required-asset-type.example"}],
    }
    before.write_text(json.dumps(payload), encoding="utf-8")
    _export(after, [])

    with pytest.raises(SnapshotValidationError, match="invalid asset at index 0"):
        diff_snapshots(before, after)
