"""CLI-level tests for `olympus argus diff`."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.argus.assets import export_assets
from olympus.cli import app
from olympus.core.enums import AssetType, Source
from olympus.core.models import Asset

runner = CliRunner()

DOMAIN = "olympusdemocorp.example"


def _write_snapshot(path: Path, hostnames: list[str]) -> Path:
    assets = [
        Asset(asset_type=AssetType.DOMAIN, hostname=hostname, source=Source.ARGUS)
        for hostname in hostnames
    ]
    export_assets(assets, path)
    return path


def test_diff_command_reports_added_and_removed(tmp_path: Path) -> None:
    previous = _write_snapshot(tmp_path / "previous.json", [DOMAIN, f"old.{DOMAIN}"])
    current = _write_snapshot(tmp_path / "current.json", [DOMAIN, f"new.{DOMAIN}"])

    result = runner.invoke(
        app, ["argus", "diff", "--previous", str(previous), "--current", str(current)]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["added"] == [f"new.{DOMAIN}"]
    assert payload["removed"] == [f"old.{DOMAIN}"]
    assert payload["unchanged"] == [DOMAIN]


def test_diff_command_missing_snapshot_errors(tmp_path: Path) -> None:
    previous = _write_snapshot(tmp_path / "previous.json", [DOMAIN])

    result = runner.invoke(
        app,
        [
            "argus",
            "diff",
            "--previous",
            str(previous),
            "--current",
            str(tmp_path / "missing.json"),
        ],
    )

    assert result.exit_code == 2
    assert "diff error" in result.output


def test_diff_command_malformed_snapshot_errors(tmp_path: Path) -> None:
    previous = _write_snapshot(tmp_path / "previous.json", [DOMAIN])
    malformed = tmp_path / "current.json"
    malformed.write_text('{"not": "a list"}', encoding="utf-8")

    result = runner.invoke(
        app, ["argus", "diff", "--previous", str(previous), "--current", str(malformed)]
    )

    assert result.exit_code == 2
    assert "diff error" in result.output
