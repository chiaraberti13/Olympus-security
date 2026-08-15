"""Smoke tests for the unified CLI wiring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus import __version__
from olympus.argus import cli as argus_cli
from olympus.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_export_schemas_outputs_valid_json() -> None:
    result = runner.invoke(app, ["core", "export-schemas"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "olympus.asset" in payload
    assert "olympus.finding" in payload
    assert "olympus.event" in payload
    assert "olympus.evidence" in payload
    assert "olympus.alert" in payload
    assert "olympus.incident" in payload


def test_argus_demo_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "DEFAULT_ASSETS_PATH", tmp_path / "argus-assets.json")
    result = runner.invoke(app, ["argus", "demo"])
    assert result.exit_code == 0
    assert "exported 2 assets" in result.stdout


def test_remaining_scaffold_demo_runs() -> None:
    # Proteus is still a scaffold until its real commands land; every other
    # module now ships real tools (no demo).
    result = runner.invoke(app, ["proteus", "demo"])
    assert result.exit_code == 0
    assert "not implemented" in result.stdout
