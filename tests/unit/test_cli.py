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


def test_tool_demo_stub_runs() -> None:
    result = runner.invoke(app, ["helios", "demo"])
    assert result.exit_code == 0
    assert "not implemented" in result.stdout


def test_argus_demo_runs_the_real_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Redirect the demo's asset export away from the tracked examples/
    # sample: running the test suite must never dirty the working tree.
    monkeypatch.setattr(argus_cli, "DEMO_ASSETS_OUTPUT_PATH", tmp_path / "argus-assets.json")

    result = runner.invoke(app, ["argus", "demo"])

    assert result.exit_code == 0, result.output
    assert "olympusdemocorp.example" in result.stdout
    assert (tmp_path / "argus-assets.json").exists()


def test_remaining_tool_demos_are_still_stubs() -> None:
    for tool in (
        "helios",
        "artemis",
        "proteus",
        "hermes",
        "apollo",
        "minerva",
        "vulcan",
    ):
        result = runner.invoke(app, [tool, "demo"])
        assert result.exit_code == 0, tool
        assert "not implemented" in result.stdout
