"""Smoke tests for the unified CLI wiring."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from olympus import __version__
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
    result = runner.invoke(app, ["argus", "demo"])
    assert result.exit_code == 0
    assert "not implemented" in result.stdout


def test_all_tool_demos_run() -> None:
    for tool in (
        "argus",
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
