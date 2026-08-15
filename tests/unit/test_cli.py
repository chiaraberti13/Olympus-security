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
    assert "olympus.event" in payload
    assert "olympus.evidence" in payload
    assert "olympus.alert" in payload
    assert "olympus.incident" in payload


def test_no_module_exposes_a_demo_command() -> None:
    # Every module ships real, working tools — no demo scaffolding anywhere.
    for tool in ("argus", "helios", "artemis", "proteus", "hermes", "apollo", "minerva", "vulcan"):
        result = runner.invoke(app, [tool, "--help"])
        assert result.exit_code == 0, tool
        assert "demo" not in result.stdout, f"{tool} still exposes a demo command"


def test_proteus_and_vulcan_are_real_tools() -> None:
    # Both were scaffolds ("not implemented"); they now expose real commands.
    assert "campaign" in runner.invoke(app, ["proteus", "--help"]).stdout
    assert "report" in runner.invoke(app, ["vulcan", "--help"]).stdout
