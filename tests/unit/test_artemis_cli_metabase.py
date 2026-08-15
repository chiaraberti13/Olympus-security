"""CLI-level tests for `olympus artemis metabase-demo`."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.artemis import cli as artemis_cli
from olympus.cli import app

runner = CliRunner()


def test_metabase_demo_flags_affected_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "metabase-findings.json"
    monkeypatch.setattr(artemis_cli, "DEMO_METABASE_OUTPUT", out)
    result = runner.invoke(app, ["artemis", "metabase-demo"])
    assert result.exit_code == 0, result.output
    findings = json.loads(out.read_text(encoding="utf-8"))
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert "CVE-2026-72898" in findings[0]["title"]
