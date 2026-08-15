"""CLI-level test for `olympus artemis xss-demo`."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.artemis import cli as artemis_cli
from olympus.cli import app

runner = CliRunner()


def test_xss_demo_flags_reflected_parameter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "xss-findings.json"
    monkeypatch.setattr(artemis_cli, "DEMO_XSS_OUTPUT", out)
    result = runner.invoke(app, ["artemis", "xss-demo"])
    assert result.exit_code == 0, result.output
    findings = json.loads(out.read_text(encoding="utf-8"))
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "Reflected XSS" in findings[0]["title"]
