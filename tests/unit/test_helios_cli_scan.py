"""CLI-level tests for `olympus helios scan` (offline: scanner is stubbed)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.models import Asset, Finding
from olympus.helios import cli as helios_cli

runner = CliRunner()

TARGET = "203.0.113.10"


class _StubScanner:
    """Offline stand-in for TcpConnectScanner injected via monkeypatch."""

    def is_open(self, host: str, port: int) -> bool:
        return host == TARGET and port in (22, 443)


@pytest.fixture(autouse=True)
def _stub_scanner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helios_cli, "TcpConnectScanner", _StubScanner)


def _write_scope(path: Path) -> Path:
    path.write_text(
        json.dumps({"engagement": "olympus-demo-corp-2026", "allowed_targets": ["203.0.113.0/24"]}),
        encoding="utf-8",
    )
    return path


def test_scan_in_scope_target_prints_open_ports(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    result = runner.invoke(
        app,
        ["helios", "scan", "--target", TARGET, "--scope", str(scope_path), "--log", str(log_path)],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["host"] == TARGET
    assert payload["open_ports"] == [22, 443]


def test_scan_with_output_exports_valid_core_assets_and_findings(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"
    findings_path = tmp_path / "out" / "helios-findings.json"

    result = runner.invoke(
        app,
        [
            "helios",
            "scan",
            "--target",
            TARGET,
            "--scope",
            str(scope_path),
            "--log",
            str(log_path),
            "--output",
            str(findings_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert findings_path.exists()

    raw = json.loads(findings_path.read_text(encoding="utf-8"))
    assets = [Asset.model_validate(item) for item in raw["assets"]]
    findings = [Finding.model_validate(item) for item in raw["findings"]]
    assert assets[0].hostname == TARGET
    assert len(findings) == 2


def test_scan_out_of_scope_target_is_blocked_and_logged(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    result = runner.invoke(
        app,
        [
            "helios",
            "scan",
            "--target",
            "198.51.100.10",
            "--scope",
            str(scope_path),
            "--log",
            str(log_path),
        ],
    )

    assert result.exit_code == 3
    assert "out of scope" in result.output
    assert log_path.exists()


def test_scan_missing_scope_file_errors(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "helios",
            "scan",
            "--target",
            TARGET,
            "--scope",
            str(tmp_path / "missing.json"),
            "--log",
            str(tmp_path / "blocked.log"),
        ],
    )

    assert result.exit_code == 2
    assert "scope error" in result.output
