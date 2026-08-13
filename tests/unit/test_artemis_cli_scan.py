"""CLI-level tests for `olympus artemis scan` (offline: HTTP client is stubbed)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.artemis import cli as artemis_cli
from olympus.artemis.http_client import HttpResponse
from olympus.cli import app

runner = CliRunner()

DOMAIN = "olympusdemocorp.example"
BASE_URL = f"https://{DOMAIN}"


class _StubClient:
    """Offline stand-in for UrllibHttpClient injected via monkeypatch."""

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if url == f"{BASE_URL}/.env":
            return HttpResponse(status_code=200)
        if url == BASE_URL or url.startswith(f"{BASE_URL}/"):
            return HttpResponse(status_code=404)
        return HttpResponse(status_code=404)


@pytest.fixture(autouse=True)
def _stub_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(artemis_cli, "UrllibHttpClient", _StubClient)


def _write_scope(path: Path) -> Path:
    path.write_text(
        json.dumps({"engagement": "olympus-demo-corp-2026", "allowed_hosts": [DOMAIN]}),
        encoding="utf-8",
    )
    return path


def test_scan_in_scope_url_reports_findings(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    result = runner.invoke(
        app,
        ["artemis", "scan", "--url", BASE_URL, "--scope", str(scope_path), "--log", str(log_path)],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["asset"]["hostname"] == DOMAIN
    titles = {f["title"] for f in payload["findings"]}
    assert "Exposed path: /.env" in titles
    assert "Missing security header: content-security-policy" in titles


def test_scan_with_output_writes_file(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"
    output_path = tmp_path / "out" / "artemis-findings.json"

    result = runner.invoke(
        app,
        [
            "artemis",
            "scan",
            "--url",
            BASE_URL,
            "--scope",
            str(scope_path),
            "--log",
            str(log_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["asset"]["hostname"] == DOMAIN


def test_scan_out_of_scope_url_is_blocked_and_logged(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    result = runner.invoke(
        app,
        [
            "artemis",
            "scan",
            "--url",
            "https://evil.com",
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
            "artemis",
            "scan",
            "--url",
            BASE_URL,
            "--scope",
            str(tmp_path / "missing.json"),
            "--log",
            str(tmp_path / "blocked.log"),
        ],
    )

    assert result.exit_code == 2
    assert "scope error" in result.output
