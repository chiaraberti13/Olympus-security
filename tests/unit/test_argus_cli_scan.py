"""CLI-level tests for `olympus argus scan` (offline: resolver is stubbed)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.argus.ct import CtQueryError
from olympus.cli import app
from olympus.core.models import Asset

runner = CliRunner()

DOMAIN = "olympusdemocorp.example"


class _StubResolver:
    """Offline stand-in for DnspythonResolver injected via monkeypatch."""

    def resolve(self, name: str, record_type: str) -> list[str]:
        if name.lower() == DOMAIN and record_type == "A":
            return ["203.0.113.10"]
        if name.lower() == DOMAIN and record_type == "TXT":
            return ["v=spf1 ~all"]
        return []


class _StubCtClient:
    """Offline stand-in for CrtShClient injected via monkeypatch."""

    def query(self, domain: str) -> list[dict[str, str]]:
        return [{"name_value": f"www.{domain}"}]


class _FailingCtClient:
    """CrtShClient double simulating a blocked/unreachable CT log (e.g. no egress)."""

    def query(self, domain: str) -> list[dict[str, str]]:
        raise CtQueryError(f"crt.sh query failed for {domain}: blocked egress")


@pytest.fixture(autouse=True)
def _stub_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "DnspythonResolver", _StubResolver)
    monkeypatch.setattr(argus_cli, "CrtShClient", _StubCtClient)


def _write_scope(path: Path) -> Path:
    path.write_text(
        json.dumps({"engagement": "olympus-demo-corp-2026", "allowed_domains": [DOMAIN]}),
        encoding="utf-8",
    )
    return path


def test_scan_in_scope_domain_prints_recon_json(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    result = runner.invoke(
        app,
        ["argus", "scan", "--domain", DOMAIN, "--scope", str(scope_path), "--log", str(log_path)],
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["domain"] == DOMAIN
    assert payload["a_records"] == ["203.0.113.10"]
    assert payload["spf"] == "v=spf1 ~all"
    assert payload["subdomains"] == [f"www.{DOMAIN}"]


def test_scan_survives_ct_lookup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(argus_cli, "CrtShClient", _FailingCtClient)
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    result = runner.invoke(
        app,
        ["argus", "scan", "--domain", DOMAIN, "--scope", str(scope_path), "--log", str(log_path)],
    )

    assert result.exit_code == 0, result.output
    assert "certificate transparency lookup failed" in result.output
    payload = json.loads(result.stdout)
    assert payload["domain"] == DOMAIN
    assert payload["a_records"] == ["203.0.113.10"]
    assert payload["subdomains"] == []


def test_scan_with_output_exports_valid_core_assets(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"
    assets_path = tmp_path / "out" / "argus-assets.json"

    result = runner.invoke(
        app,
        [
            "argus",
            "scan",
            "--domain",
            DOMAIN,
            "--scope",
            str(scope_path),
            "--log",
            str(log_path),
            "--output",
            str(assets_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert assets_path.exists()

    raw = json.loads(assets_path.read_text(encoding="utf-8"))
    assets = [Asset.model_validate(item) for item in raw]
    hostnames = {asset.hostname for asset in assets}
    assert DOMAIN in hostnames
    assert f"www.{DOMAIN}" in hostnames


def test_scan_out_of_scope_domain_is_blocked_and_logged(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    result = runner.invoke(
        app,
        [
            "argus",
            "scan",
            "--domain",
            "evil.com",
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
            "argus",
            "scan",
            "--domain",
            DOMAIN,
            "--scope",
            str(tmp_path / "missing.json"),
            "--log",
            str(tmp_path / "blocked.log"),
        ],
    )

    assert result.exit_code == 2
    assert "scope error" in result.output
