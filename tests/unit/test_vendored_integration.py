"""Temporary compatibility tests for the legacy vendored VAP boundary.

ARGUS has completed its native migration and is covered by
``test_argus_native_replacement.py``.  These tests remain only until the VAP
runtime surface is replaced by the native AEGIS control plane.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from olympus.cli import app
from olympus.integrations.vendored import (
    VAP_DIR,
    tool_path,
    vendor_root,
)

runner = CliRunner()

# The complete VAP scanner catalogue — all 24 integrations.
EXPECTED_VAP_SCANNERS = {
    "acunetix", "arjun", "burp", "commix", "dalfox", "dirsearch", "httpx",
    "katana", "nessus", "nikto", "nmap", "nosqlmap", "nuclei", "openvas",
    "sqlmap", "subfinder", "testssl", "theharvester", "wafw00f", "wapiti",
    "whatweb", "wpscan", "xsstrike", "zap",
}


# --------------------------------------------------------------------------- #
# Vendored source completeness (feature parity)
# --------------------------------------------------------------------------- #
def test_vendor_root_exists() -> None:
    assert vendor_root().is_dir()


def test_vap_source_is_complete() -> None:
    vap = tool_path(VAP_DIR)
    assert (vap / "LICENSE").is_file()
    scanners = {
        p.stem.removesuffix("_scanner")
        for p in (vap / "scanners").glob("*_scanner.py")
    }
    assert scanners == EXPECTED_VAP_SCANNERS
    for key_file in (
        "app.py",
        "database.py",
        "scanner_engine.py",
        "report_generator.py",
        "celery_app.py",
        "alembic.ini",
        "docker-compose.yml",
        "requirements.txt",
    ):
        assert (vap / key_file).is_file(), key_file
    for key_dir in ("templates", "static", "db_migrations", "assets"):
        assert (vap / key_dir).is_dir(), key_dir


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #
def test_aegis_scanners_command_lists_all_24() -> None:
    result = runner.invoke(app, ["aegis", "scanners"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["count"] == 24
    assert set(payload["scanners"]) == EXPECTED_VAP_SCANNERS


def test_aegis_scanners_check_reports_binaries() -> None:
    result = runner.invoke(app, ["aegis", "scanners", "--check"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["count"] == 24
    assert "available_binaries" in payload
    assert all("binary" in row and "licence" in row for row in payload["scanners"])


def test_aegis_info_command() -> None:
    result = runner.invoke(app, ["aegis", "info"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["scanners"] == 24
    assert "path" in payload
    assert "install_hint" in payload


def test_legacy_web_requires_explicit_acknowledgement() -> None:
    result = runner.invoke(app, ["aegis", "serve"])
    assert result.exit_code == 2
    assert "quarantined" in result.output.lower()


def test_legacy_web_rejects_non_loopback_bind() -> None:
    result = runner.invoke(
        app,
        ["aegis", "serve", "--allow-legacy-web", "--host", "0.0.0.0"],
    )
    assert result.exit_code == 2
    assert "loopback" in result.output.lower()


def test_aegis_and_vap_compatibility_are_registered() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "argus-native" not in result.output
    assert "argus" in result.output
    assert "aegis" in result.output
    assert "vap" in result.output  # deprecated alias still present


def test_vap_alias_is_deprecated_and_forwards() -> None:
    result = runner.invoke(app, ["vap", "scanners"])
    assert result.exit_code == 0, result.output
    assert "deprecated" in result.output.lower()
    # The forwarded aegis output (JSON) follows the deprecation notice.
    assert '"count": 24' in result.output


def test_doctor_commands_run() -> None:
    for argv in (["doctor"], ["aegis", "doctor"], ["argus", "doctor"]):
        result = runner.invoke(app, argv)
        assert result.exit_code == 0, (argv, result.output)
        payload = json.loads(result.output)
        assert payload.get("checks")
