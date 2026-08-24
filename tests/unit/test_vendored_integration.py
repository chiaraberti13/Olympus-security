"""Feature-parity and wiring tests for the complete vendored upstream tools.

These tests confirm the vendored ARGUS and Vulnerability Assessment Platform
sources are present and complete (so nothing is lost when the standalone
repositories are deleted) and that both are wired into the ``olympus`` CLI as
first-class, runnable subcommands. They are dependency-light: heavy upstream
imports are only exercised where their runtime deps are installed.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.integrations.vendored import (
    ARGUS_DIR,
    VAP_DIR,
    VendoredToolNotFoundError,
    ensure_on_path,
    tool_path,
    vendor_root,
)

runner = CliRunner()

# Complete standalone ARGUS module set (every original OSINT module).
EXPECTED_ARGUS_MODULES = {
    "dns_lookup",
    "domain",
    "email_osint",
    "ip_tracker",
    "mac_lookup",
    "myip",
    "phone_tracker",
    "username_tracker",
    "web_recon",
}

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


def test_argus_source_is_complete() -> None:
    argus = tool_path(ARGUS_DIR)
    assert (argus / "LICENSE").is_file()
    assert (argus / "pyproject.toml").is_file()
    modules = {p.stem for p in (argus / "argus" / "modules").glob("*.py") if p.stem != "__init__"}
    assert modules >= EXPECTED_ARGUS_MODULES
    for core in ("cli", "config", "exporters", "ui", "updater", "utils", "banner"):
        assert (argus / "argus" / f"{core}.py").is_file()


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


def test_tool_path_rejects_unknown() -> None:
    with pytest.raises(VendoredToolNotFoundError):
        tool_path("does-not-exist")


def test_ensure_on_path_is_idempotent() -> None:
    first = ensure_on_path(ARGUS_DIR)
    second = ensure_on_path(ARGUS_DIR)
    assert first == second


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


def test_aegis_and_argus_native_are_registered() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "argus-native" in result.output
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


def test_argus_native_passthrough_runs_offline() -> None:
    # Phone analysis is fully offline (phonenumbers); requires the [argus] extra.
    pytest.importorskip("phonenumbers")
    pytest.importorskip("rich")
    result = runner.invoke(app, ["argus-native", "phone", "+14155552671"])
    assert result.exit_code == 0, result.output
    assert "Phone Intelligence" in result.output
