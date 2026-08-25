"""Tests for bounded and scoped Helios surface discovery."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.models import Finding, Observation
from olympus.helios import cli as helios_cli
from olympus.helios.export import export_findings, to_findings, to_observations
from olympus.helios.scanner import OpenPort, discover
from olympus.helios.scope import OutOfScopeError, enforce_scope


class FakeConnector:
    def is_open(self, host: str, port: int, timeout: float) -> bool:
        return host == "192.0.2.10" and port == 443 and timeout == 1.0


runner = CliRunner()


def _scope(path: Path) -> Path:
    path.write_text(json.dumps({"allowed_networks": ["192.0.2.0/24", "2001:db8::/32"]}))
    return path


def test_scope_accepts_ipv4_and_ipv6_and_logs_blocks(tmp_path: Path) -> None:
    scope = _scope(tmp_path / "scope.json")
    log = tmp_path / "blocked.log"

    assert str(enforce_scope("192.0.2.10", scope, log)) == "192.0.2.10"
    assert str(enforce_scope("2001:db8::10", scope, log)) == "2001:db8::10"
    with pytest.raises(OutOfScopeError):
        enforce_scope("203.0.113.10", scope, log)
    assert "BLOCK target=203.0.113.10" in log.read_text(encoding="utf-8")


def test_discovery_is_bounded_and_injectable() -> None:
    assert discover("192.0.2.10", [443, 80, 443], FakeConnector()) == [
        OpenPort("192.0.2.10", 443, "https")
    ]
    with pytest.raises(ValueError):
        discover("192.0.2.10", [0], FakeConnector())
    with pytest.raises(ValueError):
        discover("192.0.2.10", list(range(1, 130)), FakeConnector())


def test_findings_round_trip_through_core(tmp_path: Path) -> None:
    output = tmp_path / "helios-findings.json"
    export_findings(to_findings("AST-2026-00001", [OpenPort("192.0.2.10", 443, "https")]), output)
    payload = json.loads(output.read_text(encoding="utf-8"))

    findings = [Finding.model_validate(item) for item in payload["findings"]]
    assert findings[0].evidence == ["tcp://192.0.2.10:443 (https)"]


def test_service_identification_and_risk() -> None:
    from olympus.helios.scanner import is_risky, service_for

    assert service_for(3389) == "rdp"
    assert service_for(65000) == "unknown"
    assert is_risky("rdp") is True
    assert is_risky("https") is False


def test_findings_flag_risky_services() -> None:
    from olympus.core.enums import Severity

    findings = to_findings("AST-1", [OpenPort("10.0.0.1", 3389, "rdp")])
    assert findings[0].severity is Severity.MEDIUM
    assert "high-risk" in findings[0].description
    assert findings[0].remediation


def test_discover_sets_service() -> None:
    result = discover("192.0.2.10", [443], FakeConnector())
    assert result and result[0].service == "https"


def test_cli_scan_enforces_scope_and_exports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helios_cli, "SocketConnector", FakeConnector)
    scope = _scope(tmp_path / "scope.json")
    output = tmp_path / "findings.json"

    result = runner.invoke(
        app,
        [
            "helios",
            "scan",
            "192.0.2.10",
            "--ports",
            "80,443",
            "--scope",
            str(scope),
            "--output",
            str(output),
            "--log",
            str(tmp_path / "blocked.log"),
        ],
    )

    assert result.exit_code == 0
    assert output.exists()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_name"] == "olympus.helios-result"
    observations = [Observation.model_validate(item) for item in payload["observations"]]
    assert observations[0].attributes == {
        "host": "192.0.2.10",
        "port": "443",
        "service": "https",
    }


def test_open_ports_map_to_versioned_observations() -> None:
    observations = to_observations("AST-2026-00001", [OpenPort("192.0.2.10", 443, "https")])
    assert observations[0].schema_name == "olympus.observation"
    assert observations[0].observation_type == "tcp.open-port"
