"""Tests for deterministic Minerva alert triage."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import Severity, Source
from olympus.core.models import Alert, Incident
from olympus.minerva.triage import export_incident, load_alerts, triage_alerts

runner = CliRunner()


def _alert(identifier: str, severity: Severity, evidence: list[str]) -> Alert:
    return Alert(
        alert_id=identifier,
        event_id="EVT-2026-00001",
        title="Synthetic alert",
        source=Source.APOLLO,
        severity=severity,
        evidence_ids=evidence,
    )


def test_triage_selects_max_severity_and_deduplicates_links() -> None:
    low = _alert("ALT-2026-00001", Severity.LOW, ["EVD-2026-00001"])
    high = _alert(
        "ALT-2026-00002",
        Severity.HIGH,
        ["EVD-2026-00001", "EVD-2026-00002"],
    )

    incident = triage_alerts([low, high, high], "Olympus Demo triage", "demo-soc")

    assert incident.severity is Severity.HIGH
    assert incident.alert_ids == ["ALT-2026-00001", "ALT-2026-00002"]
    assert incident.evidence_ids == ["EVD-2026-00001", "EVD-2026-00002"]
    assert incident.owner == "demo-soc"


def test_triage_rejects_empty_alerts() -> None:
    with pytest.raises(ValueError, match="at least one alert"):
        triage_alerts([], "Invalid")


def test_load_alerts_and_cli_export_round_trip(tmp_path: Path) -> None:
    alert = _alert("ALT-2026-00001", Severity.CRITICAL, [])
    source = tmp_path / "alerts.json"
    source.write_text(
        json.dumps({
            "schema_name": "olympus.apollo-alerts",
            "schema_version": "1.0.0",
            "alerts": [alert.model_dump(mode="json")],
        }),
        encoding="utf-8",
    )
    assert load_alerts(source) == [alert]
    output = tmp_path / "incident.json"

    result = runner.invoke(
        app,
        [
            "minerva",
            "triage",
            str(source),
            "--title",
            "Critical synthetic incident",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    incident = Incident.model_validate_json(output.read_text(encoding="utf-8"))
    assert incident.alert_ids == [alert.alert_id]
    assert incident.severity is Severity.CRITICAL


def test_export_incident_is_atomic_shape(tmp_path: Path) -> None:
    incident = triage_alerts(
        [_alert("ALT-2026-00001", Severity.MEDIUM, [])], "Synthetic incident"
    )
    output = tmp_path / "incident.json"
    export_incident(incident, output)
    assert Incident.model_validate_json(output.read_text(encoding="utf-8")) == incident
