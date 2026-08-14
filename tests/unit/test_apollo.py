"""Tests for secure Apollo rule loading and detection evaluation."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.apollo import cli as apollo_cli
from olympus.apollo.engine import evaluate
from olympus.apollo.export import export_alerts
from olympus.apollo.rules import load_rule
from olympus.cli import app
from olympus.core.enums import Source
from olympus.core.models import Alert, Event

runner = CliRunner()


def _rule(path: Path, technique: str = "T1059.001") -> Path:
    path.write_text(
        json.dumps({
            "rule_id": "APL-DEMO",
            "title": "Synthetic detection",
            "event_type": "process.start",
            "conditions": {"image": "powershell.exe"},
            "severity": "high",
            "mitre_attack": [technique],
        }),
        encoding="utf-8",
    )
    return path


def test_rule_validation_and_true_false_positives(tmp_path: Path) -> None:
    rule = load_rule(_rule(tmp_path / "rule.yaml"))
    matching = Event(
        event_type="process.start", source=Source.APOLLO, attributes={"image": "powershell.exe"}
    )
    benign = Event(
        event_type="process.start", source=Source.APOLLO, attributes={"image": "notepad.exe"}
    )

    assert len(evaluate([rule], matching)) == 1
    assert evaluate([rule], benign) == []


def test_rule_rejects_invalid_mitre_id_and_document(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        load_rule(_rule(tmp_path / "bad.yaml", "invalid"))
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("not executable yaml", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load_rule(malformed)


def test_alert_export_round_trips_core_model(tmp_path: Path) -> None:
    event = Event(event_type="auth.failure", source=Source.APOLLO)
    alert = Alert(event_id=event.event_id, title="Synthetic alert", source=Source.APOLLO)
    output = tmp_path / "alerts.json"
    export_alerts([alert], output)
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert Alert.model_validate(payload["alerts"][0]) == alert


def test_apollo_cli_and_demo_export_alerts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rule = _rule(tmp_path / "rule.yaml")
    event = Event(
        event_type="process.start", source=Source.APOLLO, attributes={"image": "powershell.exe"}
    )
    event_path = tmp_path / "event.json"
    event_path.write_text(event.model_dump_json(), encoding="utf-8")
    output = tmp_path / "alerts.json"

    result = runner.invoke(
        app, ["apollo", "test", str(rule), str(event_path), "--output", str(output)]
    )
    assert result.exit_code == 0
    assert "1 alert" in result.stdout

    monkeypatch.setattr(apollo_cli, "DEFAULT_OUTPUT", tmp_path / "demo-alerts.json")
    demo = runner.invoke(app, ["apollo", "demo"])
    assert demo.exit_code == 0
    assert "1 synthetic alert" in demo.stdout
