"""Unit tests for Minerva's incident-opening aggregation."""

from __future__ import annotations

from olympus.core.enums import IncidentStatus, Severity, Source
from olympus.core.models import Alert, Finding
from olympus.minerva.incident import open_incident


def _finding(asset_id: str, severity: Severity) -> Finding:
    return Finding(asset_id=asset_id, source=Source.HELIOS, title="x", severity=severity)


def _alert(severity: Severity) -> Alert:
    return Alert(title="x", source=Source.APOLLO, rule_id="RULE-001", severity=severity)


def test_open_incident_defaults() -> None:
    incident = open_incident("Suspicious activity")

    assert incident.title == "Suspicious activity"
    assert incident.status is IncidentStatus.NEW
    assert incident.severity is Severity.MEDIUM
    assert incident.asset_ids == []
    assert incident.finding_ids == []
    assert incident.alert_ids == []
    assert incident.source == Source.MINERVA


def test_open_incident_uses_highest_severity_across_alerts_and_findings() -> None:
    incident = open_incident(
        "Multi-source incident",
        alerts=[_alert(Severity.LOW)],
        findings=[_finding("AST-2026-00001", Severity.CRITICAL)],
    )
    assert incident.severity is Severity.CRITICAL


def test_open_incident_collects_deduplicated_sorted_asset_ids() -> None:
    incident = open_incident(
        "Incident",
        findings=[
            _finding("AST-2026-00002", Severity.LOW),
            _finding("AST-2026-00001", Severity.LOW),
            _finding("AST-2026-00001", Severity.LOW),
        ],
    )
    assert incident.asset_ids == ["AST-2026-00001", "AST-2026-00002"]


def test_open_incident_links_finding_and_alert_ids() -> None:
    finding = _finding("AST-2026-00001", Severity.HIGH)
    alert = _alert(Severity.HIGH)

    incident = open_incident("Incident", alerts=[alert], findings=[finding])

    assert incident.finding_ids == [finding.finding_id]
    assert incident.alert_ids == [alert.alert_id]
