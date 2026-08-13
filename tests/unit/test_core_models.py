"""Unit tests for the core Pydantic models and their strict contract."""

from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from olympus.core.enums import (
    AssetType,
    EventType,
    EvidenceType,
    FindingStatus,
    IncidentStatus,
    Severity,
    Source,
)
from olympus.core.models import Alert, Asset, Event, Evidence, Finding, Incident

ASSET_ID = re.compile(r"^AST-\d{4}-\d{5}$")
FINDING_ID = re.compile(r"^FND-\d{4}-\d{5}$")
EVENT_ID = re.compile(r"^EVT-\d{4}-\d{5}$")
EVIDENCE_ID = re.compile(r"^EVD-\d{4}-\d{5}$")
ALERT_ID = re.compile(r"^ALT-\d{4}-\d{5}$")
INCIDENT_ID = re.compile(r"^INC-\d{4}-\d{5}$")


def test_asset_autogenerates_traceable_id() -> None:
    asset = Asset(asset_type=AssetType.WEB_SERVER)
    assert ASSET_ID.match(asset.asset_id)
    assert asset.schema_name == "olympus.asset"
    assert asset.schema_version == "1.0.0"


def test_asset_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        Asset(asset_type=AssetType.HOST, not_a_field=True)  # type: ignore[call-arg]


def test_finding_requires_asset_id_and_title() -> None:
    finding = Finding(asset_id="AST-2026-00001", source=Source.HELIOS, title="Open port 22")
    assert FINDING_ID.match(finding.finding_id)
    assert finding.severity is Severity.MEDIUM


def test_finding_rejects_empty_title() -> None:
    with pytest.raises(ValidationError):
        Finding(asset_id="AST-2026-00001", source=Source.HELIOS, title="")


def test_finding_cvss_out_of_range_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(asset_id="AST-2026-00001", source=Source.ARTEMIS, title="XSS", cvss=42.0)


def test_finding_json_round_trip() -> None:
    original = Finding(
        asset_id="AST-2026-00001",
        source=Source.ARTEMIS,
        title="Reflected XSS",
        severity=Severity.HIGH,
        cvss=7.4,
    )
    restored = Finding.model_validate_json(original.model_dump_json())
    assert restored == original


def test_event_autogenerates_traceable_id() -> None:
    event = Event(event_type=EventType.AUTHENTICATION, source=Source.APOLLO, summary="login")
    assert EVENT_ID.match(event.event_id)
    assert event.schema_name == "olympus.event"


def test_event_rejects_empty_summary() -> None:
    with pytest.raises(ValidationError):
        Event(event_type=EventType.NETWORK, source=Source.APOLLO, summary="")


def test_evidence_autogenerates_traceable_id() -> None:
    evidence = Evidence(evidence_type=EvidenceType.LOG_EXCERPT, reference="EVT-2026-00001")
    assert EVIDENCE_ID.match(evidence.evidence_id)


def test_evidence_rejects_empty_reference() -> None:
    with pytest.raises(ValidationError):
        Evidence(evidence_type=EvidenceType.LOG_EXCERPT, reference="")


def test_alert_autogenerates_traceable_id_and_defaults() -> None:
    alert = Alert(title="Brute force detected", source=Source.APOLLO, rule_id="RULE-001")
    assert ALERT_ID.match(alert.alert_id)
    assert alert.severity is Severity.MEDIUM
    assert alert.status is FindingStatus.NEW
    assert alert.evidence == []


def test_alert_rejects_empty_rule_id() -> None:
    with pytest.raises(ValidationError):
        Alert(title="x", source=Source.APOLLO, rule_id="")


def test_alert_json_round_trip_with_embedded_evidence() -> None:
    evidence = Evidence(evidence_type=EvidenceType.LOG_EXCERPT, reference="EVT-2026-00001")
    original = Alert(
        title="Brute force detected",
        source=Source.APOLLO,
        rule_id="RULE-001",
        mitre_technique_id="T1110",
        event_ids=["EVT-2026-00001"],
        evidence=[evidence],
    )
    restored = Alert.model_validate_json(original.model_dump_json())
    assert restored == original


def test_incident_autogenerates_traceable_id_and_defaults() -> None:
    incident = Incident(title="Suspicious brute force activity")
    assert INCIDENT_ID.match(incident.incident_id)
    assert incident.status is IncidentStatus.NEW
    assert incident.severity is Severity.MEDIUM
    assert incident.closed_at is None


def test_incident_rejects_empty_title() -> None:
    with pytest.raises(ValidationError):
        Incident(title="")


def test_incident_json_round_trip_with_linked_objects() -> None:
    evidence = Evidence(evidence_type=EvidenceType.LOG_EXCERPT, reference="ALT-2026-00001")
    original = Incident(
        title="Suspicious brute force activity",
        source=Source.MINERVA,
        status=IncidentStatus.TRIAGED,
        asset_ids=["AST-2026-00001"],
        finding_ids=["FND-2026-00001"],
        alert_ids=["ALT-2026-00001"],
        evidence=[evidence],
    )
    restored = Incident.model_validate_json(original.model_dump_json())
    assert restored == original
