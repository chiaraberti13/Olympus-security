"""Deterministic alert-to-incident triage for Minerva."""

from __future__ import annotations

import json
from pathlib import Path

from olympus.core.contracts import validate_contract_header
from olympus.core.enums import IncidentStatus, Severity, Source
from olympus.core.models import Alert, Incident

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def triage_alerts(alerts: list[Alert], title: str, owner: str | None = None) -> Incident:
    """Create one triaged incident linked to non-duplicated alert evidence."""
    if not alerts:
        raise ValueError("at least one alert is required for triage")
    severity = max((alert.severity for alert in alerts), key=_SEVERITY_RANK.__getitem__)
    alert_ids = list(dict.fromkeys(alert.alert_id for alert in alerts))
    evidence_ids = list(
        dict.fromkeys(evidence_id for alert in alerts for evidence_id in alert.evidence_ids)
    )
    return Incident(
        title=title,
        summary=f"Triaged from {len(alert_ids)} alert(s).",
        source=Source.MINERVA,
        severity=severity,
        status=IncidentStatus.TRIAGED,
        alert_ids=alert_ids,
        evidence_ids=evidence_ids,
        owner=owner,
    )


def export_incident(incident: Incident, output: Path) -> None:
    """Write a core-compatible Incident document atomically."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(f"{output.suffix}.tmp")
    temporary.write_text(incident.model_dump_json(indent=2) + "\n", encoding="utf-8")
    temporary.replace(output)


def load_alerts(path: Path) -> list[Alert]:
    """Load alerts from an Apollo export and validate every shared object."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    validate_contract_header(payload, schema_name="olympus.apollo-alerts")
    raw_alerts = payload.get("alerts")
    if not isinstance(raw_alerts, list):
        raise ValueError("alerts must be a JSON array")
    return [Alert.model_validate(item) for item in raw_alerts]
