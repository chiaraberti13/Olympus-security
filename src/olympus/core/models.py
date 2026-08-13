"""Canonical Pydantic models shared by every Olympus module.

These models are the interoperability contract: the same ``Asset`` or
``Finding`` can be produced by one tool and consumed by another without any
format negotiation. Each model declares its ``schema_name`` and
``schema_version`` (Semantic Versioning) and forbids unknown fields.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from olympus.core.enums import (
    AssetType,
    Criticality,
    EventType,
    EvidenceType,
    FindingStatus,
    IncidentStatus,
    Severity,
    Source,
)
from olympus.core.ids import new_id


def _utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


class OlympusModel(BaseModel):
    """Base class for every Olympus object.

    Enforces a strict contract: unknown fields are rejected and every object
    is self-describing through its schema name and version.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    schema_name: str
    schema_version: str = "1.0.0"


class Asset(OlympusModel):
    """A resource observed or managed by the platform (host, domain, URL...)."""

    schema_name: str = "olympus.asset"
    asset_id: str = Field(default_factory=lambda: new_id("asset"))
    asset_type: AssetType
    hostname: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    criticality: Criticality = Criticality.MEDIUM
    owner: str | None = None
    source: Source = Source.MANUAL
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class Finding(OlympusModel):
    """A weakness, vulnerability or misconfiguration attached to an asset."""

    schema_name: str = "olympus.finding"
    finding_id: str = Field(default_factory=lambda: new_id("finding"))
    asset_id: str
    source: Source
    title: str = Field(min_length=1)
    description: str = ""
    severity: Severity = Severity.MEDIUM
    status: FindingStatus = FindingStatus.NEW
    cvss: float | None = None
    evidence: list[str] = Field(default_factory=list)
    remediation: str = ""
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    references: list[str] = Field(default_factory=list)

    @field_validator("cvss")
    @classmethod
    def _validate_cvss(cls, value: float | None) -> float | None:
        """Ensure CVSS, when present, stays within the 0.0-10.0 range."""
        if value is not None and not 0.0 <= value <= 10.0:
            raise ValueError("cvss must be between 0.0 and 10.0")
        return value


class Event(OlympusModel):
    """A single observed telemetry event feeding the detection pipeline."""

    schema_name: str = "olympus.event"
    event_id: str = Field(default_factory=lambda: new_id("event"))
    event_type: EventType
    source: Source
    asset_id: str | None = None
    summary: str = Field(min_length=1)
    raw: dict[str, str] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=_utcnow)


class Evidence(OlympusModel):
    """A piece of supporting evidence backing an alert, finding or incident."""

    schema_name: str = "olympus.evidence"
    evidence_id: str = Field(default_factory=lambda: new_id("evidence"))
    evidence_type: EvidenceType
    description: str = ""
    reference: str = Field(min_length=1)
    collected_at: datetime = Field(default_factory=_utcnow)


class Alert(OlympusModel):
    """A detection-engineering alert: a rule that fired against one or more events."""

    schema_name: str = "olympus.alert"
    alert_id: str = Field(default_factory=lambda: new_id("alert"))
    title: str = Field(min_length=1)
    description: str = ""
    severity: Severity = Severity.MEDIUM
    status: FindingStatus = FindingStatus.NEW
    source: Source
    rule_id: str = Field(min_length=1)
    mitre_technique_id: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)


class Incident(OlympusModel):
    """An incident-response case aggregating alerts/findings into one investigation."""

    schema_name: str = "olympus.incident"
    incident_id: str = Field(default_factory=lambda: new_id("incident"))
    title: str = Field(min_length=1)
    description: str = ""
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.NEW
    source: Source = Source.MANUAL
    asset_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    opened_at: datetime = Field(default_factory=_utcnow)
    closed_at: datetime | None = None
