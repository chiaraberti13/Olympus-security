"""Canonical Pydantic models shared by every Olympus module.

These models are the interoperability contract: the same ``Asset`` or
``Finding`` can be produced by one tool and consumed by another without any
format negotiation. Each model declares its ``schema_name`` and
``schema_version`` (Semantic Versioning) and forbids unknown fields.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from olympus.core.enums import AlertStatus, AssetType, Criticality, FindingStatus, Severity, Source
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
    """A normalized observable consumed by detection rules."""

    schema_name: str = "olympus.event"
    event_id: str = Field(default_factory=lambda: new_id("event"))
    event_type: str = Field(min_length=1)
    source: Source
    observed_at: datetime = Field(default_factory=_utcnow)
    asset_id: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)


class Evidence(OlympusModel):
    """An immutable reference to material supporting a finding or alert."""

    schema_name: str = "olympus.evidence"
    evidence_id: str = Field(default_factory=lambda: new_id("evidence"))
    evidence_type: str = Field(min_length=1)
    uri: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    collected_at: datetime = Field(default_factory=_utcnow)


class Alert(OlympusModel):
    """A detection result linked to its source event and supporting evidence."""

    schema_name: str = "olympus.alert"
    alert_id: str = Field(default_factory=lambda: new_id("alert"))
    event_id: str
    title: str = Field(min_length=1)
    source: Source
    severity: Severity = Severity.MEDIUM
    status: AlertStatus = AlertStatus.OPEN
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
