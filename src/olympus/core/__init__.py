"""Olympus Core — the shared data contract for every module.

Exposes the canonical models, enumerations, traceable ID generator and
structured validation errors that all Olympus tools rely on.
"""

from __future__ import annotations

from olympus.core.enums import (
    AlertStatus,
    AssetType,
    Criticality,
    FindingStatus,
    IncidentStatus,
    Severity,
    Source,
)
from olympus.core.errors import ValidationReport, format_validation_error
from olympus.core.execution import (
    AuthorizationRequiredError,
    CancellationRequested,
    CancellationToken,
    ExecutionPolicy,
    ExecutionPolicyError,
    StructuredAuditRecord,
)
from olympus.core.ids import IdGenerator, new_id
from olympus.core.models import (
    Alert,
    Asset,
    Event,
    Evidence,
    Finding,
    Incident,
    Observation,
    OlympusModel,
    ScanJob,
    SecurityReport,
)

__all__ = [
    "Alert",
    "AlertStatus",
    "Asset",
    "AssetType",
    "AuthorizationRequiredError",
    "CancellationRequested",
    "CancellationToken",
    "Criticality",
    "Event",
    "Evidence",
    "ExecutionPolicy",
    "ExecutionPolicyError",
    "Finding",
    "FindingStatus",
    "IdGenerator",
    "Incident",
    "IncidentStatus",
    "Observation",
    "OlympusModel",
    "ScanJob",
    "SecurityReport",
    "Severity",
    "Source",
    "StructuredAuditRecord",
    "ValidationReport",
    "format_validation_error",
    "new_id",
]
