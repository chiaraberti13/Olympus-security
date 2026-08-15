"""Aggregate, deduplicate and rank the JSON outputs of other Olympus modules.

Vulcan is the reporting capstone: it consumes canonical arrays of
``core.Asset`` / ``core.Finding`` / ``core.Alert`` (produced by Argus,
Artemis, Helios, Apollo...) and turns them into one deduplicated, severity
-ranked view of an engagement — no format negotiation, just the shared
contract.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ValidationError

from olympus.core.enums import Severity
from olympus.core.models import Alert, Asset, Finding

# Highest first — the order findings/alerts are ranked in.
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class AggregationError(Exception):
    """Raised when an input file is missing, unreadable or fails validation."""


def _load_array(path: Path, model: type[BaseModel]) -> list[BaseModel]:
    """Load a JSON array (or single object) of ``model`` from ``path``."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AggregationError(f"input file not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AggregationError(f"input file could not be read: {path} ({exc})") from exc
    items = raw if isinstance(raw, list) else [raw]
    try:
        return [model.model_validate(item) for item in items]
    except ValidationError as exc:
        raise AggregationError(f"{path} failed validation against {model.__name__}: {exc}") from exc


def load_assets(paths: list[Path]) -> list[Asset]:
    """Load and concatenate ``core.Asset`` arrays from every path."""
    assets: list[Asset] = []
    for path in paths:
        assets.extend(a for a in _load_array(path, Asset) if isinstance(a, Asset))
    return assets


def load_findings(paths: list[Path]) -> list[Finding]:
    """Load and concatenate ``core.Finding`` arrays from every path."""
    findings: list[Finding] = []
    for path in paths:
        findings.extend(f for f in _load_array(path, Finding) if isinstance(f, Finding))
    return findings


def load_alerts(paths: list[Path]) -> list[Alert]:
    """Load and concatenate ``core.Alert`` arrays from every path."""
    alerts: list[Alert] = []
    for path in paths:
        alerts.extend(a for a in _load_array(path, Alert) if isinstance(a, Alert))
    return alerts


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Drop duplicate findings, keyed by (asset_id, title, severity)."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.asset_id, finding.title, str(finding.severity))
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Return findings sorted by severity (critical first), then title."""
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER[f.severity], f.title))


def severity_breakdown(findings: list[Finding]) -> dict[str, int]:
    """Return a count of findings per severity level (all levels present)."""
    counts = {level.value: 0 for level in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts
