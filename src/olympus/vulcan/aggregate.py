"""Aggregate Assets/Findings/Alerts from multiple module export files.

Every Olympus module export is, ultimately, a JSON structure containing
zero or more objects with a ``schema_name`` field (``olympus.asset``,
``olympus.finding``, ``olympus.alert``...). Rather than hand-coding a
reader per module's specific export shape — a plain list here (Argus), an
``{"assets": [...], "findings": [...]}`` object there (Helios) — this
module walks any JSON structure recursively and picks up every
recognized object by its ``schema_name``, so Vulcan can ingest whatever
downstream modules produce today, or add tomorrow, without a matching
change here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from olympus.core.models import Alert, Asset, Finding

_SCHEMA_MODELS: dict[str, type[Asset] | type[Finding] | type[Alert]] = {
    "olympus.asset": Asset,
    "olympus.finding": Finding,
    "olympus.alert": Alert,
}


def _walk(node: Any, found: dict[str, list[Any]]) -> None:
    """Recursively collect every recognized schema_name-tagged object under ``node``."""
    if isinstance(node, dict):
        schema_name = node.get("schema_name")
        if isinstance(schema_name, str) and schema_name in _SCHEMA_MODELS:
            model = _SCHEMA_MODELS[schema_name]
            found.setdefault(schema_name, []).append(model.model_validate(node))
            return  # a recognized object's own fields are not walked further
        for value in node.values():
            _walk(value, found)
    elif isinstance(node, list):
        for item in node:
            _walk(item, found)


def load_export(path: Path) -> dict[str, list[Any]]:
    """Extract every recognized core object from a single export file."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    found: dict[str, list[Any]] = {}
    _walk(raw, found)
    return found


@dataclass
class AggregatedData:
    """Deduplicated Assets/Findings/Alerts aggregated from multiple exports."""

    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)


def aggregate(paths: list[Path]) -> AggregatedData:
    """Load and deduplicate (by id) core objects from multiple export files."""
    assets: dict[str, Asset] = {}
    findings: dict[str, Finding] = {}
    alerts: dict[str, Alert] = {}

    for path in paths:
        found = load_export(path)
        for asset in found.get("olympus.asset", []):
            assets[asset.asset_id] = asset
        for finding in found.get("olympus.finding", []):
            findings[finding.finding_id] = finding
        for alert in found.get("olympus.alert", []):
            alerts[alert.alert_id] = alert

    return AggregatedData(
        assets=sorted(assets.values(), key=lambda asset: asset.asset_id),
        findings=sorted(findings.values(), key=lambda finding: finding.finding_id),
        alerts=sorted(alerts.values(), key=lambda alert: alert.alert_id),
    )
