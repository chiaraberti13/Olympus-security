"""Change monitoring for Argus asset snapshots."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from olympus.core.contracts import ContractCompatibilityError, validate_contract_header
from olympus.core.models import Asset


class SnapshotValidationError(ValueError):
    """Raised when an input is not a compatible versioned Argus asset snapshot."""


@dataclass(frozen=True)
class AssetDiff:
    """Hostname-level changes between two Argus snapshots."""

    added: list[str]
    removed: list[str]
    unchanged: list[str]


def _hostnames(path: Path) -> set[str]:
    payload: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("assets"), list):
        raise SnapshotValidationError(f"invalid Argus asset snapshot: {path}")
    try:
        validate_contract_header(payload, schema_name="olympus.argus-assets")
    except ContractCompatibilityError as exc:
        raise SnapshotValidationError(f"incompatible snapshot {path}: {exc}") from exc

    hostnames: set[str] = set()
    for index, item in enumerate(payload["assets"]):
        try:
            asset = Asset.model_validate(item)
        except ValidationError as exc:
            raise SnapshotValidationError(
                f"invalid asset at index {index} in snapshot {path}: {exc}"
            ) from exc
        if asset.hostname:
            hostnames.add(asset.hostname.strip().lower().rstrip("."))
    return hostnames


def diff_snapshots(before: Path, after: Path) -> AssetDiff:
    """Return deterministic hostname changes between two exported snapshots."""
    old = _hostnames(before)
    new = _hostnames(after)
    return AssetDiff(sorted(new - old), sorted(old - new), sorted(old & new))
