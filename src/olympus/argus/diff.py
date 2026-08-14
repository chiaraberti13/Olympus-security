"""Change monitoring for Argus asset snapshots."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AssetDiff:
    """Hostname-level changes between two Argus snapshots."""

    added: list[str]
    removed: list[str]
    unchanged: list[str]


def _hostnames(path: Path) -> set[str]:
    payload: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("assets"), list):
        raise ValueError(f"invalid Argus asset snapshot: {path}")
    return {
        hostname.lower()
        for asset in payload["assets"]
        if isinstance(asset, dict) and isinstance((hostname := asset.get("hostname")), str)
    }


def diff_snapshots(before: Path, after: Path) -> AssetDiff:
    """Return deterministic hostname changes between two exported snapshots."""
    old = _hostnames(before)
    new = _hostnames(after)
    return AssetDiff(sorted(new - old), sorted(old - new), sorted(old & new))
