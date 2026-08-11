"""Change monitoring: diff two Argus asset snapshots.

Compares two `argus-assets.json` snapshots (typically the same domain
scanned at two different points in time) and reports which hosts appeared,
disappeared, or changed IP addresses — passive attack-surface drift
detection, built directly on the shared `core.Asset` contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from olympus.core.models import Asset


@dataclass(frozen=True)
class AssetChange:
    """A hostname present in both snapshots whose IP addresses differ."""

    hostname: str
    previous_ip_addresses: list[str]
    current_ip_addresses: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view of this change."""
        return {
            "hostname": self.hostname,
            "previous_ip_addresses": self.previous_ip_addresses,
            "current_ip_addresses": self.current_ip_addresses,
        }


@dataclass(frozen=True)
class SnapshotDiff:
    """Result of comparing two Argus asset snapshots, by hostname."""

    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[AssetChange] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        """Return ``True`` if any hostname was added, removed, or changed."""
        return bool(self.added or self.removed or self.changed)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view of this diff."""
        return {
            "added": self.added,
            "removed": self.removed,
            "changed": [change.to_dict() for change in self.changed],
            "unchanged": self.unchanged,
        }


def _index_by_hostname(assets: list[Asset]) -> dict[str, Asset]:
    """Index assets by hostname, skipping any asset with no hostname."""
    return {asset.hostname: asset for asset in assets if asset.hostname is not None}


def diff_snapshots(previous: list[Asset], current: list[Asset]) -> SnapshotDiff:
    """Compare two Argus asset snapshots and report added/removed/changed hosts."""
    previous_by_host = _index_by_hostname(previous)
    current_by_host = _index_by_hostname(current)

    previous_hosts = set(previous_by_host)
    current_hosts = set(current_by_host)

    added = sorted(current_hosts - previous_hosts)
    removed = sorted(previous_hosts - current_hosts)

    changed: list[AssetChange] = []
    unchanged: list[str] = []
    for hostname in sorted(previous_hosts & current_hosts):
        previous_asset = previous_by_host[hostname]
        current_asset = current_by_host[hostname]
        if previous_asset.ip_addresses != current_asset.ip_addresses:
            changed.append(
                AssetChange(
                    hostname=hostname,
                    previous_ip_addresses=previous_asset.ip_addresses,
                    current_ip_addresses=current_asset.ip_addresses,
                )
            )
        else:
            unchanged.append(hostname)

    return SnapshotDiff(added=added, removed=removed, changed=changed, unchanged=unchanged)
