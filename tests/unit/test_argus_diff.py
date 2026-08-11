"""Unit tests for Argus change monitoring (diff between two asset snapshots)."""

from __future__ import annotations

from olympus.argus.diff import diff_snapshots
from olympus.core.enums import AssetType, Source
from olympus.core.models import Asset

DOMAIN = "olympusdemocorp.example"


def _asset(hostname: str, ip_addresses: list[str] | None = None) -> Asset:
    return Asset(
        asset_type=AssetType.DOMAIN,
        hostname=hostname,
        ip_addresses=ip_addresses or [],
        source=Source.ARGUS,
    )


def test_diff_detects_added_and_removed_hosts() -> None:
    previous = [_asset(DOMAIN), _asset(f"old.{DOMAIN}")]
    current = [_asset(DOMAIN), _asset(f"new.{DOMAIN}")]

    result = diff_snapshots(previous, current)

    assert result.added == [f"new.{DOMAIN}"]
    assert result.removed == [f"old.{DOMAIN}"]
    assert result.unchanged == [DOMAIN]
    assert result.changed == []
    assert result.has_changes is True


def test_diff_detects_ip_address_changes() -> None:
    previous = [_asset(DOMAIN, ["203.0.113.10"])]
    current = [_asset(DOMAIN, ["203.0.113.99"])]

    result = diff_snapshots(previous, current)

    assert result.added == []
    assert result.removed == []
    assert len(result.changed) == 1
    change = result.changed[0]
    assert change.hostname == DOMAIN
    assert change.previous_ip_addresses == ["203.0.113.10"]
    assert change.current_ip_addresses == ["203.0.113.99"]
    assert result.has_changes is True


def test_diff_identical_snapshots_has_no_changes() -> None:
    snapshot = [_asset(DOMAIN, ["203.0.113.10"]), _asset(f"www.{DOMAIN}")]

    result = diff_snapshots(snapshot, snapshot)

    assert result.added == []
    assert result.removed == []
    assert result.changed == []
    assert set(result.unchanged) == {DOMAIN, f"www.{DOMAIN}"}
    assert result.has_changes is False


def test_diff_to_dict_is_json_serializable() -> None:
    previous = [_asset(DOMAIN, ["203.0.113.10"])]
    current = [_asset(DOMAIN, ["203.0.113.99"]), _asset(f"new.{DOMAIN}")]

    payload = diff_snapshots(previous, current).to_dict()

    assert payload["added"] == [f"new.{DOMAIN}"]
    assert payload["changed"][0]["hostname"] == DOMAIN
    assert payload["unchanged"] == []


def test_diff_ignores_assets_without_hostname() -> None:
    hostless = Asset(asset_type=AssetType.OTHER, source=Source.ARGUS)
    result = diff_snapshots([hostless], [hostless])

    assert result.added == []
    assert result.removed == []
    assert result.unchanged == []
