"""Unit tests for the core Pydantic models and their strict contract."""

from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding

ASSET_ID = re.compile(r"^AST-\d{4}-\d{5}$")
FINDING_ID = re.compile(r"^FND-\d{4}-\d{5}$")


def test_asset_autogenerates_traceable_id() -> None:
    asset = Asset(asset_type=AssetType.WEB_SERVER)
    assert ASSET_ID.match(asset.asset_id)
    assert asset.schema_name == "olympus.asset"
    assert asset.schema_version == "1.0.0"


def test_asset_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        Asset(asset_type=AssetType.HOST, not_a_field=True)  # type: ignore[call-arg]


def test_finding_requires_asset_id_and_title() -> None:
    finding = Finding(asset_id="AST-2026-00001", source=Source.HELIOS, title="Open port 22")
    assert FINDING_ID.match(finding.finding_id)
    assert finding.severity is Severity.MEDIUM


def test_finding_rejects_empty_title() -> None:
    with pytest.raises(ValidationError):
        Finding(asset_id="AST-2026-00001", source=Source.HELIOS, title="")


def test_finding_cvss_out_of_range_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(asset_id="AST-2026-00001", source=Source.ARTEMIS, title="XSS", cvss=42.0)


def test_finding_json_round_trip() -> None:
    original = Finding(
        asset_id="AST-2026-00001",
        source=Source.ARTEMIS,
        title="Reflected XSS",
        severity=Severity.HIGH,
        cvss=7.4,
    )
    restored = Finding.model_validate_json(original.model_dump_json())
    assert restored == original
