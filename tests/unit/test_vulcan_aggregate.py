"""Unit tests for Vulcan's cross-module export aggregation and deduplication."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from olympus.core.enums import AssetType, Source
from olympus.core.models import Alert, Asset, Finding
from olympus.vulcan.aggregate import aggregate, load_export


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _as_dict(model_json: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(model_json))


def _asset(asset_id: str) -> dict[str, Any]:
    return _as_dict(
        Asset(asset_id=asset_id, asset_type=AssetType.HOST, source=Source.HELIOS).model_dump_json()
    )


def _finding(finding_id: str, asset_id: str) -> dict[str, Any]:
    return _as_dict(
        Finding(
            finding_id=finding_id, asset_id=asset_id, source=Source.HELIOS, title="x"
        ).model_dump_json()
    )


def _alert(alert_id: str) -> dict[str, Any]:
    alert = Alert(alert_id=alert_id, title="x", source=Source.APOLLO, rule_id="RULE-001")
    return _as_dict(alert.model_dump_json())


def test_load_export_finds_objects_in_a_plain_list(tmp_path: Path) -> None:
    path = _write(tmp_path / "argus-assets.json", [_asset("AST-2026-00001")])
    found = load_export(path)
    assert len(found["olympus.asset"]) == 1


def test_load_export_finds_objects_nested_in_an_object(tmp_path: Path) -> None:
    payload = {
        "assets": [_asset("AST-2026-00001")],
        "findings": [_finding("FND-2026-00001", "AST-2026-00001")],
        "alerts": [_alert("ALT-2026-00001")],
    }
    path = _write(tmp_path / "helios-findings.json", payload)
    found = load_export(path)

    assert len(found["olympus.asset"]) == 1
    assert len(found["olympus.finding"]) == 1
    assert len(found["olympus.alert"]) == 1


def test_load_export_ignores_files_with_no_core_objects(tmp_path: Path) -> None:
    path = _write(tmp_path / "notes.json", {"note": "nothing here"})
    assert load_export(path) == {}


def test_aggregate_combines_objects_from_multiple_files(tmp_path: Path) -> None:
    file_a = _write(tmp_path / "a.json", [_asset("AST-2026-00001")])
    file_b = _write(tmp_path / "b.json", [_asset("AST-2026-00002")])

    result = aggregate([file_a, file_b])

    assert [a.asset_id for a in result.assets] == ["AST-2026-00001", "AST-2026-00002"]


def test_aggregate_deduplicates_by_id_across_files(tmp_path: Path) -> None:
    file_a = _write(tmp_path / "a.json", [_asset("AST-2026-00001")])
    file_b = _write(tmp_path / "b.json", {"assets": [_asset("AST-2026-00001")]})

    result = aggregate([file_a, file_b])

    assert len(result.assets) == 1


def test_aggregate_collects_findings_and_alerts_too(tmp_path: Path) -> None:
    payload = {
        "assets": [_asset("AST-2026-00001")],
        "findings": [_finding("FND-2026-00001", "AST-2026-00001")],
        "alerts": [_alert("ALT-2026-00001")],
    }
    path = _write(tmp_path / "combined.json", payload)

    result = aggregate([path])

    assert len(result.assets) == 1
    assert len(result.findings) == 1
    assert len(result.alerts) == 1


def test_aggregate_empty_input_yields_empty_result() -> None:
    result = aggregate([])
    assert result.assets == []
    assert result.findings == []
    assert result.alerts == []
