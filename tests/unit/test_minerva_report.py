"""Unit tests for Minerva's incident report export/import round trip."""

from __future__ import annotations

from pathlib import Path

import pytest

from olympus.minerva.custody import ChainOfCustody
from olympus.minerva.incident import open_incident
from olympus.minerva.report import export_incident, load_incident


def test_export_and_load_round_trip_incident_only(tmp_path: Path) -> None:
    original_incident = open_incident("Suspicious brute force activity")
    output_path = tmp_path / "nested" / "incident.json"

    export_incident(original_incident, ChainOfCustody(), output_path)
    loaded_incident, loaded_chain = load_incident(output_path)

    assert loaded_incident == original_incident
    assert loaded_incident.schema_name == "olympus.incident"
    assert loaded_chain.entries == []


def test_export_and_load_round_trip_with_chain_of_custody(tmp_path: Path) -> None:
    incident = open_incident("Suspicious brute force activity")
    chain = ChainOfCustody()
    chain.append("Alert triaged", reference=incident.incident_id)
    chain.append("Evidence collected from auth log", reference="EVD-2026-00001")
    output_path = tmp_path / "incident.json"

    export_incident(incident, chain, output_path)
    _loaded_incident, loaded_chain = load_incident(output_path)

    assert len(loaded_chain.entries) == 2
    assert loaded_chain.entries == chain.entries
    assert loaded_chain.verify() is True


def test_load_incident_rejects_non_object_payload(tmp_path: Path) -> None:
    path = tmp_path / "incident.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a JSON object"):
        load_incident(path)
