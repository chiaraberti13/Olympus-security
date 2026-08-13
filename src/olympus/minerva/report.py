"""Export/import an incident report: the Incident plus its chain of custody.

The chain of custody is dataclass-based (not a Pydantic model, see
custody.py) so it needs its own, explicit JSON conversion rather than
`model_dump_json`.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from olympus.core.models import Incident
from olympus.minerva.custody import ChainOfCustody, CustodyEntry


def _entry_to_dict(entry: CustodyEntry) -> dict[str, Any]:
    data = asdict(entry)
    data["recorded_at"] = entry.recorded_at.isoformat()
    return data


def _entry_from_dict(data: dict[str, Any]) -> CustodyEntry:
    return CustodyEntry(
        sequence=data["sequence"],
        description=data["description"],
        reference=data["reference"],
        recorded_at=datetime.fromisoformat(data["recorded_at"]),
        previous_hash=data["previous_hash"],
        entry_hash=data["entry_hash"],
    )


def export_incident(incident: Incident, chain: ChainOfCustody, path: Path) -> None:
    """Write ``incident``/``chain`` as a JSON object conforming to core models."""
    payload = {
        "incident": json.loads(incident.model_dump_json()),
        "chain_of_custody": [_entry_to_dict(entry) for entry in chain.entries],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_incident(path: Path) -> tuple[Incident, ChainOfCustody]:
    """Read and validate a previously exported incident report."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a JSON object with 'incident'/'chain_of_custody'")
    incident = Incident.model_validate(raw["incident"])
    chain = ChainOfCustody(
        entries=[_entry_from_dict(item) for item in raw.get("chain_of_custody", [])]
    )
    return incident, chain
