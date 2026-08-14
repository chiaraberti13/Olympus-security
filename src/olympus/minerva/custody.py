"""Tamper-evident chain of custody for DFIR evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from olympus.core.models import Evidence

GENESIS_HASH = "0" * 64


class CustodyAction(StrEnum):
    """Allowed evidence custody transitions."""

    COLLECTED = "collected"
    TRANSFERRED = "transferred"
    ANALYZED = "analyzed"
    ARCHIVED = "archived"


class CustodyEntry(BaseModel):
    """One immutable, hash-linked custody event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int = Field(ge=1)
    evidence_id: str = Field(pattern=r"^EVD-\d{4}-\d{5}$")
    action: CustodyAction
    actor: str = Field(min_length=1, max_length=200)
    occurred_at: datetime
    previous_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    entry_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class CustodyIntegrityError(ValueError):
    """Raised when a ledger is malformed or its hash chain is invalid."""


def _entry_hash(
    sequence: int,
    evidence_id: str,
    action: CustodyAction,
    actor: str,
    occurred_at: datetime,
    previous_hash: str,
) -> str:
    payload = {
        "action": action.value,
        "actor": actor,
        "evidence_id": evidence_id,
        "occurred_at": occurred_at.isoformat(),
        "previous_hash": previous_hash,
        "sequence": sequence,
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_entries(entries: list[CustodyEntry]) -> None:
    """Validate ordering, timestamps and every hash link in a custody chain."""
    previous_hash = GENESIS_HASH
    previous_time: datetime | None = None
    for expected_sequence, entry in enumerate(entries, 1):
        expected_hash = _entry_hash(
            entry.sequence,
            entry.evidence_id,
            entry.action,
            entry.actor,
            entry.occurred_at,
            entry.previous_hash,
        )
        if entry.sequence != expected_sequence:
            raise CustodyIntegrityError("custody sequence is not contiguous")
        if entry.previous_hash != previous_hash or entry.entry_hash != expected_hash:
            raise CustodyIntegrityError(f"custody hash mismatch at sequence {entry.sequence}")
        if previous_time is not None and entry.occurred_at < previous_time:
            raise CustodyIntegrityError("custody timestamps are not monotonic")
        previous_hash = entry.entry_hash
        previous_time = entry.occurred_at


def load_ledger(path: Path) -> list[CustodyEntry]:
    """Load and verify a ledger, returning an empty chain when it does not exist."""
    if not path.exists():
        return []
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_name") != "olympus.custody":
            raise CustodyIntegrityError("invalid custody document")
        entries = [CustodyEntry.model_validate(item) for item in payload["entries"]]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise CustodyIntegrityError(f"invalid custody document: {exc}") from exc
    verify_entries(entries)
    return entries


def append_entry(
    ledger: Path,
    evidence: Evidence,
    action: CustodyAction,
    actor: str,
    occurred_at: datetime | None = None,
) -> CustodyEntry:
    """Verify the existing ledger, append one event and replace the file atomically."""
    entries = load_ledger(ledger)
    timestamp = occurred_at or datetime.now(UTC)
    sequence = len(entries) + 1
    previous_hash = entries[-1].entry_hash if entries else GENESIS_HASH
    entry = CustodyEntry(
        sequence=sequence,
        evidence_id=evidence.evidence_id,
        action=action,
        actor=actor,
        occurred_at=timestamp,
        previous_hash=previous_hash,
        entry_hash=_entry_hash(
            sequence, evidence.evidence_id, action, actor, timestamp, previous_hash
        ),
    )
    entries.append(entry)
    verify_entries(entries)
    payload = {
        "schema_name": "olympus.custody",
        "schema_version": "1.0.0",
        "entries": [item.model_dump(mode="json") for item in entries],
    }
    ledger.parent.mkdir(parents=True, exist_ok=True)
    temporary = ledger.with_suffix(f"{ledger.suffix}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(ledger)
    return entry
