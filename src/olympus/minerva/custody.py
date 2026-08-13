"""Chain-of-custody evidence log: append-only, hash-chained, tamper-evident.

Each entry's hash covers its own content plus the previous entry's hash,
so any modification to an earlier entry — content or ordering — breaks
the chain from that point forward. This is the same tamper-evidence
technique blockchains use, applied to a plain append-only list; no
consensus or distributed ledger needed for a single-investigator log.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class CustodyEntry:
    """One append-only chain-of-custody log entry."""

    sequence: int
    description: str
    reference: str
    recorded_at: datetime
    previous_hash: str
    entry_hash: str


def _compute_hash(
    sequence: int,
    description: str,
    reference: str,
    recorded_at: datetime,
    previous_hash: str,
) -> str:
    payload = json.dumps(
        {
            "sequence": sequence,
            "description": description,
            "reference": reference,
            "recorded_at": recorded_at.isoformat(),
            "previous_hash": previous_hash,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class ChainOfCustody:
    """An append-only, hash-chained sequence of custody entries."""

    entries: list[CustodyEntry] = field(default_factory=list)

    def append(
        self, description: str, reference: str, *, recorded_at: datetime | None = None
    ) -> CustodyEntry:
        """Append a new, tamper-evident entry to the chain."""
        sequence = len(self.entries)
        previous_hash = self.entries[-1].entry_hash if self.entries else GENESIS_HASH
        timestamp = recorded_at or datetime.now(UTC)
        entry_hash = _compute_hash(sequence, description, reference, timestamp, previous_hash)
        entry = CustodyEntry(
            sequence=sequence,
            description=description,
            reference=reference,
            recorded_at=timestamp,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        """Return ``True`` if every entry is internally consistent and correctly chained."""
        previous_hash = GENESIS_HASH
        for entry in self.entries:
            if entry.previous_hash != previous_hash:
                return False
            expected_hash = _compute_hash(
                entry.sequence,
                entry.description,
                entry.reference,
                entry.recorded_at,
                entry.previous_hash,
            )
            if entry.entry_hash != expected_hash:
                return False
            previous_hash = entry.entry_hash
        return True
