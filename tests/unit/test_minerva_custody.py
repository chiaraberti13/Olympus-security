"""Unit tests for Minerva's hash-chained chain-of-custody log."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

from olympus.minerva.custody import GENESIS_HASH, ChainOfCustody, CustodyEntry


def test_empty_chain_verifies_trivially() -> None:
    assert ChainOfCustody().verify() is True


def test_first_entry_chains_to_genesis_hash() -> None:
    chain = ChainOfCustody()
    entry = chain.append("Disk image acquired", reference="EVD-2026-00001")

    assert entry.sequence == 0
    assert entry.previous_hash == GENESIS_HASH
    assert entry.entry_hash != GENESIS_HASH
    assert chain.verify() is True


def test_multiple_entries_form_a_valid_chain() -> None:
    chain = ChainOfCustody()
    first = chain.append("Disk image acquired", reference="EVD-2026-00001")
    second = chain.append("Image hashed with SHA-256", reference="EVD-2026-00002")
    third = chain.append("Image transferred to analyst", reference="EVD-2026-00003")

    assert second.previous_hash == first.entry_hash
    assert third.previous_hash == second.entry_hash
    assert chain.verify() is True


def test_tampering_with_an_entry_content_is_detected() -> None:
    chain = ChainOfCustody()
    chain.append("Disk image acquired", reference="EVD-2026-00001")
    chain.append("Image hashed with SHA-256", reference="EVD-2026-00002")
    assert chain.verify() is True

    # Simulate an attacker editing the log's description in place without
    # recomputing the stored hash (the realistic tamper scenario).
    tampered = dataclasses.replace(chain.entries[0], description="Nothing happened here")
    chain.entries[0] = tampered

    assert chain.verify() is False


def test_tampering_with_entry_order_is_detected() -> None:
    chain = ChainOfCustody()
    chain.append("Disk image acquired", reference="EVD-2026-00001")
    chain.append("Image hashed with SHA-256", reference="EVD-2026-00002")

    chain.entries[0], chain.entries[1] = chain.entries[1], chain.entries[0]

    assert chain.verify() is False


def test_tampering_with_entry_hash_directly_is_detected() -> None:
    chain = ChainOfCustody()
    chain.append("Disk image acquired", reference="EVD-2026-00001")

    forged = dataclasses.replace(chain.entries[0], entry_hash="f" * 64)
    chain.entries[0] = forged

    assert chain.verify() is False


def test_append_accepts_explicit_timestamp() -> None:
    chain = ChainOfCustody()
    when = datetime(2026, 8, 4, 9, 0, 0, tzinfo=UTC)
    entry = chain.append("Evidence collected", reference="EVD-2026-00001", recorded_at=when)

    assert entry.recorded_at == when
    assert chain.verify() is True


def test_custody_entry_is_frozen() -> None:
    entry = CustodyEntry(
        sequence=0,
        description="x",
        reference="EVD-2026-00001",
        recorded_at=datetime.now(UTC),
        previous_hash=GENESIS_HASH,
        entry_hash="a" * 64,
    )
    with_replacement = dataclasses.replace(entry, description="y")
    assert with_replacement.description == "y"
    assert entry.description == "x"
