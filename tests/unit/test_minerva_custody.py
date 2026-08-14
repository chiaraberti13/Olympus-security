"""Tests for Minerva's tamper-evident evidence custody ledger."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.models import Evidence
from olympus.minerva import cli as minerva_cli
from olympus.minerva.custody import (
    CustodyAction,
    CustodyIntegrityError,
    append_entry,
    load_ledger,
)

runner = CliRunner()


def _evidence() -> Evidence:
    return Evidence(
        evidence_id="EVD-2026-00001",
        evidence_type="memory-image",
        uri="file://olympus-demo/memory.raw",
        sha256="a" * 64,
    )


def test_append_and_load_verified_chain(tmp_path: Path) -> None:
    ledger = tmp_path / "custody.json"
    started = datetime(2026, 8, 14, 9, tzinfo=UTC)
    first = append_entry(ledger, _evidence(), CustodyAction.COLLECTED, "responder", started)
    second = append_entry(
        ledger,
        _evidence(),
        CustodyAction.TRANSFERRED,
        "forensics",
        started + timedelta(minutes=30),
    )

    assert first.sequence == 1
    assert second.previous_hash == first.entry_hash
    assert load_ledger(ledger) == [first, second]


def test_tampering_is_detected_before_append(tmp_path: Path) -> None:
    ledger = tmp_path / "custody.json"
    append_entry(ledger, _evidence(), CustodyAction.COLLECTED, "responder")
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    payload["entries"][0]["actor"] = "attacker"
    ledger.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(CustodyIntegrityError, match="hash mismatch"):
        load_ledger(ledger)
    with pytest.raises(CustodyIntegrityError):
        append_entry(ledger, _evidence(), CustodyAction.ANALYZED, "analyst")


def test_regressive_timestamp_is_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "custody.json"
    later = datetime(2026, 8, 14, 10, tzinfo=UTC)
    append_entry(ledger, _evidence(), CustodyAction.COLLECTED, "responder", later)
    with pytest.raises(CustodyIntegrityError, match="timestamps"):
        append_entry(
            ledger,
            _evidence(),
            CustodyAction.TRANSFERRED,
            "forensics",
            later - timedelta(hours=1),
        )
    assert len(load_ledger(ledger)) == 1


def test_demo_and_verify_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = tmp_path / "demo-custody.json"
    monkeypatch.setattr(minerva_cli, "DEFAULT_LEDGER", ledger)

    demo = runner.invoke(app, ["minerva", "demo"])
    verified = runner.invoke(app, ["minerva", "verify", str(ledger)])

    assert demo.exit_code == 0
    assert "2 synthetic entries" in demo.stdout
    assert verified.exit_code == 0
    assert "2 entries" in verified.stdout
