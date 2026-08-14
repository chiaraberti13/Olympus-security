"""Command-line interface for Minerva incident response workflows."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import typer
from pydantic import ValidationError

from olympus.core.models import Evidence
from olympus.minerva.custody import (
    CustodyAction,
    CustodyIntegrityError,
    append_entry,
    load_ledger,
)

app = typer.Typer(help="Minerva — incident response and DFIR.", no_args_is_help=True)
DEFAULT_LEDGER = Path("examples/output/minerva-custody.json")


@app.command()
def record(
    evidence: Path,
    ledger: Path,
    actor: str = typer.Option(..., "--actor"),
    action: CustodyAction = typer.Option(..., "--action"),
) -> None:
    """Append a custody event after verifying the complete existing chain."""
    try:
        item = Evidence.model_validate_json(evidence.read_text(encoding="utf-8"))
        entry = append_entry(ledger, item, action, actor)
    except (OSError, ValidationError, CustodyIntegrityError) as exc:
        typer.echo(f"minerva: custody error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"minerva: recorded custody sequence {entry.sequence}")


@app.command()
def verify(ledger: Path) -> None:
    """Verify every link in an existing custody ledger."""
    try:
        entries = load_ledger(ledger)
    except (OSError, ValidationError, CustodyIntegrityError) as exc:
        typer.echo(f"minerva: custody integrity failure: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"minerva: custody verified ({len(entries)} entries)")


@app.command()
def demo() -> None:
    """Create and verify an offline Olympus Demo Corp custody chain."""
    evidence = Evidence(
        evidence_id="EVD-2026-00001",
        evidence_type="memory-image",
        uri="file://olympus-demo/memory.raw",
        sha256="a" * 64,
    )
    started = datetime(2026, 8, 14, 9, tzinfo=UTC)
    DEFAULT_LEDGER.unlink(missing_ok=True)
    append_entry(DEFAULT_LEDGER, evidence, CustodyAction.COLLECTED, "demo-responder", started)
    append_entry(
        DEFAULT_LEDGER,
        evidence,
        CustodyAction.TRANSFERRED,
        "demo-forensics",
        started + timedelta(minutes=30),
    )
    entries = load_ledger(DEFAULT_LEDGER)
    typer.echo(f"minerva: demo custody verified ({len(entries)} synthetic entries)")
