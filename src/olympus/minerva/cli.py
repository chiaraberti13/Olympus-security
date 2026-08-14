"""Command-line interface for Minerva incident response workflows."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import typer
from pydantic import ValidationError

from olympus.core.enums import Severity, Source
from olympus.core.models import Alert, Evidence
from olympus.minerva.custody import (
    CustodyAction,
    CustodyIntegrityError,
    append_entry,
    load_ledger,
)
from olympus.minerva.triage import export_incident, load_alerts, triage_alerts

app = typer.Typer(help="Minerva — incident response and DFIR.", no_args_is_help=True)
DEFAULT_LEDGER = Path("examples/output/minerva-custody.json")
DEFAULT_INCIDENT = Path("examples/output/minerva-incident.json")


@app.command()
def triage(
    alerts: Path,
    output: Path = typer.Option(DEFAULT_INCIDENT, "--output"),
    title: str = typer.Option(..., "--title"),
    owner: str | None = typer.Option(None, "--owner"),
) -> None:
    """Create a normalized Incident from a validated Apollo alert export."""
    try:
        incident = triage_alerts(load_alerts(alerts), title, owner)
        export_incident(incident, output)
    except (OSError, ValueError, ValidationError) as exc:
        typer.echo(f"minerva: triage error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"minerva: incident {incident.incident_id} written to {output}")


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
    alert = Alert(
        alert_id="ALT-2026-00001",
        event_id="EVT-2026-00001",
        title="Olympus Demo encoded PowerShell",
        source=Source.APOLLO,
        severity=Severity.HIGH,
        evidence_ids=[evidence.evidence_id],
    )
    incident = triage_alerts(
        [alert], "Olympus Demo Corp suspicious process", owner="demo-soc"
    )
    export_incident(incident, DEFAULT_INCIDENT)
    typer.echo(
        f"minerva: demo custody verified ({len(entries)} synthetic entries); "
        f"incident {incident.incident_id} triaged"
    )
