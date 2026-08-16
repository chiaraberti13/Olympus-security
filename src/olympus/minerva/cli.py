"""Command-line interface for Minerva incident response workflows."""

from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError

from olympus.core.models import Evidence
from olympus.core.output import OutputFormat, render
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
def timeline(
    ledger: Path,
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render as table (human) or json (machine)."
    ),
) -> None:
    """Print the chain-of-custody timeline of a verified ledger, in order."""
    try:
        entries = load_ledger(ledger)
    except (OSError, ValidationError, CustodyIntegrityError) as exc:
        typer.echo(f"minerva: custody integrity failure: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    records: list[dict[str, object]] = [
        {
            "seq": entry.sequence,
            "occurred_at": entry.occurred_at.isoformat(),
            "action": entry.action.value,
            "actor": entry.actor,
            "evidence_id": entry.evidence_id,
        }
        for entry in entries
    ]
    columns = ["seq", "occurred_at", "action", "actor", "evidence_id"]
    typer.echo(render(records, columns, output_format, title=f"Custody timeline ({len(entries)})"))
