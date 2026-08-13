"""Command-line interface for the Minerva module."""

from __future__ import annotations

from pathlib import Path

import typer

from olympus.core.enums import IncidentStatus
from olympus.minerva.custody import ChainOfCustody
from olympus.minerva.demo_data import demo_alerts, demo_findings
from olympus.minerva.incident import open_incident
from olympus.minerva.lifecycle import transition
from olympus.minerva.report import export_incident

app = typer.Typer(
    help="Minerva — Incident response & triage (DFIR).",
    no_args_is_help=True,
)

DEMO_OUTPUT_PATH = Path("examples/output/minerva-incident.json")

_DEMO_LIFECYCLE: tuple[IncidentStatus, ...] = (
    IncidentStatus.TRIAGED,
    IncidentStatus.CONTAINED,
    IncidentStatus.RESOLVED,
    IncidentStatus.CLOSED,
)


@app.command()
def demo() -> None:
    """Run the full Minerva pipeline on a synthetic 'Olympus Demo Corp' incident.

    Opens an incident from a synthetic Apollo alert + Helios finding, walks
    it through the full response lifecycle while recording each step in a
    hash-chained chain of custody, then exports the report -- the real
    production code path (T-151..T-154), fully offline.
    """
    typer.echo("minerva: demo — opening an incident from synthetic alerts/findings")

    incident = open_incident(
        "Suspicious authentication activity on the Olympus Demo Corp perimeter",
        alerts=demo_alerts(),
        findings=demo_findings(),
        description="Brute-force alert correlated with an exposed high-risk service.",
    )
    typer.echo(f"minerva: opened {incident.incident_id} (severity={incident.severity.value})")

    chain = ChainOfCustody()
    chain.append(
        "Incident opened from Apollo alert + Helios finding", reference=incident.incident_id
    )

    for target_status in _DEMO_LIFECYCLE:
        incident = transition(incident, target_status)
        chain.append(f"Incident moved to {target_status.value}", reference=incident.incident_id)
        typer.echo(f"minerva: {incident.incident_id} -> {target_status.value}")

    typer.echo(f"minerva: chain of custody verified: {chain.verify()}")

    export_incident(incident, chain, DEMO_OUTPUT_PATH)
    typer.echo(f"minerva: wrote incident report to {DEMO_OUTPUT_PATH}")
