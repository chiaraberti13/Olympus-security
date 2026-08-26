"""Command-line surface for METIS capability routing and CTI cases."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import typer

from olympus.core.fileio import atomic_write_text
from olympus.metis.cases import CaseStore, export_report
from olympus.metis.catalog import CAPABILITIES, recommend
from olympus.metis.labs import LABS
from olympus.metis.planner import build_plan

app = typer.Typer(
    help="Deterministic planning, capability routing and CTI casework.", no_args_is_help=True
)
case_app = typer.Typer(help="Local-first cyber threat-intelligence cases.", no_args_is_help=True)


def _fail(exc: Exception) -> None:
    typer.echo(f"metis: {exc}", err=True)
    raise typer.Exit(code=2) from exc


@app.command("capabilities")
def capabilities(
    as_json: bool = typer.Option(False, "--json", help="Emit the strict catalog as JSON."),
) -> None:
    """List the independently implemented Olympus capability catalog."""
    if as_json:
        typer.echo(json.dumps([item.model_dump(mode="json") for item in CAPABILITIES], indent=2))
        return
    for item in CAPABILITIES:
        gate = "authorization" if item.requires_authorization else "ready"
        typer.echo(f"{item.capability_id:32} {item.mode.value:8} {gate:13} {item.title}")


@app.command("recommend")
def recommend_command(
    task: str = typer.Argument(..., help="Free-form security objective."),
    limit: int = typer.Option(5, min=1, max=20),
    advisory_only: bool = typer.Option(
        False, "--advisory-only", help="Exclude active-execution capabilities."
    ),
) -> None:
    """Route an objective to the best matching local capabilities."""
    try:
        results = recommend(task, limit=limit, include_active=not advisory_only)
    except ValueError as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            [
                {
                    "capability_id": item.capability.capability_id,
                    "title": item.capability.title,
                    "score": item.score,
                    "matched_terms": item.matched_terms,
                    "mode": item.capability.mode.value,
                    "noise": item.capability.noise.value,
                    "requires_authorization": item.capability.requires_authorization,
                    "commands": item.capability.commands,
                }
                for item in results
            ],
            indent=2,
        )
    )


@app.command("plan")
def plan_command(
    objective: str = typer.Argument(..., help="Security objective to plan."),
    scope: list[str] | None = typer.Option(
        None, "--scope", help="Authorized scope entry; repeatable."
    ),
    include_active: bool = typer.Option(False, help="Include active capabilities in the plan."),
    authorized: bool = typer.Option(
        False,
        "--i-am-authorized",
        help="Confirm documented authorization for the supplied scope.",
    ),
    output: Path | None = typer.Option(None, help="Owner-only JSON output path."),
) -> None:
    """Build a safe, non-executing engagement plan."""
    try:
        plan = build_plan(
            objective,
            scope=tuple(scope or ()),
            authorization_confirmed=authorized,
            include_active=include_active,
        )
    except (ValueError, AssertionError) as exc:
        _fail(exc)
    payload = plan.model_dump_json(indent=2) + "\n"
    if output is None:
        typer.echo(payload, nl=False)
    else:
        atomic_write_text(output, payload, mode=0o600)
        typer.echo(str(output))


@app.command("labs")
def labs_command(
    level: str | None = typer.Option(None, help="foundation, beginner, intermediate or advanced."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List safe guided labs built from native Olympus capabilities."""
    if level is not None and level not in {"foundation", "beginner", "intermediate", "advanced"}:
        _fail(ValueError("level must be foundation, beginner, intermediate, or advanced"))
    selected = [item for item in LABS if level is None or item.level == level]
    if as_json:
        typer.echo(json.dumps([item.__dict__ for item in selected], indent=2))
        return
    for item in selected:
        typer.echo(f"{item.lab_id:34} {item.level:12} {item.title}")


@case_app.command("init")
def case_init(database: Path = typer.Argument(..., help="SQLite case database.")) -> None:
    """Initialize or verify an owner-only case database."""
    try:
        with CaseStore(database):
            pass
    except (OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(str(database))


@case_app.command("create")
def case_create(
    database: Path = typer.Argument(...),
    title: str = typer.Argument(...),
) -> None:
    """Create a new CTI case and print its stable identifier."""
    try:
        with CaseStore(database) as store:
            case_id = store.create_case(title)
    except (ValueError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(case_id)


@case_app.command("ingest")
def case_ingest(
    database: Path = typer.Argument(...),
    case_id: str = typer.Argument(...),
    evidence: Path = typer.Argument(...),
    source: str = typer.Option(..., help="Analyst-visible evidence provenance."),
    confidence: int = typer.Option(50, min=0, max=100),
) -> None:
    """Extract normalized indicators from one bounded local evidence file."""
    try:
        with CaseStore(database) as store:
            count = store.ingest_file(case_id, evidence, source=source, confidence=confidence)
    except (ValueError, LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(json.dumps({"case_id": case_id, "inserted": count}))


@case_app.command("finding")
def case_finding(
    database: Path = typer.Argument(...),
    case_id: str = typer.Argument(...),
    title: str = typer.Option(...),
    assessment: str = typer.Option(...),
    source: str = typer.Option(...),
    confidence: int = typer.Option(..., min=0, max=100),
    indicator: list[str] | None = typer.Option(
        None, "--indicator", help="Linked IOC ID; repeatable."
    ),
) -> None:
    """Record a sourced analytic finding and optional IOC links."""
    try:
        with CaseStore(database) as store:
            finding_id = store.add_finding(
                case_id,
                title=title,
                assessment=assessment,
                source=source,
                confidence=confidence,
                indicator_ids=tuple(indicator or ()),
            )
    except (ValueError, LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(finding_id)


@case_app.command("show")
def case_show(database: Path = typer.Argument(...), case_id: str = typer.Argument(...)) -> None:
    """Print one strict, portable CTI case document."""
    try:
        with CaseStore(database) as store:
            document = store.load_case(case_id)
    except (LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(document.model_dump_json(indent=2))


@case_app.command("report")
def case_report(
    database: Path = typer.Argument(...),
    case_id: str = typer.Argument(...),
    output: Path = typer.Argument(...),
    format: str = typer.Option("markdown", help="markdown or json."),
) -> None:
    """Export an owner-only CTI case report."""
    try:
        with CaseStore(database) as store:
            document = store.load_case(case_id)
        export_report(document, output, format=format)
    except (ValueError, LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(str(output))


app.add_typer(case_app, name="case")
