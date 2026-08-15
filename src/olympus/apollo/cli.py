"""Command-line interface for Apollo detection testing."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from pydantic import ValidationError

from olympus.apollo.engine import evaluate
from olympus.apollo.export import export_alerts
from olympus.apollo.rules import load_rule
from olympus.core.models import Event

app = typer.Typer(help="Apollo — detection engineering and testing.", no_args_is_help=True)
DEFAULT_OUTPUT = Path("examples/output/apollo-alerts.json")


@app.command()
def test(
    rule: Path,
    event: Path,
    output: Path = typer.Option(DEFAULT_OUTPUT, "--output"),
) -> None:
    """Evaluate one rule against one normalized Event fixture."""
    try:
        detection_rule = load_rule(rule)
        normalized_event = Event.model_validate_json(event.read_text(encoding="utf-8"))
    except (OSError, ValueError, ValidationError, json.JSONDecodeError) as exc:
        typer.echo(f"apollo: invalid input: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    alerts = evaluate([detection_rule], normalized_event)
    export_alerts(alerts, output)
    typer.echo(f"apollo: {len(alerts)} alert(s); output: {output}")


