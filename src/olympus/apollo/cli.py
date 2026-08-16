"""Command-line interface for Apollo detection testing."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from pydantic import ValidationError

from olympus.apollo.engine import evaluate, evaluate_stream
from olympus.apollo.export import export_alerts
from olympus.apollo.rules import load_rule, load_rules
from olympus.core.models import Event
from olympus.core.output import OutputFormat, render

app = typer.Typer(help="Apollo — detection engineering and testing.", no_args_is_help=True)
DEFAULT_OUTPUT = Path("examples/output/apollo-alerts.json")
DEFAULT_RULES_DIR = Path("examples/input/apollo-ad")


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


@app.command()
def run(
    rules: Path = typer.Option(DEFAULT_RULES_DIR, "--rules", help="Directory of YAML rules."),
    events: Path = typer.Option(..., "--events", help="NDJSON file: one core.Event per line."),
    output: Path = typer.Option(DEFAULT_OUTPUT, "--output", help="Alerts JSON output."),
) -> None:
    """Evaluate a whole rule set against a stream of events (NDJSON)."""
    try:
        rule_set = load_rules(rules)
    except (OSError, ValueError) as exc:
        typer.echo(f"apollo: rule error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    parsed: list[Event] = []
    for number, line in enumerate(events.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            parsed.append(Event.model_validate_json(line))
        except (ValueError, ValidationError) as exc:
            typer.echo(f"apollo: skipping malformed event on line {number}: {exc}", err=True)

    alerts = evaluate_stream(rule_set, parsed)
    export_alerts(alerts, output)
    typer.echo(
        f"apollo: {len(rule_set)} rule(s) x {len(parsed)} event(s) -> {len(alerts)} alert(s); "
        f"{output}"
    )
    if alerts:
        raise typer.Exit(code=1)


@app.command()
def rules(
    directory: Path = typer.Option(DEFAULT_RULES_DIR, "--rules", help="Directory of YAML rules."),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render as table (human) or json (machine)."
    ),
) -> None:
    """Load and validate a rule directory, listing every rule."""
    try:
        rule_set = load_rules(directory)
    except (OSError, ValueError) as exc:
        typer.echo(f"apollo: rule error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    records: list[dict[str, object]] = [
        {
            "rule_id": r.rule_id,
            "event_type": r.event_type,
            "severity": r.severity.value,
            "mitre": ",".join(r.mitre_attack),
            "title": r.title,
        }
        for r in rule_set
    ]
    columns = ["rule_id", "event_type", "severity", "mitre", "title"]
    typer.echo(render(records, columns, output_format, title=f"Apollo rules ({len(rule_set)})"))
