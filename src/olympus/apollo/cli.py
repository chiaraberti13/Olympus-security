"""Command-line interface for the Apollo module."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import typer
from pydantic import BaseModel

from olympus.apollo.alerting import generate_alerts
from olympus.apollo.demo_data import demo_events
from olympus.apollo.rules import RuleError, load_rules
from olympus.apollo.testing import LabeledEvent, run_rule_tests
from olympus.core.models import Alert

app = typer.Typer(
    help="Apollo — Detection engineering (SIEM-lite).",
    no_args_is_help=True,
)

DEMO_RULES_DIR = Path("examples/input/apollo-rules")
DEMO_EVENTS_OUTPUT_PATH = Path("examples/output/apollo-events.json")
DEMO_ALERTS_OUTPUT_PATH = Path("examples/output/apollo-alerts.json")


def _write_json(items: Sequence[BaseModel], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [json.loads(item.model_dump_json()) for item in items]
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


@app.command()
def demo() -> None:
    """Run the full Apollo pipeline on synthetic 'Olympus Demo Corp' events.

    Loads the real YAML rule(s) under ``examples/input/apollo-rules``,
    matches them against a small synthetic authentication log, generates
    Alerts with evidence linking, and runs each rule's labeled detection
    tests -- the real production code path (T-131..T-134), fully offline.
    """
    typer.echo(f"apollo: demo — loading rules from {DEMO_RULES_DIR}")
    try:
        rules = load_rules(DEMO_RULES_DIR)
    except RuleError as exc:
        typer.echo(f"apollo: rule error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    events = demo_events()
    _write_json(events, DEMO_EVENTS_OUTPUT_PATH)
    typer.echo(f"apollo: wrote {len(events)} synthetic event(s) to {DEMO_EVENTS_OUTPUT_PATH}")

    all_alerts: list[Alert] = []
    for rule in rules:
        alerts = generate_alerts(rule, events)
        all_alerts.extend(alerts)
        typer.echo(f"apollo: rule {rule.rule_id} ({rule.name}) matched {len(alerts)} event(s)")

        # Illustrative detection test: the demo's first event is a known
        # brute-force attempt, the fourth a known successful login.
        cases = [
            LabeledEvent(events[0], should_match=True, label="known brute-force attempt"),
            LabeledEvent(events[3], should_match=False, label="known successful login"),
        ]
        report = run_rule_tests(rule, cases)
        status = "PASS" if report.passed else "FAIL"
        typer.echo(f"apollo: detection test for {rule.rule_id}: {status}")

    _write_json(all_alerts, DEMO_ALERTS_OUTPUT_PATH)
    typer.echo(f"apollo: wrote {len(all_alerts)} alert(s) to {DEMO_ALERTS_OUTPUT_PATH}")
