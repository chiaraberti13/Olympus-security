"""Command-line interface for the Proteus module."""

from __future__ import annotations

from pathlib import Path

import typer

from olympus.proteus.campaign import Recipient, simulate_campaign
from olympus.proteus.report import build_report, export_report
from olympus.proteus.scope import filter_in_scope
from olympus.proteus.training_page import render_training_page

app = typer.Typer(
    help="Proteus — Authorized phishing simulation.",
    no_args_is_help=True,
)

DEMO_SCOPE_PATH = Path("examples/input/proteus-scope.json")
DEMO_BLOCK_LOG_PATH = Path("examples/output/proteus-blocked.log")
DEMO_REPORT_PATH = Path("examples/output/proteus-report.json")
DEMO_TRAINING_PAGE_PATH = Path("examples/output/proteus-training-page.html")
DEMO_CAMPAIGN_NAME = "Olympus Demo Corp Q3 Awareness Campaign"
# One recipient (eve@evil.com) is intentionally out of scope, to demonstrate blocking.
DEMO_RECIPIENTS: tuple[str, ...] = (
    "alice@olympusdemocorp.example",
    "bob@olympusdemocorp.example",
    "carol@olympusdemocorp.example",
    "dave@olympusdemocorp.example",
    "eve@evil.com",
)


@app.command()
def demo() -> None:
    """Run the full Proteus pipeline on a synthetic 'Olympus Demo Corp' campaign.

    Fully offline and deterministic: no email is ever sent, no network
    call is made, and no credential is ever requested or collected. Scope
    enforcement, campaign simulation, training-page rendering and report
    export are all the real production code path (T-161..T-164).
    """
    typer.echo(f"proteus: demo — {DEMO_CAMPAIGN_NAME}")

    in_scope, blocked = filter_in_scope(list(DEMO_RECIPIENTS), DEMO_SCOPE_PATH, DEMO_BLOCK_LOG_PATH)
    if blocked:
        typer.echo(f"proteus: blocked {len(blocked)} out-of-scope recipient(s): {blocked}")

    recipients = [Recipient(email=email) for email in in_scope]
    results = simulate_campaign(recipients, click_rate=0.5, seed=42)
    clicked = sum(1 for result in results if result.clicked)
    typer.echo(f"proteus: simulated {len(results)} recipient(s), {clicked} clicked")

    DEMO_TRAINING_PAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEMO_TRAINING_PAGE_PATH.write_text(render_training_page(DEMO_CAMPAIGN_NAME), encoding="utf-8")
    typer.echo(f"proteus: wrote training page to {DEMO_TRAINING_PAGE_PATH}")

    assets, findings = build_report(DEMO_CAMPAIGN_NAME, results)
    export_report(DEMO_CAMPAIGN_NAME, assets, findings, DEMO_REPORT_PATH)
    typer.echo(f"proteus: wrote campaign report ({len(findings)} clicked) to {DEMO_REPORT_PATH}")
