"""Command-line interface for the Proteus module."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.proteus.campaign import (
    build_campaign,
    campaign_report,
    export_campaign,
    load_campaign,
    render_email,
    render_training_page,
)
from olympus.proteus.scope import (
    ProteusOutOfScopeError,
    ProteusScopeError,
)

app = typer.Typer(
    help="Proteus — Authorized phishing simulation (training only).",
    no_args_is_help=True,
)

DEFAULT_SCOPE = Path("examples/input/proteus-scope.json")
DEFAULT_LOG = Path("examples/output/proteus-blocked.log")

_DISCLAIMER = (
    "AUTHORIZED USE ONLY — a phishing simulation targets real people's inboxes. Run it only "
    "with documented authorization for the engagement. Proteus never collects credentials: "
    "clickers land on a training page. Re-run with --i-am-authorized to confirm."
)


def _read_lines(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


@app.command()
def campaign(
    engagement: str = typer.Option(..., "--engagement", help="Engagement name."),
    targets: Path = typer.Option(..., "--targets", help="File with one recipient email per line."),
    landing_url: str = typer.Option(..., "--landing-url", help="Base URL of the training page."),
    subject: str = typer.Option(
        "Action required: confirm your account", "--subject", help="Lure email subject."
    ),
    sender: str = typer.Option("it-support@example.com", "--sender", help="Lure sender address."),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope", help="Authorized email-domain allowlist."),
    log: Path = typer.Option(DEFAULT_LOG, "--log", help="Out-of-scope audit log."),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for the engagement."
    ),
    output: Path = typer.Option(
        Path("examples/output/proteus-campaign.json"), "--output", help="Campaign JSON output."
    ),
) -> None:
    """Build an authorized simulation campaign (unique token per in-scope target)."""
    if not i_am_authorized:
        typer.echo(f"proteus: {_DISCLAIMER}", err=True)
        raise typer.Exit(code=4)

    emails = _read_lines(targets)
    kept: list[str] = []
    for email in emails:
        try:
            build_campaign(engagement, [email], scope, log, subject=subject, sender=sender,
                           landing_url=landing_url)
        except ProteusScopeError as exc:
            typer.echo(f"proteus: scope error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        except ProteusOutOfScopeError:
            typer.echo(f"proteus: skipping out-of-scope target {email!r} (logged)", err=True)
            continue
        kept.append(email)

    built = build_campaign(engagement, kept, scope, log, subject=subject, sender=sender,
                           landing_url=landing_url)
    export_campaign(built, output)
    typer.echo(json.dumps(built.to_dict(), indent=2, sort_keys=True))
    typer.echo(
        f"proteus: campaign '{engagement}' built for {len(built.targets)} target(s); {output}",
        err=True,
    )


@app.command()
def page(
    engagement: str = typer.Option(..., "--engagement", help="Engagement name for the page."),
    output: Path = typer.Option(
        Path("examples/output/proteus-training.html"), "--output", help="Training-page HTML output."
    ),
) -> None:
    """Render the training/awareness page a clicker lands on (captures nothing)."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_training_page(engagement), encoding="utf-8")
    typer.echo(f"proteus: wrote training page to {output}")


@app.command()
def email(
    campaign_file: Path = typer.Option(
        ..., "--campaign", help="Campaign JSON from `proteus campaign`."
    ),
    token: str = typer.Option(..., "--token", help="Target token to render the lure email for."),
) -> None:
    """Render the simulated lure email for one target token."""
    built = load_campaign(campaign_file)
    for target in built.targets:
        if target.token == token:
            typer.echo(render_email(built, target))
            return
    typer.echo(f"proteus: no target with token {token!r} in campaign", err=True)
    raise typer.Exit(code=2)


@app.command()
def report(
    campaign_file: Path = typer.Option(
        ..., "--campaign", help="Campaign JSON from `proteus campaign`."
    ),
    clicked: list[str] = typer.Option(
        [], "--clicked", help="Token(s) recorded as clicked (repeatable)."
    ),
) -> None:
    """Summarize campaign click-through (a training metric, never secrets)."""
    built = load_campaign(campaign_file)
    summary = campaign_report(built, set(clicked))
    typer.echo(json.dumps(summary, indent=2, sort_keys=True))
