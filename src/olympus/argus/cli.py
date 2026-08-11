"""Command-line interface for the Argus module."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.argus.ct import CrtShClient, CtQueryError, enumerate_subdomains
from olympus.argus.recon import scan_domain
from olympus.argus.resolver import DnspythonResolver
from olympus.argus.scope import OutOfScopeError, ScopeError, enforce_scope

app = typer.Typer(
    help="Argus — OSINT & passive recon.",
    no_args_is_help=True,
)

DEFAULT_SCOPE_PATH = Path("examples/input/argus-scope.json")
DEFAULT_BLOCK_LOG_PATH = Path("examples/output/argus-blocked.log")


@app.command()
def scan(
    domain: str = typer.Option(..., "--domain", help="Domain to run passive DNS recon against."),
    scope: Path = typer.Option(
        DEFAULT_SCOPE_PATH,
        "--scope",
        help="Path to the JSON scope file listing authorized domains.",
    ),
    log: Path = typer.Option(
        DEFAULT_BLOCK_LOG_PATH,
        "--log",
        help="Path to the out-of-scope audit log.",
    ),
) -> None:
    """Run passive DNS/MX/SPF/DMARC recon against a single in-scope domain."""
    try:
        enforce_scope(domain, scope, log)
    except ScopeError as exc:
        typer.echo(f"argus: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    dns_result = scan_domain(domain, DnspythonResolver())

    subdomains: list[str] = []
    try:
        subdomains = enumerate_subdomains(domain, CrtShClient()).subdomains
    except CtQueryError as exc:
        # CT lookup is an auxiliary, best-effort source: a network hiccup or
        # a blocked egress must not fail the whole (otherwise valid) DNS scan.
        typer.echo(f"argus: warning: certificate transparency lookup failed: {exc}", err=True)

    output = dns_result.to_dict()
    output["subdomains"] = subdomains
    typer.echo(json.dumps(output, indent=2, sort_keys=True))


@app.command()
def demo() -> None:
    """Run a self-contained demo on the synthetic 'Olympus Demo Corp' dataset."""
    # NOTE: scaffold only. The development loop implements this command.
    typer.echo("argus: demo not implemented yet (scaffold).")
