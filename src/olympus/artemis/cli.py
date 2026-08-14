"""Command-line interface for scope-safe Artemis web reconnaissance."""

from __future__ import annotations

from pathlib import Path

import typer

from olympus.artemis.scope import OutOfScopeError, ScopeError, enforce_scope

app = typer.Typer(help="Artemis — authorized web reconnaissance.", no_args_is_help=True)
DEFAULT_SCOPE = Path("examples/input/artemis-scope.json")
DEFAULT_LOG = Path("examples/output/artemis-blocked.log")


@app.command("check-scope")
def check_scope(
    url: str = typer.Option(..., "--url"),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
) -> None:
    """Validate URL authorization without performing a network request."""
    try:
        approved = enforce_scope(url, scope, log)
    except ScopeError as exc:
        typer.echo(f"artemis: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"artemis: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    typer.echo(f"artemis: authorized {approved.url} (no network request performed)")


@app.command()
def demo() -> None:
    """Validate a synthetic Olympus Demo Corp URL without network access."""
    approved = enforce_scope(
        "https://portal.olympusdemocorp.example/app/login",
        DEFAULT_SCOPE,
        DEFAULT_LOG,
    )
    typer.echo(f"artemis: demo authorized {approved.url}; zero network requests")
