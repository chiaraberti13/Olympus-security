"""Command-line interface for scope-safe Artemis web reconnaissance."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.artemis.http import HttpClientError, HttpResponse, UrllibTransport, fetch_scoped
from olympus.artemis.scope import OutOfScopeError, ScopeError, enforce_scope

app = typer.Typer(help="Artemis — authorized web reconnaissance.", no_args_is_help=True)
DEFAULT_SCOPE = Path("examples/input/artemis-scope.json")
DEFAULT_LOG = Path("examples/output/artemis-blocked.log")


@app.command()
def fetch(
    url: str = typer.Option(..., "--url"),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    timeout: float = typer.Option(5.0, "--timeout"),
    max_bytes: int = typer.Option(1_000_000, "--max-bytes"),
) -> None:
    """Perform one bounded, scope-safe GET flow and print metadata only."""
    try:
        result = fetch_scoped(
            url, scope, log, UrllibTransport(), timeout=timeout, max_bytes=max_bytes
        )
    except (ScopeError, OutOfScopeError, HttpClientError, ValueError) as exc:
        typer.echo(f"artemis: fetch blocked or failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    metadata = {
        "body_bytes": len(result.response.body),
        "final_url": result.response.url,
        "redirects": result.redirects,
        "status": result.response.status,
    }
    typer.echo(json.dumps(metadata, indent=2, sort_keys=True))


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
    """Run a redirecting synthetic GET flow using an offline transport."""
    class DemoTransport:
        def get(self, url: str, timeout: float, max_bytes: int) -> HttpResponse:
            del timeout, max_bytes
            if url.endswith("/app/login"):
                return HttpResponse(url, 302, {"location": "/app/home"}, b"")
            return HttpResponse(url, 200, {"content-type": "text/html"}, b"<h1>Demo</h1>")

    result = fetch_scoped(
        "https://portal.olympusdemocorp.example/app/login",
        DEFAULT_SCOPE,
        DEFAULT_LOG,
        DemoTransport(),
    )
    typer.echo(
        f"artemis: demo fetched {result.response.status} via {len(result.redirects)} "
        "scoped redirect(s); offline transport"
    )
