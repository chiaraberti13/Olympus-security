"""Command-line interface for the Helios module."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.helios.alerts import build_alerts
from olympus.helios.findings import build_findings, export_findings
from olympus.helios.recon import scan_host
from olympus.helios.scanner import TcpConnectScanner
from olympus.helios.scope import OutOfScopeError, ScopeError, enforce_scope

app = typer.Typer(
    help="Helios — Authorized network attack-surface mapper.",
    no_args_is_help=True,
)

DEFAULT_SCOPE_PATH = Path("examples/input/helios-scope.json")
DEFAULT_BLOCK_LOG_PATH = Path("examples/output/helios-blocked.log")


@app.command()
def scan(
    target: str = typer.Option(..., "--target", help="Host or IP to scan for open ports."),
    scope: Path = typer.Option(
        DEFAULT_SCOPE_PATH,
        "--scope",
        help="Path to the JSON scope file listing authorized targets.",
    ),
    log: Path = typer.Option(
        DEFAULT_BLOCK_LOG_PATH,
        "--log",
        help="Path to the out-of-scope audit log.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="If set, also export the scan as core.Asset/Finding JSON to this path.",
    ),
) -> None:
    """Scan a single in-scope host for open common ports (plain TCP connect)."""
    try:
        enforce_scope(target, scope, log)
    except ScopeError as exc:
        typer.echo(f"helios: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"helios: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    result = scan_host(target, TcpConnectScanner())
    typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))

    if output is not None:
        assets, findings = build_findings([result])
        alerts = build_alerts(findings)
        export_findings(assets, findings, output, alerts=alerts)
        typer.echo(
            f"helios: wrote {len(findings)} finding(s), {len(alerts)} alert(s) to {output}",
            err=True,
        )


@app.command()
def demo() -> None:
    """Run a self-contained demo on the synthetic 'Olympus Demo Corp' dataset."""
    # NOTE: scaffold only. The development loop implements this command.
    typer.echo("helios: demo not implemented yet (scaffold).")
