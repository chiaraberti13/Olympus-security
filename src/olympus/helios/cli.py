"""Command-line interface for authorized Helios surface discovery."""

from __future__ import annotations

from pathlib import Path

import typer

from olympus.helios.export import export_findings, to_findings
from olympus.helios.scanner import SocketConnector, discover
from olympus.helios.scope import OutOfScopeError, ScopeError, enforce_scope

app = typer.Typer(help="Helios — authorized network attack-surface mapper.", no_args_is_help=True)
DEFAULT_SCOPE = Path("examples/input/helios-scope.json")
DEFAULT_LOG = Path("examples/output/helios-blocked.log")
DEFAULT_OUTPUT = Path("examples/output/helios-findings.json")


@app.command()
def scan(
    target: str,
    ports: str = typer.Option("80,443", "--ports"),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    asset_id: str = typer.Option(
        "AST-HELIOS-00001", "--asset-id", help="core.Asset id to attach findings to."
    ),
    output: Path = typer.Option(DEFAULT_OUTPUT, "--output"),
) -> None:
    """Perform bounded TCP discovery only after scope authorization."""
    try:
        address = enforce_scope(target, scope, log)
        requested_ports = [int(port) for port in ports.split(",")]
        observations = discover(str(address), requested_ports, SocketConnector())
    except ScopeError as exc:
        typer.echo(f"helios: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"helios: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    except ValueError as exc:
        typer.echo(f"helios: invalid ports: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    findings = to_findings(asset_id, observations)
    export_findings(findings, output)
    typer.echo(f"helios: exported {len(findings)} finding(s) to {output}")
