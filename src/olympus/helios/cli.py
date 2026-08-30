"""Command-line interface for authorized Helios surface discovery."""

from __future__ import annotations

from pathlib import Path

import typer

from olympus.core.execution import AuthorizationRequiredError, ExecutionPolicyError
from olympus.core.paths import audit_log_path, output_path
from olympus.helios.application import SurfaceScanRequest, SurfaceScanService
from olympus.helios.export import export_scan_result
from olympus.helios.scanner import SocketConnector
from olympus.helios.scope import OutOfScopeError, ScopeError

app = typer.Typer(help="Helios — authorized network attack-surface mapper.", no_args_is_help=True)
DEFAULT_SCOPE = Path("examples/input/helios-scope.json")
DEFAULT_LOG = audit_log_path("helios-blocked.log")
DEFAULT_OUTPUT = output_path("helios-findings.json")


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
    timeout: float = typer.Option(1.0, "--timeout", help="Per-port TCP connect timeout."),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for this live scan."
    ),
) -> None:
    """Perform bounded TCP discovery only after scope authorization."""
    try:
        requested_ports = [int(port) for port in ports.split(",")]
        outcome = SurfaceScanService(SocketConnector()).run(
            SurfaceScanRequest(
                target=target,
                ports=tuple(requested_ports),
                scope_path=scope,
                audit_log_path=log,
                asset_id=asset_id,
                authorized=i_am_authorized,
                timeout_seconds=timeout,
            )
        )
    except AuthorizationRequiredError as exc:
        typer.echo("helios: explicit authorization confirmation is required", err=True)
        raise typer.Exit(code=4) from exc
    except ScopeError as exc:
        typer.echo(f"helios: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"helios: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    except (ValueError, ExecutionPolicyError) as exc:
        typer.echo(f"helios: invalid ports: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    export_scan_result(list(outcome.observations), list(outcome.findings), output)
    typer.echo(
        f"helios: exported {len(outcome.observations)} observation(s) and "
        f"{len(outcome.findings)} finding(s) to {output}"
    )
