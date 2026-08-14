"""Command-line interface for the Argus module."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.argus.assets import export_assets, recon_to_assets
from olympus.argus.ct import CertificateTransparencyError, CrtShClient
from olympus.argus.diff import diff_snapshots
from olympus.argus.recon import scan_domain
from olympus.argus.resolver import DnspythonResolver
from olympus.argus.scope import OutOfScopeError, ScopeError, enforce_scope

app = typer.Typer(
    help="Argus — OSINT & passive recon.",
    no_args_is_help=True,
)

DEFAULT_SCOPE_PATH = Path("examples/input/argus-scope.json")
DEFAULT_BLOCK_LOG_PATH = Path("examples/output/argus-blocked.log")
DEFAULT_ASSETS_PATH = Path("examples/output/argus-assets.json")


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
    output: Path = typer.Option(
        DEFAULT_ASSETS_PATH,
        "--output",
        help="Path for the core.Asset-compatible JSON export.",
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

    try:
        result = scan_domain(domain, DnspythonResolver(), CrtShClient())
    except CertificateTransparencyError as exc:
        typer.echo(f"argus: Certificate Transparency error: {exc}", err=True)
        raise typer.Exit(code=4) from exc
    export_assets(recon_to_assets(result), output)
    typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))


@app.command("diff")
def diff_command(before: Path, after: Path) -> None:
    """Compare two Argus asset snapshots without performing network activity."""
    try:
        result = diff_snapshots(before, after)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        typer.echo(f"argus: diff error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(result.__dict__, indent=2, sort_keys=True))


@app.command()
def demo() -> None:
    """Run a self-contained demo on the synthetic 'Olympus Demo Corp' dataset."""
    domain = "olympusdemocorp.example"

    class DemoResolver:
        """Resolve the synthetic dataset without network access."""

        def resolve(self, name: str, record_type: str) -> list[str]:
            records = {
                (domain, "A"): ["203.0.113.10"],
                (domain, "MX"): [f"10 mail.{domain}"],
                (domain, "TXT"): ["v=spf1 -all"],
                (f"_dmarc.{domain}", "TXT"): ["v=DMARC1; p=reject"],
            }
            return records.get((name, record_type), [])

    class DemoCtClient:
        """Return synthetic Certificate Transparency observations."""

        def discover(self, requested_domain: str) -> list[str]:
            return [f"portal.{requested_domain}"]

    result = scan_domain(domain, DemoResolver(), DemoCtClient())
    export_assets(recon_to_assets(result), DEFAULT_ASSETS_PATH)
    typer.echo(f"argus: exported {len(recon_to_assets(result))} assets to {DEFAULT_ASSETS_PATH}")
