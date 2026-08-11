"""Command-line interface for the Argus module."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from pydantic import ValidationError

from olympus.argus.assets import build_assets, export_assets, load_assets
from olympus.argus.ct import CrtShClient, CtQueryError, CtRecon, enumerate_subdomains
from olympus.argus.demo_data import DEMO_DOMAIN, DemoCtClient, DemoResolver
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
DEMO_ASSETS_OUTPUT_PATH = Path("examples/output/argus-assets.json")
DEMO_PREVIOUS_ASSETS_PATH = Path("examples/input/argus-assets-previous.json")


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
    output: Path | None = typer.Option(
        None,
        "--output",
        help="If set, also export discovered hosts as core.Asset JSON to this path.",
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

    ct_result = CtRecon(domain=domain)
    try:
        ct_result = enumerate_subdomains(domain, CrtShClient())
    except CtQueryError as exc:
        # CT lookup is an auxiliary, best-effort source: a network hiccup or
        # a blocked egress must not fail the whole (otherwise valid) DNS scan.
        typer.echo(f"argus: warning: certificate transparency lookup failed: {exc}", err=True)

    result = dns_result.to_dict()
    result["subdomains"] = ct_result.subdomains
    typer.echo(json.dumps(result, indent=2, sort_keys=True))

    if output is not None:
        assets = build_assets(dns_result, ct_result)
        export_assets(assets, output)
        typer.echo(f"argus: wrote {len(assets)} asset(s) to {output}", err=True)


@app.command("diff")
def diff_command(
    previous: Path = typer.Option(
        ..., "--previous", help="Older argus-assets.json snapshot."
    ),
    current: Path = typer.Option(
        ..., "--current", help="Newer argus-assets.json snapshot."
    ),
) -> None:
    """Compare two argus-assets.json snapshots and report added/removed/changed hosts."""
    try:
        previous_assets = load_assets(previous)
        current_assets = load_assets(current)
    except (OSError, ValueError, ValidationError) as exc:
        typer.echo(f"argus: diff error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    result = diff_snapshots(previous_assets, current_assets)
    typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))


@app.command()
def demo() -> None:
    """Run the full Argus pipeline on the synthetic 'Olympus Demo Corp' dataset.

    Fully offline and deterministic: DNS and Certificate Transparency are
    served from :mod:`olympus.argus.demo_data` instead of the network, but
    every other step (scope enforcement, recon, asset export, change
    monitoring) is the real production code path used by ``argus scan``.
    """
    typer.echo(f"argus: demo — passive recon on {DEMO_DOMAIN} (Olympus Demo Corp, synthetic)")
    enforce_scope(DEMO_DOMAIN, DEFAULT_SCOPE_PATH, DEFAULT_BLOCK_LOG_PATH)

    dns_result = scan_domain(DEMO_DOMAIN, DemoResolver())
    ct_result = enumerate_subdomains(DEMO_DOMAIN, DemoCtClient())

    recon_output = dns_result.to_dict()
    recon_output["subdomains"] = ct_result.subdomains
    typer.echo(json.dumps(recon_output, indent=2, sort_keys=True))

    assets = build_assets(dns_result, ct_result)
    export_assets(assets, DEMO_ASSETS_OUTPUT_PATH)
    typer.echo(f"argus: wrote {len(assets)} asset(s) to {DEMO_ASSETS_OUTPUT_PATH}")

    previous_assets = load_assets(DEMO_PREVIOUS_ASSETS_PATH)
    change_report = diff_snapshots(previous_assets, assets)
    typer.echo(f"argus: change monitoring vs {DEMO_PREVIOUS_ASSETS_PATH}:")
    typer.echo(json.dumps(change_report.to_dict(), indent=2, sort_keys=True))
