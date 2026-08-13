"""Command-line interface for the Artemis module."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import typer

from olympus.artemis.cors import analyze_cors
from olympus.artemis.discovery import discover_content
from olympus.artemis.headers import analyze_headers
from olympus.artemis.http_client import UrllibHttpClient
from olympus.artemis.scope import OutOfScopeError, ScopeError, enforce_scope
from olympus.core.enums import AssetType, Source
from olympus.core.models import Asset, Finding

app = typer.Typer(
    help="Artemis — Offensive web recon.",
    no_args_is_help=True,
)

DEFAULT_SCOPE_PATH = Path("examples/input/artemis-scope.json")
DEFAULT_BLOCK_LOG_PATH = Path("examples/output/artemis-blocked.log")
# Origin sent to probe for CORS reflection: attacker.example is IANA-reserved
# for documentation (RFC 6761 style .example convention), never a real site.
PROBE_ORIGIN = "https://attacker.example"


@app.command()
def scan(
    url: str = typer.Option(..., "--url", help="Base URL to run web recon against."),
    scope: Path = typer.Option(
        DEFAULT_SCOPE_PATH,
        "--scope",
        help="Path to the JSON scope file listing authorized hosts.",
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
    """Run web recon (headers, CORS, content discovery) against a single in-scope URL."""
    host = urlparse(url).hostname or ""
    try:
        enforce_scope(host, scope, log)
    except ScopeError as exc:
        typer.echo(f"artemis: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"artemis: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    client = UrllibHttpClient()
    asset = Asset(
        asset_type=AssetType.WEB_SERVER,
        hostname=host,
        source=Source.ARTEMIS,
        tags=["artemis", "web-recon"],
    )

    response = client.get(url, headers={"Origin": PROBE_ORIGIN})

    findings: list[Finding] = []
    findings.extend(analyze_headers(asset.asset_id, response))
    findings.extend(analyze_cors(asset.asset_id, response, request_origin=PROBE_ORIGIN))
    findings.extend(discover_content(asset.asset_id, url, client))

    result = {
        "asset": json.loads(asset.model_dump_json()),
        "status_code": response.status_code,
        "findings": [json.loads(finding.model_dump_json()) for finding in findings],
    }
    typer.echo(json.dumps(result, indent=2, sort_keys=True))

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        typer.echo(f"artemis: wrote {len(findings)} finding(s) to {output}", err=True)


@app.command()
def demo() -> None:
    """Run a self-contained demo on the synthetic 'Olympus Demo Corp' dataset."""
    # NOTE: scaffold only. The development loop implements this command.
    typer.echo("artemis: demo not implemented yet (scaffold).")
