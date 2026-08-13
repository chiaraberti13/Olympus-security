"""Command-line interface for the Artemis module."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import typer

from olympus.artemis.cors import analyze_cors
from olympus.artemis.demo_data import DEMO_URL, DemoClient
from olympus.artemis.discovery import discover_content
from olympus.artemis.headers import analyze_headers
from olympus.artemis.http_client import HttpClient, UrllibHttpClient
from olympus.artemis.scope import OutOfScopeError, ScopeError, enforce_scope
from olympus.core.enums import AssetType, Source
from olympus.core.models import Asset, Finding

app = typer.Typer(
    help="Artemis — Offensive web recon.",
    no_args_is_help=True,
)

DEFAULT_SCOPE_PATH = Path("examples/input/artemis-scope.json")
DEFAULT_BLOCK_LOG_PATH = Path("examples/output/artemis-blocked.log")
DEMO_OUTPUT_PATH = Path("examples/output/artemis-findings.json")
# Origin sent to probe for CORS reflection: attacker.example is IANA-reserved
# for documentation (RFC 6761 style .example convention), never a real site.
PROBE_ORIGIN = "https://attacker.example"


def _run_recon(url: str, client: HttpClient) -> tuple[Asset, int, list[Finding]]:
    """Run headers/CORS/content-discovery recon against ``url`` via ``client``."""
    host = urlparse(url).hostname or ""
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

    return asset, response.status_code, findings


def _render(asset: Asset, status_code: int, findings: list[Finding]) -> str:
    """Render the recon result as pretty-printed, sorted JSON."""
    payload = {
        "asset": json.loads(asset.model_dump_json()),
        "status_code": status_code,
        "findings": [json.loads(finding.model_dump_json()) for finding in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


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

    asset, status_code, findings = _run_recon(url, UrllibHttpClient())
    text = _render(asset, status_code, findings)
    typer.echo(text)

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        typer.echo(f"artemis: wrote {len(findings)} finding(s) to {output}", err=True)


@app.command()
def demo() -> None:
    """Run the full Artemis pipeline against a synthetic 'Olympus Demo Corp' website.

    Fully offline and deterministic: the HTTP client is served from
    :mod:`olympus.artemis.demo_data` instead of the network, but every
    other step (scope enforcement, headers/CORS/discovery analysis) is the
    real production code path used by ``artemis scan``.
    """
    typer.echo(f"artemis: demo — web recon on {DEMO_URL} (Olympus Demo Corp, synthetic)")
    host = urlparse(DEMO_URL).hostname or ""
    enforce_scope(host, DEFAULT_SCOPE_PATH, DEFAULT_BLOCK_LOG_PATH)

    asset, status_code, findings = _run_recon(DEMO_URL, DemoClient())
    text = _render(asset, status_code, findings)
    typer.echo(text)

    DEMO_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEMO_OUTPUT_PATH.write_text(text, encoding="utf-8")
    typer.echo(f"artemis: wrote {len(findings)} finding(s) to {DEMO_OUTPUT_PATH}")
