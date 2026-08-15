"""Command-line interface for scope-safe Artemis web reconnaissance."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import typer

from olympus.artemis.http import (
    HttpClientError,
    HttpResponse,
    PinnedTransport,
    SocketResolver,
    fetch_scoped,
)
from olympus.artemis.metabase import detect_metabase
from olympus.artemis.scope import OutOfScopeError, ScopeError, enforce_scope
from olympus.artemis.xss import check_reflected_xss
from olympus.core.enums import AssetType, Source
from olympus.core.models import Asset, Finding

app = typer.Typer(help="Artemis — authorized web reconnaissance.", no_args_is_help=True)
DEFAULT_SCOPE = Path("examples/input/artemis-scope.json")
DEFAULT_LOG = Path("examples/output/artemis-blocked.log")
DEFAULT_METABASE_SCOPE = Path("examples/input/artemis-metabase-scope.json")

# Shown before an active web test that sends requests to a live target.
_ACTIVE_DISCLAIMER = (
    "AUTHORIZED USE ONLY — this actively probes a live web target. Run it only against "
    "systems you are explicitly authorized to test (documented engagement/scope). "
    "Re-run with --i-am-authorized to confirm."
)


def _render_findings(findings: list[Finding]) -> str:
    """Render findings as pretty-printed, sorted JSON."""
    return json.dumps(
        [json.loads(finding.model_dump_json()) for finding in findings],
        indent=2,
        sort_keys=True,
    )


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
            url,
            scope,
            log,
            SocketResolver(),
            PinnedTransport(),
            timeout=timeout,
            max_bytes=max_bytes,
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
        def get(
            self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
        ) -> HttpResponse:
            del addresses, timeout, max_bytes
            if url.endswith("/app/login"):
                return HttpResponse(url, 302, {"location": "/app/home"}, b"")
            return HttpResponse(url, 200, {"content-type": "text/html"}, b"<h1>Demo</h1>")

    class DemoResolver:
        def resolve(self, hostname: str, port: int) -> list[str]:
            del hostname, port
            return ["192.0.2.10"]

    result = fetch_scoped(
        "https://portal.olympusdemocorp.example/app/login",
        DEFAULT_SCOPE,
        DEFAULT_LOG,
        DemoResolver(),
        DemoTransport(),
    )
    typer.echo(
        f"artemis: demo fetched {result.response.status} via {len(result.redirects)} "
        "scoped redirect(s); offline transport"
    )


@app.command()
def metabase(
    url: str = typer.Option(..., "--url", help="Base URL of the Metabase instance to fingerprint."),
    scope: Path = typer.Option(DEFAULT_METABASE_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm you are authorized to test this target."
    ),
    output: Path | None = typer.Option(None, "--output", help="Export findings JSON to this path."),
) -> None:
    """Non-exploitatively check a Metabase instance for CVE-2026-72898 exposure.

    Reads the public version and endpoint reachability through the scope-safe,
    DNS-pinned transport. Never sends a SQL injection payload.
    """
    if not i_am_authorized:
        typer.echo(f"artemis: {_ACTIVE_DISCLAIMER}", err=True)
        raise typer.Exit(code=4)
    asset = Asset(
        asset_type=AssetType.WEB_SERVER,
        hostname=url,
        source=Source.ARTEMIS,
        tags=["artemis", "metabase"],
    )
    findings = detect_metabase(asset.asset_id, url, scope, log, SocketResolver(), PinnedTransport())
    typer.echo(_render_findings(findings))
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(_render_findings(findings), encoding="utf-8")
    typer.echo(f"artemis: metabase check produced {len(findings)} finding(s)", err=True)


def _target_params(url: str, param: str | None) -> list[str]:
    """Return the query parameters to test: the named one, or all in the URL."""
    if param is not None:
        return [param]
    return [key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]


@app.command()
def xss(
    url: str = typer.Option(..., "--url", help="URL to probe (with query params to test)."),
    param: str | None = typer.Option(
        None, "--param", help="Parameter to test; if omitted, every query parameter is tested."
    ),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm you are authorized to test this target."
    ),
    output: Path | None = typer.Option(None, "--output", help="Export findings JSON to this path."),
) -> None:
    """Non-destructively test URL parameters for reflected XSS (marker reflection only).

    Sends a benign structural marker (no script/payload) through the scope-safe
    transport and flags an unescaped reflection. No WAF evasion is performed.
    """
    if not i_am_authorized:
        typer.echo(f"artemis: {_ACTIVE_DISCLAIMER}", err=True)
        raise typer.Exit(code=4)
    params = _target_params(url, param)
    if not params:
        typer.echo(
            "artemis: no query parameter to test (add one to the URL or use --param)", err=True
        )
        raise typer.Exit(code=2)
    asset = Asset(
        asset_type=AssetType.WEB_SERVER,
        hostname=url,
        source=Source.ARTEMIS,
        tags=["artemis", "xss"],
    )
    resolver, transport = SocketResolver(), PinnedTransport()
    findings: list[Finding] = []
    for target in params:
        findings.extend(
            check_reflected_xss(asset.asset_id, url, target, scope, log, resolver, transport)
        )
    typer.echo(_render_findings(findings))
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(_render_findings(findings), encoding="utf-8")
    typer.echo(
        f"artemis: xss check tested {len(params)} param(s), {len(findings)} finding(s)", err=True
    )
