"""Command-line interface for scope-safe Artemis web reconnaissance."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import typer

from olympus.artemis.application import ScopedFetchRequest, ScopedFetchService
from olympus.artemis.content import (
    WordlistError,
    discover_content,
    discoveries_to_findings,
    load_wordlist,
)
from olympus.artemis.fingerprint import fingerprint_response, fingerprints_to_findings
from olympus.artemis.http import (
    HttpClientError,
    PinnedTransport,
    SocketResolver,
)
from olympus.artemis.metabase import detect_metabase
from olympus.artemis.scope import OutOfScopeError, ScopeError, enforce_scope
from olympus.artemis.xss import check_reflected_xss
from olympus.core.enums import AssetType, Source
from olympus.core.execution import (
    AuthorizationRequiredError,
    ExecutionPolicy,
    ExecutionPolicyError,
)
from olympus.core.models import Asset, Finding
from olympus.core.paths import audit_log_path

app = typer.Typer(help="Artemis — authorized web reconnaissance.", no_args_is_help=True)
DEFAULT_SCOPE = Path("examples/input/artemis-scope.json")
DEFAULT_LOG = audit_log_path("artemis-blocked.log")
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


def _require_active_authorization(authorized: bool) -> ExecutionPolicy:
    policy = ExecutionPolicy(authorized=authorized, timeout_seconds=5.0, deadline_seconds=60.0)
    try:
        policy.require_authorization("Artemis live web probe")
    except AuthorizationRequiredError as exc:
        typer.echo(f"artemis: {_ACTIVE_DISCLAIMER}", err=True)
        raise typer.Exit(code=4) from exc
    return policy


@app.command()
def fetch(
    url: str = typer.Option(..., "--url"),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    timeout: float = typer.Option(5.0, "--timeout"),
    max_bytes: int = typer.Option(1_000_000, "--max-bytes"),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for this live fetch."
    ),
) -> None:
    """Perform one bounded, scope-safe GET flow and print metadata only."""
    try:
        result = ScopedFetchService(SocketResolver(), PinnedTransport()).run(
            ScopedFetchRequest(
                url=url,
                scope_path=scope,
                audit_log_path=log,
                authorized=i_am_authorized,
                timeout_seconds=timeout,
                max_bytes=max_bytes,
            )
        )
    except AuthorizationRequiredError as exc:
        typer.echo(f"artemis: {_ACTIVE_DISCLAIMER}", err=True)
        raise typer.Exit(code=4) from exc
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


@app.command()
def fingerprint(
    url: str = typer.Option(..., "--url", help="Base URL to fetch once and fingerprint."),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    timeout: float = typer.Option(5.0, "--timeout"),
    max_bytes: int = typer.Option(1_000_000, "--max-bytes"),
    asset_id: str = typer.Option(
        "AST-ARTEMIS-FP-1", "--asset-id", help="core.Asset id to attach findings to."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm you are authorized to test this target."
    ),
    output: Path | None = typer.Option(None, "--output", help="Export findings JSON to this path."),
) -> None:
    """Identify the technology stack from one scope-safe GET (passive, no extra requests)."""
    try:
        result = ScopedFetchService(SocketResolver(), PinnedTransport()).run(
            ScopedFetchRequest(
                url=url,
                scope_path=scope,
                audit_log_path=log,
                authorized=i_am_authorized,
                timeout_seconds=timeout,
                max_bytes=max_bytes,
            )
        )
    except AuthorizationRequiredError as exc:
        typer.echo(f"artemis: {_ACTIVE_DISCLAIMER}", err=True)
        raise typer.Exit(code=4) from exc
    except (ScopeError, OutOfScopeError, HttpClientError, ValueError) as exc:
        typer.echo(f"artemis: fingerprint blocked or failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    fingerprints = fingerprint_response(result.response)
    findings = fingerprints_to_findings(asset_id, result.response.url, fingerprints)
    typer.echo(_render_findings(findings))
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(_render_findings(findings), encoding="utf-8")
    products = ", ".join(f.product for f in fingerprints) or "no known technology"
    typer.echo(f"artemis: fingerprint identified {products}", err=True)


@app.command()
def content(
    url: str = typer.Option(..., "--url", help="Authorized base URL to discover paths under."),
    wordlist: Path = typer.Option(..., "--wordlist", help="Newline-delimited candidate paths."),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    timeout: float = typer.Option(5.0, "--timeout"),
    max_bytes: int = typer.Option(1_000_000, "--max-bytes"),
    rate: float = typer.Option(
        0.0, "--rate", help="Minimum seconds between requests (politeness throttle)."
    ),
    asset_id: str = typer.Option(
        "AST-ARTEMIS-CONTENT-1", "--asset-id", help="core.Asset id to attach findings to."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm you are authorized to test this target."
    ),
    output: Path | None = typer.Option(None, "--output", help="Export findings JSON to this path."),
) -> None:
    """Discover existing paths/files under an authorized base URL (real dirbusting).

    Every candidate is re-checked against scope before the request, so discovery
    only ever touches authorized origins/path-prefixes. GET-only, bounded and
    rate-limited — it discovers, it never exploits.
    """
    _require_active_authorization(i_am_authorized)
    try:
        words = load_wordlist(wordlist)
    except WordlistError as exc:
        typer.echo(f"artemis: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        policy = ExecutionPolicy(
            authorized=i_am_authorized,
            timeout_seconds=timeout,
            deadline_seconds=min(86_400.0, max(timeout * max(len(words), 1), timeout)),
            min_interval_seconds=rate,
        )
        discovered = discover_content(
            url,
            words,
            scope,
            log,
            SocketResolver(),
            PinnedTransport(),
            max_bytes=max_bytes,
            policy=policy,
        )
    except ExecutionPolicyError as exc:
        typer.echo(f"artemis: invalid execution policy: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    findings = discoveries_to_findings(asset_id, discovered)
    typer.echo(_render_findings(findings))
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(_render_findings(findings), encoding="utf-8")
    typer.echo(
        f"artemis: content discovery tried {len(words)} path(s), found {len(discovered)}", err=True
    )
    if discovered:
        raise typer.Exit(code=1)


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
    policy = _require_active_authorization(i_am_authorized)
    asset = Asset(
        asset_type=AssetType.WEB_SERVER,
        hostname=url,
        source=Source.ARTEMIS,
        tags=["artemis", "metabase"],
    )
    findings = detect_metabase(
        asset.asset_id,
        url,
        scope,
        log,
        SocketResolver(),
        PinnedTransport(),
        policy=policy,
    )
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
    policy = _require_active_authorization(i_am_authorized)
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
            check_reflected_xss(
                asset.asset_id,
                url,
                target,
                scope,
                log,
                resolver,
                transport,
                policy=policy,
            )
        )
    typer.echo(_render_findings(findings))
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(_render_findings(findings), encoding="utf-8")
    typer.echo(
        f"artemis: xss check tested {len(params)} param(s), {len(findings)} finding(s)", err=True
    )
