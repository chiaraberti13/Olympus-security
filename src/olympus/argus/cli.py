"""Command-line interface for the Argus module."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import typer

from olympus.argus.accounts import (
    AccountIntel,
    AccountScanResult,
    SiteRegistryError,
    build_account_assets,
    build_account_finding,
    enumerate_accounts,
    load_site_registry,
)
from olympus.argus.accounts_scope import (
    AccountOutOfScopeError,
    AccountScopeError,
    enforce_account_scope,
)
from olympus.argus.application import DomainScanRequest, DomainScanService
from olympus.argus.assets import export_assets, recon_to_assets
from olympus.argus.ct import CertificateTransparencyError, CrtShClient
from olympus.argus.diff import diff_snapshots
from olympus.argus.enrichment import (
    EnrichmentError,
    HudsonRockBreachClient,
    MessagingPresence,
    NumverifyClient,
    PhoneEnrichment,
    RapidApiMessagingClient,
)
from olympus.argus.fronting import (
    assess_fronting,
    export_fronting,
    report_to_asset,
    report_to_findings,
)
from olympus.argus.graph import EntityType, export_investigation
from olympus.argus.ip_osint import (
    IpApiClient,
    IpGeo,
    IpGeoError,
    IpIntel,
    IpParseError,
    analyze_ip,
    build_ip_asset,
    build_ip_findings,
    export_ip_intel,
)
from olympus.argus.ip_scope import (
    IpOutOfScopeError,
    IpScopeError,
    enforce_ip_scope,
)
from olympus.argus.phone import (
    PhoneIntel,
    PhoneParseError,
    analyze_phone,
    build_phone_asset,
    build_phone_findings,
    export_phone_intel,
)
from olympus.argus.phone_scope import (
    PhoneOutOfScopeError,
    PhoneScopeError,
    enforce_phone_scope,
)
from olympus.argus.resolver import DnspythonResolver
from olympus.argus.scope import OutOfScopeError, ScopeError, enforce_scope
from olympus.argus.transforms import TransformContext, run_investigation
from olympus.core.http import UrllibHttpClient

app = typer.Typer(
    help="Argus — OSINT & passive recon.",
    no_args_is_help=True,
)

DEFAULT_SCOPE_PATH = Path("examples/input/argus-scope.json")
DEFAULT_BLOCK_LOG_PATH = Path("examples/output/argus-blocked.log")
DEFAULT_ASSETS_PATH = Path("examples/output/argus-assets.json")

DEFAULT_PHONE_SCOPE_PATH = Path("examples/input/argus-phone-scope.json")
DEFAULT_PHONE_BLOCK_LOG_PATH = Path("examples/output/argus-phone-blocked.log")

DEFAULT_SITES_PATH = Path("examples/input/argus-sites.json")
DEFAULT_ACCOUNT_SCOPE_PATH = Path("examples/input/argus-accounts-scope.json")
DEFAULT_ACCOUNT_BLOCK_LOG_PATH = Path("examples/output/argus-accounts-blocked.log")

DEFAULT_IP_SCOPE_PATH = Path("examples/input/argus-ip-scope.json")
DEFAULT_IP_BLOCK_LOG_PATH = Path("examples/output/argus-ip-blocked.log")

_IP_DISCLAIMER = (
    "AUTHORIZED USE ONLY — --geo queries a third-party geolocation service about the target "
    "IP. Run it only with documented authorization. Re-run with --i-am-authorized to confirm."
)

_METADATA_DISCLAIMER = (
    "AUTHORIZED USE ONLY — extracting public profile metadata (avatar/bio/followers) about a "
    "real person is privacy-sensitive OSINT. Run it only with documented authorization/consent. "
    "Re-run with --i-am-authorized to confirm."
)

# Shown before any real, third-party lookup against a live number.
_AUTH_DISCLAIMER = (
    "AUTHORIZED USE ONLY — phone enrichment, breach and messaging lookups query real "
    "third-party services about a real person's number. Run them only with documented "
    "authorization/consent (pentest engagement, your own number, or study on numbers you "
    "control). Re-run with --i-am-authorized to confirm."
)


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
        result = DomainScanService(DnspythonResolver(), CrtShClient()).run(
            DomainScanRequest(domain=domain, scope_path=scope, audit_log_path=log)
        )
    except ScopeError as exc:
        typer.echo(f"argus: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    except CertificateTransparencyError as exc:
        typer.echo(f"argus: Certificate Transparency error: {exc}", err=True)
        raise typer.Exit(code=4) from exc
    export_assets(recon_to_assets(result), output)
    typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))


@app.command()
def fronting(
    domain: str = typer.Option(..., "--domain", help="Domain to assess for CDN/WAF fronting."),
    scope: Path = typer.Option(
        DEFAULT_SCOPE_PATH, "--scope", help="JSON scope file listing authorized domains."
    ),
    log: Path = typer.Option(
        DEFAULT_BLOCK_LOG_PATH, "--log", help="Path to the out-of-scope audit log."
    ),
    asset_id: str = typer.Option(
        "AST-ARGUS-FRONT-1", "--asset-id", help="core.Asset id to attach findings to."
    ),
    output: Path = typer.Option(
        Path("examples/output/argus-fronting.json"), "--output", help="Fronting report JSON."
    ),
) -> None:
    """Passively check whether an in-scope domain is CDN/WAF-fronted and leaks its origin IP."""
    try:
        enforce_scope(domain, scope, log)
    except ScopeError as exc:
        typer.echo(f"argus: scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except OutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    try:
        report = assess_fronting(domain, DnspythonResolver(), CrtShClient())
    except CertificateTransparencyError as exc:
        typer.echo(f"argus: Certificate Transparency error: {exc}", err=True)
        raise typer.Exit(code=4) from exc

    asset = report_to_asset(report, asset_id)
    findings = report_to_findings(report, asset_id)
    export_fronting(report, asset, findings, output)
    typer.echo(
        f"argus: {domain} — fronted={report.fronted} "
        f"({', '.join(report.providers) or 'no CDN'}); "
        f"{len(report.origin_leaks)} candidate origin leak(s); {output}"
    )
    if report.origin_leaks:
        raise typer.Exit(code=1)


@app.command("diff")
def diff_command(before: Path, after: Path) -> None:
    """Compare two Argus asset snapshots without performing network activity."""
    try:
        result = diff_snapshots(before, after)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        typer.echo(f"argus: diff error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(result.__dict__, indent=2, sort_keys=True))




def _collect_enrichment(e164: str, *, enrich: bool, breach: bool) -> PhoneEnrichment | None:
    """Run the opt-in carrier/breach lookups and merge them into one result."""
    if not (enrich or breach):
        return None
    client = UrllibHttpClient()
    carrier_name, line_type, breach_count = "", "", 0
    breach_sources: tuple[str, ...] = ()

    if enrich:
        numverify = NumverifyClient.from_env(client)
        if numverify is None:
            typer.echo(
                "argus: warning: --enrich skipped (set OLYMPUS_NUMVERIFY_KEY to enable)", err=True
            )
        else:
            try:
                result = numverify.enrich(e164)
                carrier_name, line_type = result.carrier, result.line_type
            except EnrichmentError as exc:
                typer.echo(f"argus: warning: carrier enrichment failed: {exc}", err=True)

    if breach:
        try:
            breach_result = HudsonRockBreachClient(client).enrich(e164)
            breach_count = breach_result.breach_count
            breach_sources = breach_result.breach_sources
        except EnrichmentError as exc:
            typer.echo(f"argus: warning: breach lookup failed: {exc}", err=True)

    return PhoneEnrichment(
        carrier=carrier_name,
        line_type=line_type,
        breach_count=breach_count,
        breach_sources=breach_sources,
    )


def _collect_messaging(e164: str, *, messaging: bool) -> MessagingPresence | None:
    """Run the opt-in messaging-presence lookup, if requested and configured."""
    if not messaging:
        return None
    client = UrllibHttpClient()
    messaging_client = RapidApiMessagingClient.from_env(client)
    if messaging_client is None:
        typer.echo(
            "argus: warning: --messaging skipped (set OLYMPUS_RAPIDAPI_KEY to enable)", err=True
        )
        return None
    try:
        return messaging_client.lookup(e164)
    except EnrichmentError as exc:
        typer.echo(f"argus: warning: messaging lookup failed: {exc}", err=True)
        return None


def _read_targets(path: Path) -> list[str]:
    """Read one target per line, skipping blanks and ``#`` comments."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def _profile_number(
    number: str,
    region: str | None,
    scope: Path,
    log: Path,
    *,
    wants_real: bool,
    enrich: bool,
    breach: bool,
    messaging: bool,
) -> PhoneIntel:
    """Profile one number: parse, enforce scope, and (optionally) enrich."""
    report = analyze_phone(number, region)
    enforce_phone_scope(report.e164 or number, scope, log)
    enrichment_result: PhoneEnrichment | None = None
    messaging_result: MessagingPresence | None = None
    if wants_real and report.e164 is not None:
        enrichment_result = _collect_enrichment(report.e164, enrich=enrich, breach=breach)
        messaging_result = _collect_messaging(report.e164, messaging=messaging)
    asset = build_phone_asset(report)
    findings = build_phone_findings(asset.asset_id, report, enrichment_result, messaging_result)
    return PhoneIntel(report=report, asset=asset, findings=findings)


@app.command()
def phone(
    number: str | None = typer.Option(
        None, "--number", help="E.164 (e.g. +14155550123) or national with --region."
    ),
    input_file: Path | None = typer.Option(
        None, "--input", help="File with one number per line (batch mode)."
    ),
    region: str | None = typer.Option(
        None, "--region", help="ISO region (e.g. US, IT) for national-format numbers."
    ),
    scope: Path = typer.Option(
        DEFAULT_PHONE_SCOPE_PATH, "--scope", help="JSON scope file of authorized E.164 prefixes."
    ),
    log: Path = typer.Option(
        DEFAULT_PHONE_BLOCK_LOG_PATH, "--log", help="Out-of-scope audit log."
    ),
    enrich: bool = typer.Option(
        False, "--enrich", help="Carrier/line-type via Numverify (needs OLYMPUS_NUMVERIFY_KEY)."
    ),
    breach: bool = typer.Option(
        False, "--breach", help="Breach-intelligence exposure lookup (keyless third-party API)."
    ),
    messaging: bool = typer.Option(
        False, "--messaging", help="Messaging-platform presence (needs OLYMPUS_RAPIDAPI_KEY)."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for real lookups."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the phone-intel bundle(s) as JSON to this path."
    ),
) -> None:
    """Profile in-scope phone number(s): offline parsing + opt-in real lookups.

    Provide exactly one of --number (single) or --input (batch, one per line).
    """
    if (number is None) == (input_file is None):
        typer.echo("argus: provide exactly one of --number or --input", err=True)
        raise typer.Exit(code=2)

    wants_real = enrich or breach or messaging
    if wants_real and not i_am_authorized:
        typer.echo(f"argus: {_AUTH_DISCLAIMER}", err=True)
        raise typer.Exit(code=4)

    if number is not None:
        try:
            intel = _profile_number(
                number, region, scope, log,
                wants_real=wants_real, enrich=enrich, breach=breach, messaging=messaging,
            )
        except PhoneParseError as exc:
            typer.echo(f"argus: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        except PhoneScopeError as exc:
            typer.echo(f"argus: phone scope error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        except PhoneOutOfScopeError as exc:
            typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
            raise typer.Exit(code=3) from exc
        typer.echo(json.dumps(intel.to_dict(), indent=2, sort_keys=True))
        if output is not None:
            export_phone_intel(intel, output)
            typer.echo(f"argus: wrote phone intel to {output}", err=True)
        return

    # Batch mode: skip unparseable / out-of-scope numbers, never abort the run.
    assert input_file is not None  # noqa: S101 (guaranteed by the exactly-one check above)
    intels: list[PhoneIntel] = []
    for target in _read_targets(input_file):
        try:
            intels.append(
                _profile_number(
                    target, region, scope, log,
                    wants_real=wants_real, enrich=enrich, breach=breach, messaging=messaging,
                )
            )
        except PhoneParseError:
            typer.echo(f"argus: skipping unparseable number {target!r}", err=True)
        except PhoneScopeError as exc:
            typer.echo(f"argus: phone scope error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        except PhoneOutOfScopeError:
            typer.echo(f"argus: skipping out-of-scope number {target!r} (logged)", err=True)

    payload = [intel.to_dict() for intel in intels]
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    typer.echo(f"argus: profiled {len(intels)} number(s)", err=True)


def _build_account_intel(result: AccountScanResult) -> AccountIntel:
    """Turn a raw scan into assets + a summary finding bundle."""
    assets = build_account_assets(result)
    finding = build_account_finding(assets[0].asset_id, result) if assets else None
    return AccountIntel(result=result, assets=assets, findings=[finding] if finding else [])


@app.command()
def accounts(
    username: str | None = typer.Option(
        None, "--username", help="Handle to enumerate across sites."
    ),
    input_file: Path | None = typer.Option(
        None, "--input", help="File with one handle per line (batch mode)."
    ),
    scope: Path = typer.Option(
        DEFAULT_ACCOUNT_SCOPE_PATH, "--scope", help="JSON allowlist of authorized handles."
    ),
    log: Path = typer.Option(
        DEFAULT_ACCOUNT_BLOCK_LOG_PATH, "--log", help="Out-of-scope audit log."
    ),
    sites: Path = typer.Option(
        DEFAULT_SITES_PATH, "--sites", help="JSON site registry to check."
    ),
    metadata: bool = typer.Option(
        False, "--metadata", help="Also extract public profile metadata (needs --i-am-authorized)."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for metadata scraping."
    ),
    concurrency: int = typer.Option(
        8, "--concurrency", min=1, max=64, help="Parallel site checks per handle."
    ),
    rate: float = typer.Option(
        0.0, "--rate", min=0.0, help="Minimum seconds between requests (politeness rate limit)."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the account-intel bundle(s) as JSON to this path."
    ),
) -> None:
    """Enumerate in-scope handle(s) across a curated list of public sites.

    Provide exactly one of --username (single) or --input (batch, one per line).
    """
    if (username is None) == (input_file is None):
        typer.echo("argus: provide exactly one of --username or --input", err=True)
        raise typer.Exit(code=2)

    if metadata and not i_am_authorized:
        typer.echo(f"argus: {_METADATA_DISCLAIMER}", err=True)
        raise typer.Exit(code=4)

    try:
        specs = load_site_registry(sites)
    except SiteRegistryError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    client = UrllibHttpClient.from_config(min_interval=rate if rate > 0.0 else None)
    handles = [username] if username is not None else _read_targets(input_file)  # type: ignore[arg-type]
    intels: list[AccountIntel] = []
    for handle in handles:
        try:
            enforce_account_scope(handle, scope, log)
        except AccountScopeError as exc:
            typer.echo(f"argus: account scope error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        except AccountOutOfScopeError as exc:
            if username is not None:
                typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
                raise typer.Exit(code=3) from exc
            typer.echo(f"argus: skipping out-of-scope handle {handle!r} (logged)", err=True)
            continue
        result = enumerate_accounts(
            handle, specs, client, want_metadata=metadata, concurrency=concurrency
        )
        intels.append(_build_account_intel(result))
        typer.echo(
            f"argus: '{handle}' found on {len(result.existing())}/{len(specs)} site(s)", err=True
        )

    if username is not None:
        payload: object = intels[0].to_dict() if intels else {}
    else:
        payload = [intel.to_dict() for intel in intels]
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        typer.echo(f"argus: wrote account intel to {output}", err=True)


def _profile_ip(ip: str, scope: Path, log: Path, *, geo: bool) -> IpIntel:
    """Profile one IP: classify offline, enforce scope, and optionally geolocate."""
    report = analyze_ip(ip)
    enforce_ip_scope(report.ip, scope, log)
    geo_result: IpGeo | None = None
    if geo:
        try:
            geo_result = IpApiClient(UrllibHttpClient()).geolocate(report.ip)
        except IpGeoError as exc:
            typer.echo(f"argus: warning: geolocation failed for {report.ip}: {exc}", err=True)
    asset = build_ip_asset(report, geo_result)
    findings = build_ip_findings(asset.asset_id, report, geo_result)
    return IpIntel(report=report, asset=asset, findings=findings)


@app.command()
def ip(
    ip_address: str | None = typer.Option(None, "--ip", help="IPv4/IPv6 address to profile."),
    input_file: Path | None = typer.Option(
        None, "--input", help="File with one IP per line (batch mode)."
    ),
    scope: Path = typer.Option(
        DEFAULT_IP_SCOPE_PATH, "--scope", help="JSON scope file of authorized CIDR networks."
    ),
    log: Path = typer.Option(DEFAULT_IP_BLOCK_LOG_PATH, "--log", help="Out-of-scope audit log."),
    geo: bool = typer.Option(
        False, "--geo", help="Geolocation/ASN via ip-api.com (third-party, keyless)."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm authorization for the third-party geo lookup."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the IP-intel bundle(s) as JSON to this path."
    ),
) -> None:
    """Profile in-scope IP address(es): offline classification + opt-in geolocation.

    Provide exactly one of --ip (single) or --input (batch, one per line).
    """
    if (ip_address is None) == (input_file is None):
        typer.echo("argus: provide exactly one of --ip or --input", err=True)
        raise typer.Exit(code=2)
    if geo and not i_am_authorized:
        typer.echo(f"argus: {_IP_DISCLAIMER}", err=True)
        raise typer.Exit(code=4)

    if ip_address is not None:
        try:
            intel = _profile_ip(ip_address, scope, log, geo=geo)
        except IpParseError as exc:
            typer.echo(f"argus: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        except IpScopeError as exc:
            typer.echo(f"argus: IP scope error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        except IpOutOfScopeError as exc:
            typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
            raise typer.Exit(code=3) from exc
        typer.echo(json.dumps(intel.to_dict(), indent=2, sort_keys=True))
        if output is not None:
            export_ip_intel(intel, output)
            typer.echo(f"argus: wrote IP intel to {output}", err=True)
        return

    assert input_file is not None  # noqa: S101 (guaranteed by the exactly-one check above)
    intels: list[IpIntel] = []
    for target in _read_targets(input_file):
        try:
            intels.append(_profile_ip(target, scope, log, geo=geo))
        except IpParseError:
            typer.echo(f"argus: skipping invalid IP {target!r}", err=True)
        except IpScopeError as exc:
            typer.echo(f"argus: IP scope error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        except IpOutOfScopeError:
            typer.echo(f"argus: skipping out-of-scope IP {target!r} (logged)", err=True)

    payload = [intel.to_dict() for intel in intels]
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    typer.echo(f"argus: profiled {len(intels)} IP(s)", err=True)


_INVESTIGATE_DISCLAIMER = (
    "AUTHORIZED USE ONLY — an investigation fans out third-party OSINT lookups about the seed "
    "and everything it links to. Run it only with documented authorization. Re-run with "
    "--i-am-authorized to confirm."
)
DEFAULT_INVESTIGATION_LOG = Path("examples/output/argus-investigate.log")


def _log_investigation(name: str, seed_type: str, seed_value: str, log: Path) -> None:
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "investigation": name,
        "seed_type": seed_type,
        "seed_value": seed_value,
        "action": "investigation_started",
    }
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


@app.command()
def investigate(
    seed_type: EntityType = typer.Option(
        ..., "--seed-type", help="Seed entity type (domain/host/ip/email/phone/username)."
    ),
    seed_value: str = typer.Option(..., "--seed-value", help="Seed entity value."),
    name: str = typer.Option("investigation", "--name", help="Investigation name."),
    depth: int = typer.Option(1, "--depth", min=0, max=3, help="How many pivot hops to expand."),
    sites: Path = typer.Option(
        DEFAULT_SITES_PATH, "--sites", help="Site registry for username transforms."
    ),
    geo: bool = typer.Option(False, "--geo", help="Enable IP geolocation/ASN (third-party)."),
    log: Path = typer.Option(DEFAULT_INVESTIGATION_LOG, "--log", help="Investigation audit log."),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for the fan-out."
    ),
    output: Path = typer.Option(
        Path("examples/output/argus-investigation.json"), "--output", help="Graph JSON output."
    ),
    mermaid: Path | None = typer.Option(
        None, "--mermaid", help="If set, also write a Mermaid diagram of the graph."
    ),
    dot: Path | None = typer.Option(
        None, "--dot", help="If set, also write a Graphviz DOT graph."
    ),
    graphml: Path | None = typer.Option(
        None, "--graphml", help="If set, also write a GraphML graph (Gephi/Neo4j/yEd)."
    ),
) -> None:
    """Build an OSINT investigation graph by pivoting from a seed entity (flowsint-style)."""
    if not i_am_authorized:
        typer.echo(f"argus: {_INVESTIGATE_DISCLAIMER}", err=True)
        raise typer.Exit(code=4)

    try:
        site_specs = load_site_registry(sites)
    except SiteRegistryError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    _log_investigation(name, seed_type.value, seed_value, log)
    ctx = TransformContext(
        resolver=DnspythonResolver(),
        ct_client=CrtShClient(),
        http=UrllibHttpClient.from_config(),
        site_specs=site_specs,
        geolocate=geo,
    )
    graph = run_investigation(name, seed_type, seed_value, ctx, depth=depth)

    typer.echo(json.dumps(graph.to_dict(), indent=2, sort_keys=True))
    export_investigation(graph, output)
    for target, renderer in (
        (mermaid, graph.to_mermaid),
        (dot, graph.to_dot),
        (graphml, graph.to_graphml),
    ):
        if target is not None:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(renderer(), encoding="utf-8")
    typer.echo(
        f"argus: investigation '{name}' — {len(graph.entities)} entit(y/ies), "
        f"{len(graph.relationships)} edge(s); {output}",
        err=True,
    )
