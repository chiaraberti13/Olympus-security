"""Command-line interface for the Argus module."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from pydantic import ValidationError

from olympus.argus.assets import build_assets, export_assets, load_assets
from olympus.argus.ct import CrtShClient, CtQueryError, CtRecon, enumerate_subdomains
from olympus.argus.demo_data import (
    DEMO_DOMAIN,
    DEMO_PHONE_NUMBER,
    DemoCtClient,
    DemoMessagingPresenceClient,
    DemoPhoneEnrichmentClient,
    DemoResolver,
)
from olympus.argus.diff import diff_snapshots
from olympus.argus.enrichment import (
    EnrichmentError,
    HudsonRockBreachClient,
    MessagingPresence,
    NumverifyClient,
    PhoneEnrichment,
    RapidApiMessagingClient,
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
from olympus.argus.recon import scan_domain
from olympus.argus.resolver import DnspythonResolver
from olympus.argus.scope import OutOfScopeError, ScopeError, enforce_scope
from olympus.core.http import UrllibHttpClient

app = typer.Typer(
    help="Argus — OSINT & passive recon.",
    no_args_is_help=True,
)

DEFAULT_SCOPE_PATH = Path("examples/input/argus-scope.json")
DEFAULT_BLOCK_LOG_PATH = Path("examples/output/argus-blocked.log")
DEMO_ASSETS_OUTPUT_PATH = Path("examples/output/argus-assets.json")
DEMO_PREVIOUS_ASSETS_PATH = Path("examples/input/argus-assets-previous.json")

DEFAULT_PHONE_SCOPE_PATH = Path("examples/input/argus-phone-scope.json")
DEFAULT_PHONE_BLOCK_LOG_PATH = Path("examples/output/argus-phone-blocked.log")
DEMO_PHONE_OUTPUT_PATH = Path("examples/output/argus-phone-intel.json")

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
    previous: Path = typer.Option(..., "--previous", help="Older argus-assets.json snapshot."),
    current: Path = typer.Option(..., "--current", help="Newer argus-assets.json snapshot."),
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


def _collect_enrichment(
    e164: str, *, enrich: bool, breach: bool
) -> PhoneEnrichment | None:
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


@app.command()
def phone(
    number: str = typer.Option(
        ..., "--number", help="Phone number: E.164 (e.g. +14155550123) or national with --region."
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
        None, "--output", help="If set, export the phone-intel bundle as JSON to this path."
    ),
) -> None:
    """Profile a single in-scope phone number (offline parsing + opt-in real lookups)."""
    try:
        report = analyze_phone(number, region)
    except PhoneParseError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    target = report.e164 or number
    try:
        enforce_phone_scope(target, scope, log)
    except PhoneScopeError as exc:
        typer.echo(f"argus: phone scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except PhoneOutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    wants_real = enrich or breach or messaging
    if wants_real and not i_am_authorized:
        typer.echo(f"argus: {_AUTH_DISCLAIMER}", err=True)
        raise typer.Exit(code=4)

    enrichment_result: PhoneEnrichment | None = None
    messaging_result: MessagingPresence | None = None
    if wants_real and report.e164 is not None:
        enrichment_result = _collect_enrichment(report.e164, enrich=enrich, breach=breach)
        messaging_result = _collect_messaging(report.e164, messaging=messaging)

    asset = build_phone_asset(report)
    findings = build_phone_findings(asset.asset_id, report, enrichment_result, messaging_result)
    intel = PhoneIntel(report=report, asset=asset, findings=findings)

    typer.echo(json.dumps(intel.to_dict(), indent=2, sort_keys=True))
    if output is not None:
        export_phone_intel(intel, output)
        typer.echo(f"argus: wrote phone intel ({len(findings)} finding(s)) to {output}", err=True)


@app.command("phone-demo")
def phone_demo() -> None:
    """Run the phone-OSINT pipeline on a synthetic, fictional number, fully offline.

    Deterministic and network-free: the number is a reserved fictional NANP
    number and enrichment/messaging come from offline doubles, but every other
    step (scope enforcement, offline parsing, asset/finding building, export)
    is the same production code path used by ``argus phone``.
    """
    typer.echo(f"argus: phone-demo — profiling {DEMO_PHONE_NUMBER} (synthetic, fictional)")
    enforce_phone_scope(DEMO_PHONE_NUMBER, DEFAULT_PHONE_SCOPE_PATH, DEFAULT_PHONE_BLOCK_LOG_PATH)

    report = analyze_phone(DEMO_PHONE_NUMBER)
    enrichment_result = DemoPhoneEnrichmentClient().enrich(DEMO_PHONE_NUMBER)
    messaging_result = DemoMessagingPresenceClient().lookup(DEMO_PHONE_NUMBER)

    asset = build_phone_asset(report)
    findings = build_phone_findings(asset.asset_id, report, enrichment_result, messaging_result)
    intel = PhoneIntel(report=report, asset=asset, findings=findings)

    typer.echo(json.dumps(intel.to_dict(), indent=2, sort_keys=True))
    export_phone_intel(intel, DEMO_PHONE_OUTPUT_PATH)
    typer.echo(f"argus: wrote phone intel ({len(findings)} finding(s)) to {DEMO_PHONE_OUTPUT_PATH}")
