"""Command-line interface for the Argus module."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.argus.accounts import (
    AccountIntel,
    AccountScanResult,
    SiteRegistryError,
    build_account_assets,
    build_account_finding,
    enumerate_accounts,
    export_account_intel,
    load_site_registry,
)
from olympus.argus.accounts_scope import (
    AccountOutOfScopeError,
    AccountScopeError,
    enforce_account_scope,
)
from olympus.argus.assets import export_assets, recon_to_assets
from olympus.argus.ct import CertificateTransparencyError, CrtShClient
from olympus.argus.demo_data import (
    DEMO_ACCOUNT_HANDLE,
    DEMO_PHONE_NUMBER,
    DemoAccountHttpClient,
    DemoMessagingPresenceClient,
    DemoPhoneEnrichmentClient,
    demo_site_specs,
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
DEFAULT_ASSETS_PATH = Path("examples/output/argus-assets.json")

DEFAULT_PHONE_SCOPE_PATH = Path("examples/input/argus-phone-scope.json")
DEFAULT_PHONE_BLOCK_LOG_PATH = Path("examples/output/argus-phone-blocked.log")
DEMO_PHONE_OUTPUT_PATH = Path("examples/output/argus-phone-intel.json")

DEFAULT_SITES_PATH = Path("examples/input/argus-sites.json")
DEFAULT_ACCOUNT_SCOPE_PATH = Path("examples/input/argus-accounts-scope.json")
DEFAULT_ACCOUNT_BLOCK_LOG_PATH = Path("examples/output/argus-accounts-blocked.log")
DEMO_ACCOUNT_OUTPUT_PATH = Path("examples/output/argus-accounts-intel.json")

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


def _build_account_intel(result: AccountScanResult) -> AccountIntel:
    """Turn a raw scan into assets + a summary finding bundle."""
    assets = build_account_assets(result)
    finding = build_account_finding(assets[0].asset_id, result) if assets else None
    return AccountIntel(result=result, assets=assets, findings=[finding] if finding else [])


@app.command()
def accounts(
    username: str = typer.Option(..., "--username", help="Handle to enumerate across sites."),
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
    output: Path | None = typer.Option(
        None, "--output", help="If set, export the account-intel bundle as JSON to this path."
    ),
) -> None:
    """Enumerate a single in-scope handle across a curated list of public sites."""
    try:
        enforce_account_scope(username, scope, log)
    except AccountScopeError as exc:
        typer.echo(f"argus: account scope error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except AccountOutOfScopeError as exc:
        typer.echo(f"argus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    if metadata and not i_am_authorized:
        typer.echo(f"argus: {_METADATA_DISCLAIMER}", err=True)
        raise typer.Exit(code=4)

    try:
        specs = load_site_registry(sites)
    except SiteRegistryError as exc:
        typer.echo(f"argus: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    result = enumerate_accounts(username, specs, UrllibHttpClient(), want_metadata=metadata)
    intel = _build_account_intel(result)

    typer.echo(json.dumps(intel.to_dict(), indent=2, sort_keys=True))
    hits = len(result.existing())
    typer.echo(f"argus: '{username}' found on {hits}/{len(specs)} site(s)", err=True)
    if output is not None:
        export_account_intel(intel, output)
        typer.echo(f"argus: wrote account intel to {output}", err=True)


@app.command("accounts-demo")
def accounts_demo() -> None:
    """Enumerate a synthetic handle across synthetic sites, fully offline.

    Deterministic and network-free: sites and responses come from
    :mod:`olympus.argus.demo_data`, but the enumeration, asset/finding
    building and export are the same production code path as ``argus accounts``.
    """
    typer.echo(f"argus: accounts-demo — enumerating {DEMO_ACCOUNT_HANDLE} (synthetic)")
    enforce_account_scope(
        DEMO_ACCOUNT_HANDLE, DEFAULT_ACCOUNT_SCOPE_PATH, DEFAULT_ACCOUNT_BLOCK_LOG_PATH
    )

    result = enumerate_accounts(
        DEMO_ACCOUNT_HANDLE, demo_site_specs(), DemoAccountHttpClient(), want_metadata=True
    )
    intel = _build_account_intel(result)

    typer.echo(json.dumps(intel.to_dict(), indent=2, sort_keys=True))
    export_account_intel(intel, DEMO_ACCOUNT_OUTPUT_PATH)
    typer.echo(
        f"argus: '{DEMO_ACCOUNT_HANDLE}' found on {len(result.existing())} site(s); "
        f"wrote {DEMO_ACCOUNT_OUTPUT_PATH}"
    )
