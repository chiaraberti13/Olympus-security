"""Command-line interface: interactive menu + scriptable subcommands."""
from __future__ import annotations

import argparse
import sys
from typing import Optional

from . import __version__, banner, ui, updater
from .config import Config
from .exporters import export
from .modules import (
    dns_lookup,
    email_osint,
    ip_tracker,
    mac_lookup,
    myip,
    phone_tracker,
    username_tracker,
    web_recon,
)
from .modules import (
    domain as domain_mod,
)

DISCLAIMER = (
    "Argus is provided for authorized security research, OSINT training and "
    "educational purposes only. You are solely responsible for complying with all "
    "applicable laws. Only gather information you are legally permitted to access."
)


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #
def _maybe_export(data: dict, kind: str, config: Config, fmt: Optional[str]) -> None:
    if not fmt or fmt == "none":
        return
    try:
        path = export(data, kind, fmt, config)
        ui.success(f"Report saved: {path}")
    except Exception as exc:
        ui.error(f"Export failed: {exc}")


def render_ip(data: dict) -> None:
    if "error" in data:
        ui.error(data["error"])
        return
    if data.get("warning"):
        ui.warn(data["warning"])
    rows = [
        ("IP", data.get("ip")),
        ("Type", data.get("type")),
        ("Country", f"{data.get('country')} ({data.get('country_code')})"),
        ("Region", data.get("region")),
        ("City", data.get("city")),
        ("Postal", data.get("postal")),
        ("Coordinates", f"{data.get('latitude')}, {data.get('longitude')}"),
        ("Timezone", f"{data.get('timezone')} {data.get('utc_offset') or ''}".strip()),
        ("ISP", data.get("isp")),
        ("Organization", data.get("org")),
        ("ASN", data.get("asn")),
        ("Google Maps", data.get("google_maps")),
        ("Source", data.get("source")),
    ]
    ui.kv_table([(k, v) for k, v in rows if v not in (None, "None")], title="IP Geolocation")


def render_phone(data: dict) -> None:
    if "error" in data:
        ui.error(data["error"])
        return
    if data.get("warning"):
        ui.warn(data["warning"])
    tz = data.get("timezones")
    rows = [
        ("Input", data.get("input")),
        ("Valid", "yes" if data.get("valid") else "no"),
        ("Possible", "yes" if data.get("possible") else "no"),
        ("Country code", f"+{data.get('country_code')}"),
        ("Line type", data.get("line_type")),
        ("Region", data.get("region")),
        ("Carrier", data.get("carrier")),
        ("Timezone(s)", ", ".join(tz) if tz else None),
        ("E.164", data.get("format_e164")),
        ("International", data.get("format_international")),
        ("National", data.get("format_national")),
        ("RFC3966", data.get("format_rfc3966")),
    ]
    ui.kv_table([(k, v) for k, v in rows if v], title="Phone Intelligence")


def render_username(data: dict) -> None:
    if "error" in data:
        ui.error(data["error"])
        return
    found = [r for r in data["results"] if r["status"] == "found"]
    blocked = [r for r in data["results"] if r["status"] == "blocked"]
    ui.results_table(
        ["Site", "Category", "URL"],
        [(r["site"], r["category"], r["url"]) for r in found],
        title=f"'{data['username']}' found on {data['found_count']}/{data['checked']} sites",
    )
    if not found:
        ui.warn("No profiles confidently found.")
    if blocked:
        names = ", ".join(sorted(r["site"] for r in blocked))
        ui.warn(
            f"{len(blocked)} site(s) could not be checked (anti-bot / rate limit): {names}. "
            "Treat these as 'unknown', not 'absent'."
        )


def render_email(data: dict) -> None:
    if "error" in data:
        ui.error(data["error"])
        return
    tri = {True: "yes", False: "no", None: "unknown"}
    rows = [
        ("Email", data.get("email")),
        ("Local part", data.get("local_part")),
        ("Domain", data.get("domain")),
        ("Valid syntax", "yes" if data.get("valid_syntax") else "no"),
        ("Domain has MX", tri[data.get("domain_has_mx")]),
        ("Gravatar exists", tri[data.get("gravatar_exists")]),
        ("Gravatar URL", data.get("gravatar_url") if data.get("gravatar_exists") else None),
        ("MD5", data.get("md5")),
        ("SHA-256", data.get("sha256")),
    ]
    ui.kv_table([(k, v) for k, v in rows if v is not None], title="Email OSINT")


def render_myip(data: dict) -> None:
    if "error" in data:
        ui.error(data["error"])
        return
    ui.kv_table([("Public IP", data["public_ip"])], title="Your Public IP")
    if data.get("geo"):
        render_ip(data["geo"])


def render_domain(data: dict) -> None:
    if "error" in data:
        ui.error(data["error"])
        return
    status = data.get("status")
    rows = [
        ("Domain", data.get("domain")),
        ("Registrar", data.get("registrar")),
        ("Registered", data.get("registered")),
        ("Expires", data.get("expires")),
        ("Last changed", data.get("last_changed")),
        ("Name servers", ", ".join(data["nameservers"]) if data.get("nameservers") else None),
        ("Status", ", ".join(status) if status else None),
        ("DNSSEC", {True: "signed", False: "unsigned", None: "unknown"}.get(data.get("dnssec"))),
        ("Source", data.get("source")),
    ]
    ui.kv_table([(k, v) for k, v in rows if v], title="Domain / WHOIS (RDAP)")


def render_dns(data: dict) -> None:
    if "error" in data:
        ui.error(data["error"])
        return
    rows = []
    for rtype, values in data.get("records", {}).items():
        for value in values:
            rows.append((rtype, value))
    ui.results_table(["Type", "Value"], rows, title=f"DNS records for {data['domain']}")


def render_web(data: dict) -> None:
    if "error" in data:
        ui.error(data["error"])
        return
    present = data.get("security_headers_present") or {}
    missing = data.get("security_headers_missing") or []
    rows = [
        ("URL", data.get("url")),
        ("Final URL", data.get("final_url")),
        ("Status", f"{data.get('status_code')} {data.get('reason') or ''}".strip()),
        ("Host", data.get("host")),
        ("Resolved IP", data.get("ip")),
        ("Redirected", "yes" if data.get("redirected") else "no"),
        ("Server", data.get("server")),
        ("Content-Type", data.get("content_type")),
        ("Security headers", f"{len(present)} present, {len(missing)} missing"),
    ]
    ui.kv_table([(k, v) for k, v in rows if v not in (None, "")], title="Web / HTTP Recon")
    if missing:
        ui.warn("Missing security headers: " + ", ".join(missing))


def _startup_update_check(config: Config) -> None:
    """Non-blocking, cached hint if newer dependencies exist. Never raises."""
    if getattr(config, "auto_update", False):
        ui.info("auto_update is on — upgrading dependencies …")
        result = updater.update_dependencies()
        ui.success("Dependencies upgraded.") if result.get("ok") else ui.warn(
            "Automatic upgrade failed; run 'argus update --deps' manually."
        )
        return
    if not getattr(config, "update_check", True):
        return
    try:
        result = updater.check_for_updates(config)
    except Exception:  # pragma: no cover - must never break startup
        return
    outdated = result.get("outdated") or []
    if outdated:
        pkgs = ", ".join(f"{o['package']} {o['installed']}→{o['latest']}" for o in outdated)
        ui.warn(f"Updates available: {pkgs}. Run 'argus update' to upgrade.")


def render_update(config: Config, do_deps: bool, do_sites: bool, check_only: bool) -> None:
    if check_only:
        deps = updater.check_dependencies()
        rows = [
            (
                d["package"] + (" (optional)" if d["optional"] else ""),
                (d["installed"] or "not installed")
                + ("  ⚠ outdated" if d["outdated"] else "")
                + ("  ⚠ missing" if d["missing"] and not d["optional"] else ""),
            )
            for d in deps
        ]
        ui.kv_table(rows, title="Installed dependencies")
        result = updater.check_for_updates(config, force=True)
        outdated = result.get("outdated") or []
        if outdated:
            ui.warn(
                "Newer releases on PyPI: "
                + ", ".join(f"{o['package']} {o['installed']}→{o['latest']}" for o in outdated)
            )
        else:
            ui.success("All dependencies are up to date.")
        return

    if do_deps:
        ui.info("Upgrading dependencies via pip (this may take a moment) …")
        result = updater.update_dependencies(include_optional=True)
        if result.get("ok"):
            ui.success("Dependencies upgraded successfully.")
        else:
            ui.error("Dependency upgrade failed.")
            if result.get("stderr"):
                ui.echo(result["stderr"])
    if do_sites:
        ui.info("Refreshing username site catalogue …")
        result = updater.refresh_sites(config)
        if not result.get("ok"):
            ui.error(f"Site refresh failed: {result.get('error')}")
        elif result.get("updated"):
            ui.success(
                f"Site catalogue updated to v{result['remote_version']} "
                f"({result['sites']} sites)."
            )
        else:
            ui.info(f"Site catalogue already current: {result.get('reason', 'no change')}.")


def render_mac(data: dict) -> None:
    if "error" in data:
        ui.error(data["error"])
        return
    rows = [
        ("MAC", data.get("mac")),
        ("OUI", data.get("oui")),
        ("Vendor", data.get("vendor")),
        ("Locally administered", "yes" if data.get("locally_administered") else "no"),
        ("Multicast", "yes" if data.get("multicast") else "no"),
        ("Source", data.get("source")),
    ]
    ui.kv_table([(k, v) for k, v in rows if v], title="MAC Vendor Lookup")


# --------------------------------------------------------------------------- #
# Interactive menu
# --------------------------------------------------------------------------- #
MENU = """
  [bold cyan] 1[/bold cyan]  IP address geolocation
  [bold cyan] 2[/bold cyan]  Phone number intelligence
  [bold cyan] 3[/bold cyan]  Username lookup (50+ sites)
  [bold cyan] 4[/bold cyan]  Email OSINT
  [bold cyan] 5[/bold cyan]  Domain / WHOIS (RDAP)
  [bold cyan] 6[/bold cyan]  DNS records (DoH)
  [bold cyan] 7[/bold cyan]  Web / HTTP recon
  [bold cyan] 8[/bold cyan]  MAC vendor lookup
  [bold cyan] 9[/bold cyan]  Show my public IP
  [bold cyan]10[/bold cyan]  Settings
  [bold cyan]11[/bold cyan]  Update (dependencies + site list)
  [bold cyan] 0[/bold cyan]  Exit
"""


def _ask_export(config: Config) -> Optional[str]:
    choice = ui.prompt("Export report? [n]one / json / csv / html:").strip().lower()
    return choice if choice in {"json", "csv", "html"} else None


def interactive(config: Config) -> int:
    ui.clear()
    banner.show()
    ui.panel(DISCLAIMER, title="Legal notice")
    _startup_update_check(config)
    while True:
        ui.echo(MENU)
        try:
            choice = ui.prompt("argus ›").strip()
        except (EOFError, KeyboardInterrupt):
            ui.echo("\nBye.")
            return 0

        try:
            if choice == "1":
                ip = ui.prompt("Target IP address:")
                data = ip_tracker.lookup(ip, config)
                render_ip(data)
                _maybe_export(data, "ip", config, _ask_export(config))
            elif choice == "2":
                num = ui.prompt("Phone number (+country...):")
                data = phone_tracker.lookup(num)
                render_phone(data)
                _maybe_export(data, "phone", config, _ask_export(config))
            elif choice == "3":
                user = ui.prompt("Username to search:")
                data = _run_username(user, config)
                render_username(data)
                _maybe_export(data, "username", config, _ask_export(config))
            elif choice == "4":
                email = ui.prompt("Email address:")
                data = email_osint.lookup(email, config)
                render_email(data)
                _maybe_export(data, "email", config, _ask_export(config))
            elif choice == "5":
                dom = ui.prompt("Domain name (example.com):")
                data = domain_mod.lookup(dom, config)
                render_domain(data)
                _maybe_export(data, "domain", config, _ask_export(config))
            elif choice == "6":
                dom = ui.prompt("Domain name (example.com):")
                data = dns_lookup.lookup(dom, config)
                render_dns(data)
                _maybe_export(data, "dns", config, _ask_export(config))
            elif choice == "7":
                target = ui.prompt("URL or host (example.com):")
                data = web_recon.lookup(target, config)
                render_web(data)
                _maybe_export(data, "web", config, _ask_export(config))
            elif choice == "8":
                mac = ui.prompt("MAC address (aa:bb:cc:dd:ee:ff):")
                data = mac_lookup.lookup(mac, config)
                render_mac(data)
                _maybe_export(data, "mac", config, _ask_export(config))
            elif choice == "9":
                data = myip.my_ip(config)
                render_myip(data)
            elif choice == "10":
                _settings_menu(config)
            elif choice == "11":
                render_update(config, do_deps=True, do_sites=True, check_only=False)
            elif choice in {"0", "q", "exit", "quit"}:
                ui.echo("Bye.")
                return 0
            else:
                ui.warn("Unknown option.")
        except KeyboardInterrupt:
            ui.warn("Cancelled.")
        ui.echo()


def _run_username(user: str, config: Config) -> dict:
    if not user.strip():
        return {"error": "empty username", "username": user}
    sites = username_tracker.load_sites()
    ui.info(f"Checking {len(sites)} sites for '{user}' …")
    collected: list[dict] = []

    def _sink(_record):
        collected.append(_record)

    # Drive the lookup while showing a progress bar.
    result_holder: dict = {}

    def _worker():
        result_holder.update(username_tracker.lookup(user, config, sites, on_result=_sink))

    import threading

    t = threading.Thread(target=_worker)
    t.start()
    total = len(sites)
    for _ in ui.progress_iter(_wait_progress(collected, total), "Scanning", total=total):
        pass
    t.join()
    return result_holder


def _wait_progress(collected: list, total: int):
    """Yield once per completed site so the progress bar advances live."""
    import time

    seen = 0
    while seen < total:
        current = len(collected)
        while seen < current:
            seen += 1
            yield seen
        time.sleep(0.05)


def _settings_menu(config: Config) -> None:
    rows = [
        ("timeout", config.timeout),
        ("max_workers", config.max_workers),
        ("retries", config.retries),
        ("verify_ssl", config.verify_ssl),
        ("output_dir", config.output_dir),
        ("user_agent", config.user_agent),
        ("update_check", config.update_check),
        ("update_check_interval_days", config.update_check_interval_days),
        ("auto_update", config.auto_update),
    ]
    ui.kv_table(rows, title="Current settings")
    ui.info("Persist changes with 'argus config --init', then edit the JSON file.")


# --------------------------------------------------------------------------- #
# Argument parsing / non-interactive subcommands
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    # Options shared by every subcommand (accepted before OR after the target).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS,
        help="disable colored output",
    )
    common.add_argument(
        "--export",
        choices=["json", "csv", "html"],
        default=argparse.SUPPRESS,
        help="export result to a report",
    )
    common.add_argument(
        "--timeout",
        type=float,
        default=argparse.SUPPRESS,
        help="per-request timeout in seconds",
    )
    common.add_argument(
        "--workers",
        type=int,
        default=argparse.SUPPRESS,
        help="max concurrent workers (username lookup)",
    )

    p = argparse.ArgumentParser(
        prog="argus",
        description="Argus — the all-seeing OSINT & reconnaissance toolkit.",
        epilog="Run without a subcommand to launch the interactive menu.",
        parents=[common],
    )
    p.add_argument("--version", action="version", version=f"Argus {__version__}")

    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("ip", help="geolocate an IP address", parents=[common])
    sp.add_argument("address")

    sp = sub.add_parser("phone", help="analyze a phone number", parents=[common])
    sp.add_argument("number")
    sp.add_argument("--region", help="default ISO region, e.g. US, IT, GB")

    sp = sub.add_parser("username", help="search a username across sites", parents=[common])
    sp.add_argument("name")

    sp = sub.add_parser("email", help="passive email OSINT", parents=[common])
    sp.add_argument("address")

    sp = sub.add_parser("domain", help="domain / WHOIS lookup via RDAP", parents=[common])
    sp.add_argument("name")

    sp = sub.add_parser("dns", help="DNS records via DNS-over-HTTPS", parents=[common])
    sp.add_argument("name")
    sp.add_argument(
        "--types",
        help="comma-separated record types (default: A,AAAA,MX,TXT,NS,CNAME,SOA)",
    )

    sp = sub.add_parser("web", help="website / HTTP reconnaissance", parents=[common])
    sp.add_argument("url")

    sp = sub.add_parser("mac", help="MAC address vendor lookup", parents=[common])
    sp.add_argument("address")

    sub.add_parser("myip", help="show this machine's public IP", parents=[common])

    sp = sub.add_parser("config", help="show or initialize configuration", parents=[common])
    sp.add_argument("--show", action="store_true", help="print current config")
    sp.add_argument("--init", action="store_true", help="write a default config file")

    sp = sub.add_parser(
        "update", help="update dependencies and the username site list", parents=[common]
    )
    sp.add_argument("--deps", action="store_true", help="upgrade only Python dependencies")
    sp.add_argument("--sites", action="store_true", help="refresh only the username site list")
    sp.add_argument(
        "--check", action="store_true", help="only report what is outdated, change nothing"
    )

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    export_fmt = getattr(args, "export", None)
    timeout = getattr(args, "timeout", None)
    workers = getattr(args, "workers", None)

    config = Config.load()
    if timeout:
        config.timeout = timeout
    if workers:
        config.max_workers = workers

    if not args.command:
        return interactive(config)

    if args.command == "ip":
        data = ip_tracker.lookup(args.address, config)
        render_ip(data)
        _maybe_export(data, "ip", config, export_fmt)
    elif args.command == "phone":
        data = phone_tracker.lookup(args.number, getattr(args, "region", None))
        render_phone(data)
        _maybe_export(data, "phone", config, export_fmt)
    elif args.command == "username":
        data = username_tracker.lookup(args.name, config)
        render_username(data)
        _maybe_export(data, "username", config, export_fmt)
    elif args.command == "email":
        data = email_osint.lookup(args.address, config)
        render_email(data)
        _maybe_export(data, "email", config, export_fmt)
    elif args.command == "domain":
        data = domain_mod.lookup(args.name, config)
        render_domain(data)
        _maybe_export(data, "domain", config, export_fmt)
    elif args.command == "dns":
        raw_types = getattr(args, "types", None)
        types = [t.strip().upper() for t in raw_types.split(",")] if raw_types else None
        data = dns_lookup.lookup(args.name, config, types=types)
        render_dns(data)
        _maybe_export(data, "dns", config, export_fmt)
    elif args.command == "web":
        data = web_recon.lookup(args.url, config)
        render_web(data)
        _maybe_export(data, "web", config, export_fmt)
    elif args.command == "mac":
        data = mac_lookup.lookup(args.address, config)
        render_mac(data)
        _maybe_export(data, "mac", config, export_fmt)
    elif args.command == "myip":
        data = myip.my_ip(config)
        render_myip(data)
        _maybe_export(data, "myip", config, export_fmt)
    elif args.command == "config":
        if args.init:
            path = config.save()
            ui.success(f"Config written to {path}")
        else:
            _settings_menu(config)
    elif args.command == "update":
        check_only = getattr(args, "check", False)
        want_deps = getattr(args, "deps", False)
        want_sites = getattr(args, "sites", False)
        # With no target flags, do both; --check overrides to a dry run.
        if not want_deps and not want_sites:
            want_deps = want_sites = True
        render_update(config, do_deps=want_deps, do_sites=want_sites, check_only=check_only)
    return 0


if __name__ == "__main__":
    sys.exit(main())
