"""Domain / WHOIS intelligence via RDAP.

RDAP (Registration Data Access Protocol) is the modern, structured successor to
WHOIS. We query ``rdap.org``, which redirects to the authoritative registry
server for the domain. No API key is required.

Returns registrar, important dates (registration/expiry/last-changed),
name servers and domain status flags.
"""
from __future__ import annotations

from typing import Optional

from ..config import Config
from ..utils import build_session

RDAP_ENDPOINT = "https://rdap.org/domain/{domain}"


def _extract_events(events: list) -> dict:
    out = {}
    for ev in events or []:
        action = ev.get("eventAction")
        date = ev.get("eventDate")
        if action and date:
            out[action] = date
    return out


def _extract_registrar(entities: list) -> Optional[str]:
    for ent in entities or []:
        roles = ent.get("roles", [])
        if "registrar" in roles:
            # vCard array: ["vcard", [ [ "fn", {}, "text", "Name" ], ... ]]
            vcard = ent.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field and field[0] == "fn":
                        return field[3]
            return ent.get("handle")
    return None


def lookup(domain: str, config: Optional[Config] = None) -> dict:
    config = config or Config.load()
    domain = domain.strip().lower().strip(".")
    # Strip a scheme/path if the user pasted a URL.
    if "//" in domain:
        domain = domain.split("//", 1)[1]
    domain = domain.split("/", 1)[0].split(":", 1)[0]

    if "." not in domain or " " in domain:
        return {"error": f"'{domain}' does not look like a domain name", "input": domain}

    session = build_session(config)
    try:
        resp = session.get(
            RDAP_ENDPOINT.format(domain=domain),
            timeout=config.timeout,
            headers={"Accept": "application/rdap+json"},
        )
    except Exception as exc:  # pragma: no cover - network dependent
        return {"error": f"network error: {exc}", "domain": domain}

    if resp.status_code == 404:
        return {"error": "domain not found / not registered (or no RDAP data)", "domain": domain}
    try:
        data = resp.json()
    except ValueError:
        return {"error": "registry returned a non-JSON response", "domain": domain}

    events = _extract_events(data.get("events", []))
    nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]

    return {
        "domain": data.get("ldhName", domain),
        "handle": data.get("handle"),
        "registrar": _extract_registrar(data.get("entities", [])),
        "status": data.get("status") or None,
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed") or events.get("last update of RDAP database"),
        "nameservers": nameservers or None,
        "dnssec": (data.get("secureDNS") or {}).get("delegationSigned"),
        "source": "rdap.org",
    }
