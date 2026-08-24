"""DNS record lookups via DNS-over-HTTPS (DoH).

Uses Cloudflare's DoH JSON API (with a Google fallback), so it needs no extra
Python dependency and works even where UDP/53 is blocked. Resolves the common
record types used in OSINT / infrastructure mapping.
"""
from __future__ import annotations

from typing import Optional

from ..config import Config
from ..utils import build_session

CLOUDFLARE = "https://cloudflare-dns.com/dns-query"
GOOGLE = "https://dns.google/resolve"

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")

# Numeric DNS type -> name, for decoding answers.
_TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA"}


def _query(session, base: str, name: str, rtype: str, timeout: float) -> Optional[list]:
    try:
        resp = session.get(
            base,
            params={"name": name, "type": rtype},
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
        )
        data = resp.json()
    except Exception:
        return None
    answers = []
    for ans in data.get("Answer", []) or []:
        answers.append(ans.get("data"))
    return answers


def lookup(
    domain: str,
    config: Optional[Config] = None,
    types: Optional[list] = None,
) -> dict:
    config = config or Config.load()
    domain = domain.strip().lower().strip(".")
    if "//" in domain:
        domain = domain.split("//", 1)[1]
    domain = domain.split("/", 1)[0]

    if "." not in domain or " " in domain:
        return {"error": f"'{domain}' does not look like a domain name", "input": domain}

    types = types or list(RECORD_TYPES)
    session = build_session(config)

    records: dict[str, list] = {}
    any_answer = False
    for rtype in types:
        answers = _query(session, CLOUDFLARE, domain, rtype, config.timeout)
        if answers is None:  # provider error → try Google
            answers = _query(session, GOOGLE, domain, rtype, config.timeout)
        if answers:
            records[rtype] = answers
            any_answer = True

    if not records and not any_answer:
        return {
            "error": "no DNS answers (domain may not exist or DoH is blocked)",
            "domain": domain,
        }

    return {"domain": domain, "records": records, "source": "cloudflare/google DoH"}
