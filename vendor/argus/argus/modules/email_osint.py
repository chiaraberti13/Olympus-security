"""Lightweight, privacy-respecting email OSINT.

This module only uses passive, non-intrusive techniques:
  * Syntactic validation.
  * Splitting local/domain parts and checking the domain has MX records
    (i.e. can it receive mail at all).
  * Deriving the Gravatar URL from the email hash (public avatar service).

It deliberately does NOT attempt to verify mailbox existence via SMTP probing
or query breach databases without an API key, keeping the module ethical and
dependency-light.
"""
from __future__ import annotations

import hashlib
import socket
from typing import Optional

from ..config import Config
from ..utils import build_session, is_valid_email


def _has_mx(domain: str) -> Optional[bool]:
    """Best-effort MX check. Returns None if resolution is unavailable."""
    try:
        import dns.resolver  # type: ignore

        try:
            answers = dns.resolver.resolve(domain, "MX")
            return len(answers) > 0
        except Exception:
            return False
    except ImportError:
        # dnspython not installed — fall back to a simple A-record lookup,
        # which at least confirms the domain resolves.
        try:
            socket.gethostbyname(domain)
            return None  # domain resolves, but MX unknown
        except socket.gaierror:
            return False


def lookup(email: str, config: Optional[Config] = None) -> dict:
    config = config or Config.load()
    email = email.strip().lower()

    if not is_valid_email(email):
        return {"error": f"'{email}' is not a syntactically valid email", "input": email}

    local, _, domain = email.partition("@")
    md5 = hashlib.md5(email.encode("utf-8")).hexdigest()  # noqa: S324 - Gravatar requires MD5
    sha256 = hashlib.sha256(email.encode("utf-8")).hexdigest()

    result = {
        "email": email,
        "local_part": local,
        "domain": domain,
        "valid_syntax": True,
        "domain_has_mx": _has_mx(domain),
        "gravatar_url": f"https://www.gravatar.com/avatar/{md5}?d=404",
        "md5": md5,
        "sha256": sha256,
    }

    # Check whether a Gravatar actually exists (404 = none).
    try:
        session = build_session(config)
        resp = session.get(result["gravatar_url"], timeout=config.timeout)
        result["gravatar_exists"] = resp.status_code == 200
    except Exception:  # pragma: no cover - network dependent
        result["gravatar_exists"] = None

    return result
