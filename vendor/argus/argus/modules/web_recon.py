"""Passive website / HTTP reconnaissance.

Fetches a URL and reports the response chain and posture without any intrusive
probing: final URL after redirects, status code, server/technology headers,
and which common security headers are present or missing.
"""
from __future__ import annotations

import socket
from typing import Optional
from urllib.parse import urlparse

from ..config import Config
from ..utils import build_session

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

INTERESTING_HEADERS = ["Server", "X-Powered-By", "Via", "CF-RAY", "X-Cache", "Set-Cookie"]


def _normalize_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    return url


def lookup(url: str, config: Optional[Config] = None) -> dict:
    config = config or Config.load()
    url = _normalize_url(url)
    parsed = urlparse(url)
    if not parsed.netloc:
        return {"error": f"'{url}' is not a valid URL", "input": url}

    session = build_session(config)
    try:
        resp = session.get(url, timeout=config.timeout, allow_redirects=True)
    except Exception as exc:  # pragma: no cover - network dependent
        return {"error": f"could not reach site: {exc}", "url": url}

    headers = resp.headers
    present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing = [h for h in SECURITY_HEADERS if h not in headers]

    # Resolve the host's IP (best effort).
    host = urlparse(resp.url).hostname or parsed.hostname
    try:
        ip = socket.gethostbyname(host) if host else None
    except socket.gaierror:
        ip = None

    redirect_chain = [r.url for r in resp.history] + [resp.url] if resp.history else [resp.url]

    return {
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "reason": resp.reason,
        "host": host,
        "ip": ip,
        "redirected": bool(resp.history),
        "redirect_chain": redirect_chain if resp.history else None,
        "server": headers.get("Server"),
        "tech_headers": {h: headers[h] for h in INTERESTING_HEADERS if h in headers} or None,
        "security_headers_present": present or None,
        "security_headers_missing": missing or None,
        "content_type": headers.get("Content-Type"),
        "source": "direct HTTP",
    }
