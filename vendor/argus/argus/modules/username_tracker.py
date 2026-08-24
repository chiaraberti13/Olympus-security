"""Concurrent username lookup across many platforms.

Detection engine
----------------
Naive "HTTP 200 means the profile exists" checks produce a lot of false
results: many big platforms answer ``200`` for *every* URL, redirect unknown
users to a login/home page, or block automated clients outright. Argus uses a
richer, Sherlock-style model instead. Each site in ``data/sites.json`` declares
how presence is detected via ``errorType``:

  * ``status_code`` (default) — the profile exists when the request returns a
    2xx status **and was not redirected away**. Explicit "not found" codes
    (404/410/…) mean the name is free.
  * ``message`` — the page always returns 200, so we look for a marker string
    (``errorMsg``) that is only present when the profile does *not* exist.
  * ``response_url`` — a missing profile is redirected to a generic page; if the
    final URL matches ``errorUrl`` (or any redirect happens) the name is free.

Crucially, anti-bot / auth responses (401/403/406/429) are reported as
``blocked`` rather than being silently miscounted as found or not-found, so the
results never pretend to a certainty they don't have.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib import resources
from pathlib import Path
from typing import Callable, Iterable, Optional

from ..config import Config
from ..utils import build_session

_STATUS_FOUND = "found"
_STATUS_NOT_FOUND = "not found"
_STATUS_BLOCKED = "blocked"
_STATUS_ERROR = "error"

# Status codes that explicitly mean "this username is free".
_NOT_FOUND_CODES = {404, 410}
# Status codes that mean "the site refused to answer" (auth wall / rate limit /
# anti-bot). These are reported as `blocked` — an honest "unknown", not a result.
_BLOCKED_CODES = {401, 403, 406, 429, 451}

# Browser-like headers reduce (but never eliminate) anti-bot blocking.
_BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def load_catalogue() -> dict:
    """Return the full site catalogue document (with metadata)."""
    candidate = Path(__file__).resolve().parents[2] / "data" / "sites.json"
    if candidate.exists():
        return json.loads(candidate.read_text(encoding="utf-8"))
    try:  # Fallback: packaged data (if shipped inside the wheel).
        with resources.files("argus").joinpath("../data/sites.json").open(
            "r", encoding="utf-8"
        ) as fh:  # pragma: no cover
            return json.load(fh)
    except Exception:  # pragma: no cover
        return {"sites": []}


def load_sites() -> list[dict]:
    """Load just the list of target sites from the catalogue."""
    return load_catalogue().get("sites", [])


def _error_type(site: dict) -> str:
    """Resolve the detection strategy, honouring the legacy ``method`` key."""
    etype = site.get("errorType") or site.get("method") or "status_code"
    return {"status": "status_code", "text": "message"}.get(etype, etype)


def _as_list(value) -> list[str]:
    if not value:
        return []
    return [value] if isinstance(value, str) else list(value)


def _classify(site: dict, resp) -> str:
    """Map an HTTP response to a detection status for a single site."""
    status = resp.status_code
    if status in _BLOCKED_CODES:
        return _STATUS_BLOCKED
    if status in _NOT_FOUND_CODES:
        return _STATUS_NOT_FOUND

    etype = _error_type(site)

    if etype == "message":
        # Page always returns 200; a marker string appears only when free.
        if not (200 <= status < 300):
            return _STATUS_NOT_FOUND
        markers = _as_list(site.get("errorMsg") or site.get("absence"))
        try:
            body = resp.text
        except Exception:  # pragma: no cover - decoding issues
            return _STATUS_ERROR
        taken = not any(m in body for m in markers)
        return _STATUS_FOUND if taken else _STATUS_NOT_FOUND

    if etype == "response_url":
        # Missing profiles get redirected to a generic page.
        if not (200 <= status < 300):
            return _STATUS_NOT_FOUND
        error_url = site.get("errorUrl", "")
        final_url = str(getattr(resp, "url", ""))
        redirected = bool(getattr(resp, "history", None))
        if error_url:
            return _STATUS_NOT_FOUND if error_url in final_url else _STATUS_FOUND
        return _STATUS_NOT_FOUND if redirected else _STATUS_FOUND

    # Default: status_code — exists on a 2xx that was not redirected away.
    if 200 <= status < 300:
        if getattr(resp, "history", None) and not site.get("allowRedirects", False):
            return _STATUS_NOT_FOUND
        return _STATUS_FOUND
    if 300 <= status < 400:
        return _STATUS_NOT_FOUND
    return _STATUS_BLOCKED


def _check_one(session, site: dict, username: str, timeout: float) -> dict:
    url = site["url"].format(username=username)
    record = {
        "site": site["name"],
        "url": url,
        "category": site.get("category", "misc"),
        "status": _STATUS_ERROR,
        "http_status": None,
    }
    # Some sites can't host certain usernames at all (length / charset rules).
    regex = site.get("regexCheck")
    if regex:
        import re

        if not re.match(regex, username):
            record["status"] = _STATUS_NOT_FOUND
            record["note"] = "username not valid for this site"
            return record

    # `message`/`response_url` need to follow redirects to inspect the final
    # page; `status_code` follows them too but treats a redirect as "not found".
    allow_redirects = _error_type(site) != "status_code" or site.get("allowRedirects", False)
    headers = dict(_BROWSER_HEADERS)
    headers.update(site.get("headers", {}))
    try:
        resp = session.get(
            url, timeout=timeout, allow_redirects=allow_redirects, headers=headers
        )
        record["http_status"] = resp.status_code
        record["status"] = _classify(site, resp)
    except Exception as exc:  # network/timeouts are expected for some sites
        record["error"] = type(exc).__name__
    return record


def lookup(
    username: str,
    config: Optional[Config] = None,
    sites: Optional[Iterable[dict]] = None,
    on_result: Optional[Callable[[dict], None]] = None,
) -> dict:
    """Check ``username`` across all configured sites concurrently.

    ``on_result`` is called with each per-site record as it completes, enabling
    live UI updates. Returns a summary dict with the full list under ``results``.
    """
    config = config or Config.load()
    sites = list(sites) if sites is not None else load_sites()
    if not sites:
        return {"error": "no sites configured (data/sites.json missing?)", "username": username}

    session = build_session(config)
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=config.max_workers) as pool:
        futures = {
            pool.submit(_check_one, session, site, username, config.timeout): site
            for site in sites
        }
        for future in as_completed(futures):
            record = future.result()
            results.append(record)
            if on_result:
                on_result(record)

    order = {_STATUS_FOUND: 0, _STATUS_BLOCKED: 1, _STATUS_NOT_FOUND: 2, _STATUS_ERROR: 3}
    results.sort(key=lambda r: (order.get(r["status"], 9), r["site"].lower()))
    found = [r for r in results if r["status"] == _STATUS_FOUND]
    blocked = [r for r in results if r["status"] == _STATUS_BLOCKED]
    return {
        "username": username,
        "checked": len(results),
        "found_count": len(found),
        "blocked_count": len(blocked),
        "results": results,
    }
