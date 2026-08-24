"""Shared helpers: HTTP session, validation, timing."""
from __future__ import annotations

import ipaddress
import re
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    Retry = None

from .config import Config

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def build_session(config: Config) -> requests.Session:
    """Create a configured requests session with retries and a shared UA."""
    session = requests.Session()
    session.headers.update({"User-Agent": config.user_agent})
    session.verify = config.verify_ssl
    if Retry is not None and config.retries > 0:
        retry = Retry(
            total=config.retries,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD"]),
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    return session


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip())
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local)
    except ValueError:
        return False


def is_valid_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value.strip()))


def is_valid_username(value: str) -> bool:
    return bool(_USERNAME_RE.match(value.strip()))


def normalize_phone(value: str) -> str:
    value = value.strip()
    if value and not value.startswith("+"):
        value = "+" + value
    return value


def human_bool(value: Optional[bool]) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"
