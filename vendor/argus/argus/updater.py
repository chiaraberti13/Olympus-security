"""Self-update helpers: dependencies, the site catalogue and update checks.

The design deliberately separates *checking* from *installing*:

  * ``check_dependencies`` compares installed versions against the declared
    minimums — offline, instant, safe to run at every startup.
  * ``check_for_updates`` optionally asks PyPI whether newer releases exist. It
    is cached (see ``state``) so it runs at most once per interval and never
    blocks or crashes the program if the network is unavailable.
  * ``update_dependencies`` / ``refresh_sites`` actually change things and are
    only triggered by an explicit ``argus update`` (or the opt-in
    ``auto_update`` config flag) — never silently on launch.

Auto-upgrading pip packages on *every* run is intentionally NOT the default:
it is slow, needs the network, and a bad upstream release could break the tool.
Checking + notifying gives the freshness without the fragility.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from .config import Config, config_dir

# Runtime packages Argus depends on (name -> minimum version).
RUNTIME_PACKAGES = {
    "requests": "2.31.0",
    "phonenumbers": "8.13.0",
    "rich": "13.0.0",
}
OPTIONAL_PACKAGES = {
    "dnspython": "2.4.0",
}

_STATE_PATH = config_dir() / "state.json"


# --------------------------------------------------------------------------- #
# Version helpers (no external deps)
# --------------------------------------------------------------------------- #
def _parse_version(value: str) -> tuple:
    parts = []
    for chunk in str(value).split("."):
        num = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts)


def _version_lt(a: str, b: str) -> bool:
    """True if version ``a`` is older than ``b``."""
    return _parse_version(a) < _parse_version(b)


def _installed_version(package: str) -> Optional[str]:
    try:
        from importlib import metadata

        return metadata.version(package)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Offline dependency inspection
# --------------------------------------------------------------------------- #
def check_dependencies() -> list[dict]:
    """Return the status of every runtime/optional dependency (offline)."""
    report: list[dict] = []
    for pkgs, required in ((RUNTIME_PACKAGES, True), (OPTIONAL_PACKAGES, False)):
        for name, minimum in pkgs.items():
            installed = _installed_version(name)
            report.append(
                {
                    "package": name,
                    "required_min": minimum,
                    "installed": installed,
                    "optional": not required,
                    "missing": installed is None,
                    "outdated": bool(installed) and _version_lt(installed, minimum),
                }
            )
    return report


# --------------------------------------------------------------------------- #
# State (last-check timestamp), cached so startup checks stay cheap
# --------------------------------------------------------------------------- #
def _load_state() -> dict:
    try:
        return json.loads(_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(state: dict) -> None:
    try:
        _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except OSError:  # pragma: no cover - best effort
        pass


# --------------------------------------------------------------------------- #
# Online update checks (best-effort, cached)
# --------------------------------------------------------------------------- #
def _latest_pypi_version(package: str, config: Config) -> Optional[str]:
    try:
        from .utils import build_session

        session = build_session(config)
        resp = session.get(f"https://pypi.org/pypi/{package}/json", timeout=config.timeout)
        if resp.status_code == 200:
            return resp.json().get("info", {}).get("version")
    except Exception:  # pragma: no cover - network dependent
        return None
    return None


def check_for_updates(config: Config, force: bool = False) -> dict:
    """Best-effort check for newer dependency releases on PyPI.

    Cached via the state file so it runs at most once per configured interval.
    Returns ``{"outdated": [...], "checked": bool, "skipped": bool}`` and never
    raises on network failure.
    """
    state = _load_state()
    interval = max(1, int(getattr(config, "update_check_interval_days", 1))) * 86400
    last = state.get("last_update_check", 0)
    if not force and (time.time() - last) < interval:
        return {"outdated": [], "checked": False, "skipped": True}

    outdated = []
    for name in {**RUNTIME_PACKAGES, **OPTIONAL_PACKAGES}:
        installed = _installed_version(name)
        if installed is None:
            continue
        latest = _latest_pypi_version(name, config)
        if latest and _version_lt(installed, latest):
            outdated.append({"package": name, "installed": installed, "latest": latest})

    state["last_update_check"] = time.time()
    _save_state(state)
    return {"outdated": outdated, "checked": True, "skipped": False}


# --------------------------------------------------------------------------- #
# Actions that actually change things (explicit only)
# --------------------------------------------------------------------------- #
def update_dependencies(include_optional: bool = False) -> dict:
    """Upgrade Argus' runtime dependencies via pip. Returns a result dict."""
    packages = list(RUNTIME_PACKAGES)
    if include_optional:
        packages += list(OPTIONAL_PACKAGES)
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", *packages]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except (subprocess.SubprocessError, OSError) as exc:
        return {"ok": False, "error": str(exc), "packages": packages}
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "packages": packages,
        "stdout": proc.stdout[-2000:],
        "stderr": proc.stderr[-2000:],
    }


def _sites_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "sites.json"


def refresh_sites(config: Config, url: Optional[str] = None) -> dict:
    """Download the latest site catalogue and replace the local copy.

    The remote is only applied if it parses as valid JSON with a non-empty
    ``sites`` list and a ``version`` at least as new as the local one.
    """
    path = _sites_path()
    try:
        local = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        local = {"sites": [], "version": 0}
    source = url or local.get("source")
    if not source:
        return {"ok": False, "error": "no update source configured in sites.json"}

    try:
        from .utils import build_session

        session = build_session(config)
        resp = session.get(source, timeout=config.timeout)
        if resp.status_code != 200:
            return {"ok": False, "error": f"download failed (HTTP {resp.status_code})"}
        remote = resp.json()
    except Exception as exc:  # pragma: no cover - network dependent
        return {"ok": False, "error": str(exc)}

    if not isinstance(remote, dict) or not remote.get("sites"):
        return {"ok": False, "error": "remote catalogue is empty or malformed"}
    local_v = int(local.get("version", 0) or 0)
    remote_v = int(remote.get("version", 0) or 0)
    if remote_v < local_v:
        return {
            "ok": True,
            "updated": False,
            "reason": "local catalogue is already newer",
            "local_version": local_v,
            "remote_version": remote_v,
        }
    try:
        path.write_text(json.dumps(remote, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    return {
        "ok": True,
        "updated": True,
        "local_version": local_v,
        "remote_version": remote_v,
        "sites": len(remote.get("sites", [])),
    }
