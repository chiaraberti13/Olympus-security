"""Optional TOML configuration so operators stop repeating the same flags.

Olympus reads, in order of precedence:

1. the path in the ``OLYMPUS_CONFIG`` environment variable, if set;
2. ``./olympus.toml`` in the current directory;
3. ``~/.olympus.toml`` in the user's home.

The file is entirely optional — with no file present every helper falls back
to the built-in defaults, so nothing changes. Example::

    [http]
    timeout = 15.0
    retries = 3
    rate = 0.25
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any


def _candidate_paths() -> list[Path]:
    paths: list[Path] = []
    env_path = os.environ.get("OLYMPUS_CONFIG", "").strip()
    if env_path:
        paths.append(Path(env_path))
    paths.append(Path("olympus.toml"))
    paths.append(Path.home() / ".olympus.toml")
    return paths


def load_config() -> dict[str, Any]:
    """Load the first existing config file, or ``{}`` when none is present."""
    for path in _candidate_paths():
        try:
            raw = path.read_bytes()
        except (FileNotFoundError, OSError):
            continue
        try:
            parsed = tomllib.loads(raw.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def get(section: str, key: str, default: Any, config: dict[str, Any] | None = None) -> Any:
    """Return ``config[section][key]`` if present and same-typed, else ``default``."""
    data = load_config() if config is None else config
    table = data.get(section)
    if not isinstance(table, dict) or key not in table:
        return default
    value = table[key]
    # Only honor a config value that matches the default's type (bool is not int here).
    if type(value) is type(default) or (
        isinstance(default, float) and isinstance(value, int) and not isinstance(value, bool)
    ):
        return value
    return default
