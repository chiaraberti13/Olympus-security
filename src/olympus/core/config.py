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


class ConfigError(RuntimeError):
    """Raised when an explicitly selected or discovered config is invalid."""


def _candidate_paths() -> list[Path]:
    paths: list[Path] = []
    env_path = os.environ.get("OLYMPUS_CONFIG", "").strip()
    if env_path:
        paths.append(Path(env_path))
    paths.append(Path("olympus.toml"))
    paths.append(Path.home() / ".olympus.toml")
    return paths


def _validate_http_config(data: dict[str, Any], path: Path) -> None:
    table = data.get("http")
    if table is None:
        return
    if not isinstance(table, dict):
        raise ConfigError(f"[http] must be a TOML table in {path}")

    numeric_rules: dict[str, tuple[type, float, float]] = {
        "timeout": (float, 0.001, 3600.0),
        "retries": (int, 0, 10),
        "backoff": (float, 0.0, 300.0),
        "rate": (float, 0.0, 3600.0),
        "max_response_bytes": (int, 1, 100 * 1024 * 1024),
        "max_response_headers": (int, 1, 1_000),
        "max_response_header_bytes": (int, 1, 1024 * 1024),
        "max_redirects": (int, 0, 10),
        "max_decompressed_bytes": (int, 1, 100 * 1024 * 1024),
        "max_expansion_ratio": (float, 1.0, 10_000.0),
        "deadline": (float, 0.05, 86_400.0),
    }
    for key, value in table.items():
        if key not in numeric_rules:
            raise ConfigError(f"unknown [http] option {key!r} in {path}")
        expected, minimum, maximum = numeric_rules[key]
        valid_type = isinstance(value, expected) and not isinstance(value, bool)
        if expected is float:
            valid_type = isinstance(value, int | float) and not isinstance(value, bool)
        if not valid_type or not minimum <= value <= maximum:
            raise ConfigError(
                f"invalid [http].{key} in {path}: expected {expected.__name__} "
                f"between {minimum:g} and {maximum:g}"
            )


def _validate_config(data: dict[str, Any], path: Path) -> dict[str, Any]:
    _validate_http_config(data, path)
    return data


def load_config() -> dict[str, Any]:
    """Load and validate the first config file; never hide a broken selection."""
    explicit_path = os.environ.get("OLYMPUS_CONFIG", "").strip()
    for index, path in enumerate(_candidate_paths()):
        try:
            raw = path.read_bytes()
        except FileNotFoundError as exc:
            if explicit_path and index == 0:
                raise ConfigError(f"explicit config file does not exist: {path}") from exc
            continue
        except OSError as exc:
            raise ConfigError(f"cannot read config file {path}: {exc}") from exc
        try:
            parsed = tomllib.loads(raw.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"invalid TOML config {path}: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ConfigError(f"config root must be a TOML table: {path}")
        return _validate_config(parsed, path)
    return {}


def get(section: str, key: str, default: Any, config: dict[str, Any] | None = None) -> Any:
    """Return a validated config value, or ``default`` when it is absent."""
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
    raise ConfigError(
        f"invalid type for [{section}].{key}: expected {type(default).__name__}, "
        f"got {type(value).__name__}"
    )
