"""User configuration handling.

Configuration is loaded from (in order of precedence):
  1. CLI flags
  2. Environment variables (ARGUS_*)
  3. A JSON config file (~/.config/argus/config.json)
  4. Built-in defaults
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path


def config_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "argus"


def default_output_dir() -> Path:
    """Default report location: a ``report`` folder inside the script's folder.

    ``config.py`` lives in the ``argus`` package, so its parent's parent is the
    project (script) root; reports are written to ``<script folder>/report``.
    """
    return Path(__file__).resolve().parent.parent / "report"


CONFIG_PATH = config_dir() / "config.json"


@dataclass
class Config:
    timeout: float = 8.0
    max_workers: int = 20
    user_agent: str = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
    output_dir: str = str(default_output_dir())
    verify_ssl: bool = True
    retries: int = 2
    # Update behaviour. `update_check` prints a one-line hint at startup when a
    # newer dependency release exists (non-blocking, cached). `auto_update`
    # additionally upgrades dependencies automatically on launch — opt-in,
    # because it is slow and needs the network.
    update_check: bool = True
    update_check_interval_days: int = 1
    auto_update: bool = False

    @classmethod
    def load(cls) -> "Config":
        cfg = cls()
        # 3. file
        if CONFIG_PATH.exists():
            try:
                data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
                for k, v in data.items():
                    if hasattr(cfg, k):
                        setattr(cfg, k, v)
            except (json.JSONDecodeError, OSError):
                pass
        # 2. environment overrides
        env_map = {
            "ARGUS_TIMEOUT": ("timeout", float),
            "ARGUS_MAX_WORKERS": ("max_workers", int),
            "ARGUS_USER_AGENT": ("user_agent", str),
            "ARGUS_OUTPUT_DIR": ("output_dir", str),
            "ARGUS_RETRIES": ("retries", int),
        }
        for env, (attr, cast) in env_map.items():
            if env in os.environ:
                try:
                    setattr(cfg, attr, cast(os.environ[env]))
                except ValueError:
                    pass
        if os.environ.get("ARGUS_NO_VERIFY_SSL"):
            cfg.verify_ssl = False
        if os.environ.get("ARGUS_NO_UPDATE_CHECK"):
            cfg.update_check = False
        if os.environ.get("ARGUS_AUTO_UPDATE"):
            cfg.auto_update = True
        return cfg

    def save(self) -> Path:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        return CONFIG_PATH
