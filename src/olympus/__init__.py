"""Olympus — offensive security platform (Red + Blue) with a shared data contract."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("olympus-security")
except PackageNotFoundError:  # pragma: no cover - only when the package isn't installed
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
