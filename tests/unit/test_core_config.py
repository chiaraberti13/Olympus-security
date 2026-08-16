"""Unit tests for optional TOML configuration."""

from pathlib import Path

import pytest

from olympus.core import config
from olympus.core.http import UrllibHttpClient


def test_no_file_returns_empty(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("OLYMPUS_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)  # no ./olympus.toml here
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)  # no ~/.olympus.toml
    assert config.load_config() == {}


def test_loads_from_env_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = tmp_path / "olympus.toml"
    cfg.write_text("[http]\ntimeout = 15.0\nretries = 3\nrate = 0.25\n", encoding="utf-8")
    monkeypatch.setenv("OLYMPUS_CONFIG", str(cfg))
    data = config.load_config()
    assert config.get("http", "timeout", 10.0, data) == 15.0
    assert config.get("http", "retries", 2, data) == 3


def test_get_falls_back_on_type_mismatch() -> None:
    data = {"http": {"timeout": "not-a-number"}}
    assert config.get("http", "timeout", 10.0, data) == 10.0


def test_get_missing_section_returns_default() -> None:
    assert config.get("http", "timeout", 10.0, {}) == 10.0


def test_malformed_toml_returns_empty(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = tmp_path / "olympus.toml"
    cfg.write_text("this is = = not toml", encoding="utf-8")
    monkeypatch.setenv("OLYMPUS_CONFIG", str(cfg))
    assert config.load_config() == {}


def test_http_from_config_uses_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = tmp_path / "olympus.toml"
    cfg.write_text("[http]\ntimeout = 20.0\nrate = 0.5\n", encoding="utf-8")
    monkeypatch.setenv("OLYMPUS_CONFIG", str(cfg))
    client = UrllibHttpClient.from_config()
    assert client._timeout == 20.0
    assert client._min_interval == 0.5


def test_http_from_config_caller_rate_wins(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = tmp_path / "olympus.toml"
    cfg.write_text("[http]\nrate = 0.5\n", encoding="utf-8")
    monkeypatch.setenv("OLYMPUS_CONFIG", str(cfg))
    client = UrllibHttpClient.from_config(min_interval=2.0)
    assert client._min_interval == 2.0
