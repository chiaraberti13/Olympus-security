"""Unit tests for Helios scope enforcement (block + log out-of-scope targets)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.helios.scope import (
    OutOfScopeError,
    ScopeError,
    enforce_scope,
    load_scope,
    log_blocked,
)


def _write_scope(path: Path, **overrides: object) -> Path:
    payload: dict[str, object] = {
        "engagement": "olympus-demo-corp-2026",
        "allowed_targets": ["203.0.113.0/24", "demo-host.olympusdemocorp.example"],
        "excluded_targets": ["203.0.113.99"],
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_load_scope_reads_valid_file(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path / "scope.json"))
    assert scope.engagement == "olympus-demo-corp-2026"
    assert scope.allowed_targets == ("203.0.113.0/24", "demo-host.olympusdemocorp.example")


def test_scope_covers_ip_inside_cidr(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path / "scope.json"))
    assert scope.covers("203.0.113.10")
    assert scope.covers("203.0.113.254")


def test_scope_rejects_ip_outside_cidr(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path / "scope.json"))
    assert not scope.covers("198.51.100.10")


def test_scope_covers_exact_hostname(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path / "scope.json"))
    assert scope.covers("demo-host.olympusdemocorp.example")
    assert not scope.covers("other-host.olympusdemocorp.example")


def test_scope_excluded_ip_wins_over_cidr_allow(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path / "scope.json"))
    assert not scope.covers("203.0.113.99")


def test_load_scope_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ScopeError, match="not found"):
        load_scope(tmp_path / "missing.json")


def test_load_scope_invalid_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ScopeError, match="not valid JSON"):
        load_scope(path)


def test_load_scope_missing_keys_raises(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"engagement": "x"}), encoding="utf-8")
    with pytest.raises(ScopeError, match="allowed_targets"):
        load_scope(path)


def test_load_scope_empty_allowed_targets_raises(tmp_path: Path) -> None:
    path = _write_scope(tmp_path / "scope.json", allowed_targets=[])
    with pytest.raises(ScopeError, match="no allowed_targets"):
        load_scope(path)


def test_log_blocked_appends_json_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "blocked.log"
    log_blocked("198.51.100.10", tmp_path / "scope.json", log_path)
    log_blocked("198.51.100.11", tmp_path / "scope.json", log_path)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["target"] == "198.51.100.10"
    assert first["action"] == "blocked_out_of_scope"


def test_enforce_scope_allows_in_scope_target(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    scope = enforce_scope("203.0.113.10", scope_path, log_path)

    assert scope.covers("203.0.113.10")
    assert not log_path.exists()


def test_enforce_scope_blocks_and_logs_out_of_scope_target(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    with pytest.raises(OutOfScopeError) as excinfo:
        enforce_scope("198.51.100.10", scope_path, log_path)

    assert excinfo.value.target == "198.51.100.10"
    assert log_path.exists()
    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert entry["target"] == "198.51.100.10"
