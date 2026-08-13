"""Unit tests for Proteus recipient scope enforcement (block + log)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.proteus.scope import (
    OutOfScopeError,
    ScopeError,
    enforce_scope,
    filter_in_scope,
    load_scope,
    log_blocked,
)


def _write_scope(path: Path, **overrides: object) -> Path:
    payload: dict[str, object] = {
        "engagement": "olympus-demo-corp-2026",
        "allowed_domains": ["olympusdemocorp.example"],
        "excluded_recipients": ["ceo@olympusdemocorp.example"],
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_load_scope_reads_valid_file(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path / "scope.json"))
    assert scope.engagement == "olympus-demo-corp-2026"
    assert scope.allowed_domains == ("olympusdemocorp.example",)


def test_scope_covers_recipient_in_allowed_domain(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path / "scope.json"))
    assert scope.covers("alice@olympusdemocorp.example")
    assert not scope.covers("alice@evil.com")


def test_scope_excluded_recipient_wins_over_allowed_domain(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path / "scope.json"))
    assert not scope.covers("ceo@olympusdemocorp.example")


def test_scope_domain_match_is_case_insensitive(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path / "scope.json"))
    assert scope.covers("Alice@OlympusDemoCorp.example")


def test_load_scope_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ScopeError, match="not found"):
        load_scope(tmp_path / "missing.json")


def test_load_scope_empty_allowed_domains_raises(tmp_path: Path) -> None:
    path = _write_scope(tmp_path / "scope.json", allowed_domains=[])
    with pytest.raises(ScopeError, match="no allowed_domains"):
        load_scope(path)


def test_log_blocked_appends_json_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "blocked.log"
    log_blocked("victim@evil.com", tmp_path / "scope.json", log_path)

    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert entry["recipient"] == "victim@evil.com"
    assert entry["action"] == "blocked_out_of_scope"


def test_enforce_scope_allows_in_scope_recipient(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    scope = enforce_scope("alice@olympusdemocorp.example", scope_path, log_path)

    assert scope.covers("alice@olympusdemocorp.example")
    assert not log_path.exists()


def test_enforce_scope_blocks_and_logs_out_of_scope_recipient(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    with pytest.raises(OutOfScopeError) as excinfo:
        enforce_scope("victim@evil.com", scope_path, log_path)

    assert excinfo.value.email == "victim@evil.com"
    assert log_path.exists()


def test_filter_in_scope_splits_and_logs_blocked(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"
    emails = [
        "alice@olympusdemocorp.example",
        "victim@evil.com",
        "bob@olympusdemocorp.example",
        "ceo@olympusdemocorp.example",  # excluded
    ]

    in_scope, blocked = filter_in_scope(emails, scope_path, log_path)

    assert in_scope == ["alice@olympusdemocorp.example", "bob@olympusdemocorp.example"]
    assert blocked == ["victim@evil.com", "ceo@olympusdemocorp.example"]
    assert len(log_path.read_text(encoding="utf-8").splitlines()) == 2
