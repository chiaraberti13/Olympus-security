"""Tests for Artemis authorized content/directory discovery."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.artemis import cli as artemis_cli
from olympus.artemis.content import (
    DiscoveredPath,
    WordlistError,
    discover_content,
    discoveries_to_findings,
    load_wordlist,
)
from olympus.artemis.http import HttpResponse
from olympus.cli import app

runner = CliRunner()

BASE = "https://portal.olympusdemocorp.example/app"


def _write_scope(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "engagement": "olympus-demo-corp-2026",
                "allowed_origins": ["https://portal.olympusdemocorp.example"],
                "allowed_path_prefixes": ["/app"],
                "allowed_ip_networks": ["192.0.2.0/24"],
            }
        ),
        encoding="utf-8",
    )
    return path


def _wordlist(path: Path, words: list[str]) -> Path:
    path.write_text("\n".join(words) + "\n", encoding="utf-8")
    return path


class _Resolver:
    def resolve(self, hostname: str, port: int) -> list[str]:
        del hostname, port
        return ["192.0.2.10"]


class _Transport:
    """Serves 200 for /app/admin and /app/.env, 404 for everything else."""

    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        del addresses, timeout, max_bytes
        if url.endswith("/app/admin"):
            return HttpResponse(url, 200, {}, b"admin console")
        if url.endswith("/app/.env"):
            return HttpResponse(url, 200, {}, b"SECRET=redacted")
        return HttpResponse(url, 404, {}, b"not found")


def test_load_wordlist_dedupes_and_skips_comments(tmp_path: Path) -> None:
    path = _wordlist(tmp_path / "w.txt", ["# comment", "admin", "", "/admin", "login"])
    assert load_wordlist(path) == ["admin", "login"]


def test_load_wordlist_rejects_empty(tmp_path: Path) -> None:
    path = _wordlist(tmp_path / "w.txt", ["# only comments"])
    with pytest.raises(WordlistError):
        load_wordlist(path)


def test_discover_reports_only_existing_paths(tmp_path: Path) -> None:
    scope = _write_scope(tmp_path / "scope.json")
    found = discover_content(
        BASE,
        ["admin", "login", ".env", "missing"],
        scope,
        tmp_path / "blocked.log",
        _Resolver(),
        _Transport(),
    )
    paths = {d.path: d.status for d in found}
    assert paths == {"admin": 200, ".env": 200}


def test_sensitive_paths_are_escalated_to_low() -> None:
    discovered = [
        DiscoveredPath(path="admin", url=f"{BASE}/admin", status=200, length=13),
        DiscoveredPath(path=".env", url=f"{BASE}/.env", status=200, length=15),
    ]
    findings = {f.title: f for f in discoveries_to_findings("AST-1", discovered)}
    env_finding = next(f for t, f in findings.items() if ".env" in t)
    assert env_finding.severity.value == "low"
    assert env_finding.remediation  # sensitive paths carry remediation


def test_out_of_scope_base_yields_nothing(tmp_path: Path) -> None:
    scope = _write_scope(tmp_path / "scope.json")
    log = tmp_path / "blocked.log"
    # /admin-area is outside the authorized /app prefix -> every candidate blocked.
    found = discover_content(
        "https://portal.olympusdemocorp.example/admin-area",
        ["admin", ".env"],
        scope,
        log,
        _Resolver(),
        _Transport(),
    )
    assert found == []
    assert log.exists()  # blocked candidates are audited


def test_cli_content_requires_authorization(tmp_path: Path) -> None:
    scope = _write_scope(tmp_path / "scope.json")
    wl = _wordlist(tmp_path / "w.txt", ["admin"])
    result = runner.invoke(
        app,
        ["artemis", "content", "--url", BASE, "--wordlist", str(wl), "--scope", str(scope)],
    )
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output


def test_cli_content_finds_paths_with_exit_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(artemis_cli, "SocketResolver", _Resolver)
    monkeypatch.setattr(artemis_cli, "PinnedTransport", _Transport)
    scope = _write_scope(tmp_path / "scope.json")
    wl = _wordlist(tmp_path / "w.txt", ["admin", "login", ".env"])
    out = tmp_path / "findings.json"
    result = runner.invoke(
        app,
        [
            "artemis", "content", "--url", BASE, "--wordlist", str(wl),
            "--scope", str(scope), "--log", str(tmp_path / "b.log"),
            "--i-am-authorized", "--output", str(out),
        ],
    )
    assert result.exit_code == 1, result.output
    findings = json.loads(out.read_text(encoding="utf-8"))
    titles = " ".join(f["title"] for f in findings)
    assert "/admin" in titles
    assert "/.env" in titles
