"""Unit tests for the Artemis reflected-XSS reflection check."""

import html
import json
from pathlib import Path

from olympus.artemis.http import HttpClientError, HttpResponse
from olympus.artemis.xss import MARKER, check_reflected_xss
from olympus.core.enums import Severity
from olympus.core.models import Finding

ASSET = "AST-2026-00001"
BASE = "https://target.example/app/search"


def _scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "engagement": "t",
                "allowed_origins": ["https://target.example"],
                "allowed_path_prefixes": ["/app"],
                "allowed_ip_networks": ["192.0.2.0/24"],
            }
        ),
        encoding="utf-8",
    )
    return path


class _Resolver:
    def resolve(self, hostname: str, port: int) -> list[str]:
        del hostname, port
        return ["192.0.2.10"]


class _Transport:
    def __init__(self, body: bytes, *, error: bool = False) -> None:
        self._body = body
        self._error = error

    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        del addresses, timeout, max_bytes
        if self._error:
            raise HttpClientError("boom")
        return HttpResponse(url, 200, {"content-type": "text/html"}, self._body)


def _run(tmp_path: Path, transport: _Transport) -> list[Finding]:
    return check_reflected_xss(
        ASSET, BASE, "q", _scope(tmp_path), tmp_path / "log", _Resolver(), transport
    )


def test_unescaped_reflection_is_flagged_high(tmp_path: Path) -> None:
    body = f"<html><h1>Results for {MARKER}</h1></html>".encode()
    findings = _run(tmp_path, _Transport(body))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "Reflected XSS" in findings[0].title


def test_escaped_reflection_is_not_flagged(tmp_path: Path) -> None:
    # The app echoes the marker but HTML-escapes it -> safe, no finding.
    body = f"<html>Results for {html.escape(MARKER)}</html>".encode()
    assert _run(tmp_path, _Transport(body)) == []


def test_no_reflection_is_not_flagged(tmp_path: Path) -> None:
    assert _run(tmp_path, _Transport(b"<html>no echo here</html>")) == []


def test_transport_error_yields_nothing(tmp_path: Path) -> None:
    assert _run(tmp_path, _Transport(b"", error=True)) == []


def test_marker_is_non_executable() -> None:
    # The probe must never carry a script/event-handler payload.
    lowered = MARKER.lower()
    assert "script" not in lowered
    assert "onerror" not in lowered
    assert "alert" not in lowered
