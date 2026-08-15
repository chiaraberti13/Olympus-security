"""Unit tests for the Artemis Metabase CVE-2026-72898 exposure check."""

import json
from pathlib import Path

from olympus.artemis.http import HttpClientError, HttpResponse
from olympus.artemis.metabase import CVE_ID, detect_metabase
from olympus.core.enums import Severity
from olympus.core.models import Finding

ASSET = "AST-2026-00001"
BASE = "https://target.example"


def _scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "engagement": "t",
                "allowed_origins": [BASE],
                "allowed_path_prefixes": ["/api"],
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
    def __init__(self, responses: dict[str, HttpResponse], *, error: bool = False) -> None:
        self._responses = responses
        self._error = error

    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        del addresses, timeout, max_bytes
        if self._error:
            raise HttpClientError("boom")
        for suffix, response in self._responses.items():
            if url.endswith(suffix):
                return response
        return HttpResponse(url, 404, {}, b"")


def _properties(url_base: str, tag: str) -> dict[str, HttpResponse]:
    body = json.dumps({"version": {"tag": tag}}).encode()
    return {
        "/api/session/properties": HttpResponse(
            f"{url_base}/api/session/properties", 200, {}, body
        ),
        "/api/session/reset_password": HttpResponse(
            f"{url_base}/api/session/reset_password", 405, {}, b""
        ),
    }


def _run(tmp_path: Path, transport: _Transport) -> list[Finding]:
    return detect_metabase(ASSET, BASE, _scope(tmp_path), tmp_path / "log", _Resolver(), transport)


def test_flags_affected_version_as_critical(tmp_path: Path) -> None:
    findings = _run(tmp_path, _Transport(_properties(BASE, "v0.60.10")))
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert CVE_ID in findings[0].title
    assert findings[0].cvss == 9.8
    assert any("reset_password" in e for e in findings[0].evidence)


def test_patched_version_is_low_severity(tmp_path: Path) -> None:
    findings = _run(tmp_path, _Transport(_properties(BASE, "v0.60.17")))
    assert findings[0].severity is Severity.LOW


def test_boundary_highest_affected_is_critical(tmp_path: Path) -> None:
    findings = _run(tmp_path, _Transport(_properties(BASE, "v0.62.8")))
    assert findings[0].severity is Severity.CRITICAL


def test_non_metabase_endpoint_yields_nothing(tmp_path: Path) -> None:
    transport = _Transport(
        {"/api/session/properties": HttpResponse(f"{BASE}/api/session/properties", 200, {}, b"hi")}
    )
    assert _run(tmp_path, transport) == []


def test_missing_endpoint_yields_nothing(tmp_path: Path) -> None:
    transport = _Transport(
        {"/api/session/properties": HttpResponse(f"{BASE}/api/session/properties", 404, {}, b"")}
    )
    assert _run(tmp_path, transport) == []


def test_transport_error_yields_nothing(tmp_path: Path) -> None:
    assert _run(tmp_path, _Transport({}, error=True)) == []


def test_unparseable_version_is_low_severity(tmp_path: Path) -> None:
    findings = _run(tmp_path, _Transport(_properties(BASE, "nightly")))
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
