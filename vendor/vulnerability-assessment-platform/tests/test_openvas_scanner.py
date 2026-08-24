"""Test dell'adapter OpenVAS / Greenbone (GVM)."""
from pathlib import Path
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanners import openvas_scanner
from scanners.openvas_scanner import OpenVASScanner
from scanner_engine import SCANNERS_MAP, get_scanner_classes
from scan_catalog import SCAN_CATALOG, get_tool_descriptions


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _settings(**overrides):
    base = dict(
        openvas_api_base_url="https://gvm.local",
        openvas_api_key="token",
        openvas_vulnerabilities_endpoint="/gmp/results",
        openvas_timeout_seconds=5,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_openvas_simulated_mode_returns_findings_with_cves():
    result = OpenVASScanner(enable_live_scans=False).run("https://demo.local")
    assert result["status"] == "simulated"
    cves = [cve for f in result["findings"] for cve in f.get("cve", [])]
    assert "CVE-2017-0144" in cves  # EternalBlue (SMBv1)


def test_openvas_skipped_when_not_configured(monkeypatch):
    monkeypatch.setattr(openvas_scanner, "settings", _settings(openvas_api_base_url="", openvas_api_key=""))
    result = OpenVASScanner(enable_live_scans=True).run("example.com")
    assert result["status"] == "skipped"
    assert result["findings"] == []


def test_openvas_parses_results_with_severity_and_cve(monkeypatch):
    monkeypatch.setattr(openvas_scanner, "settings", _settings())

    payload = {
        "results": [
            {
                "name": "OpenSSH outdated",
                "threat": "High",
                "cvss_score": "7.3",
                "host": "10.0.0.10",
                "port": "22",
                "cve": ["CVE-2023-38408"],
                "description": "desc",
                "solution": "update",
            },
            {
                "name": "Info finding",
                "cvss": "0.0",
                "cve": "CVE-2020-0001",
            },
        ]
    }
    monkeypatch.setattr(openvas_scanner.requests, "get", lambda *a, **k: _FakeResponse(payload))

    result = OpenVASScanner(enable_live_scans=True).run("10.0.0.10")
    assert result["status"] == "executed"
    findings = result["findings"]
    assert findings[0]["severity"] == "high"
    assert findings[0]["cve"] == ["CVE-2023-38408"]
    assert findings[0]["cvss_score"] == 7.3
    # 'cve' scalare normalizzato a lista; cvss 0.0 -> severità info
    assert findings[1]["cve"] == ["CVE-2020-0001"]
    assert findings[1]["severity"] == "info"


def test_openvas_handles_api_errors_gracefully(monkeypatch):
    monkeypatch.setattr(openvas_scanner, "settings", _settings())

    def _boom(*a, **k):
        raise openvas_scanner.requests.RequestException("down")

    monkeypatch.setattr(openvas_scanner.requests, "get", _boom)
    result = OpenVASScanner(enable_live_scans=True).run("10.0.0.10")
    assert result["status"] == "error"
    assert result["findings"] == []


def test_openvas_registered_and_in_catalog():
    assert "openvas" in SCANNERS_MAP
    assert get_scanner_classes("openvas") == [OpenVASScanner]
    assert "openvas" in SCAN_CATALOG
    assert SCAN_CATALOG["openvas"].category == "Rete"
    assert get_tool_descriptions().get("openvas", "").strip()
