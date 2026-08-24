from __future__ import annotations

from scanners.arjun_scanner import ArjunScanner
from scanners.dalfox_scanner import DalfoxScanner
from scanners.httpx_scanner import HttpxScanner
from scanners.katana_scanner import KatanaScanner
from scanners.nosqlmap_scanner import NosqlmapScanner
from scanners.testssl_scanner import TestsslScanner
from scanners.theharvester_scanner import TheHarvesterScanner
from scanners.wafw00f_scanner import Wafw00fScanner

import scanner_engine


def test_new_scanners_registered_in_map():
    assert "wafw00f" in scanner_engine.SCANNERS_MAP
    assert "testssl" in scanner_engine.SCANNERS_MAP
    assert "theharvester" in scanner_engine.SCANNERS_MAP
    assert "arjun" in scanner_engine.SCANNERS_MAP
    assert "dalfox" in scanner_engine.SCANNERS_MAP
    assert "httpx" in scanner_engine.SCANNERS_MAP
    assert "katana" in scanner_engine.SCANNERS_MAP
    assert "nosqlmap" in scanner_engine.SCANNERS_MAP


def test_wafw00f_extract_findings():
    scanner = Wafw00fScanner(enable_live_scans=False)
    findings = scanner._extract_findings({"detected_wafs": ["Cloudflare"]})
    assert findings
    assert "Cloudflare" in findings[0]["title"]
    assert findings[0]["bypass_hints"]


def test_testssl_extract_findings():
    scanner = TestsslScanner(enable_live_scans=False)
    findings = scanner._extract_findings([{"id": "TLSv1", "severity": "high", "finding": "Protocollo debole"}])
    assert findings
    assert findings[0]["severity"] == "medium"
    assert findings[0]["title"] == "Protocollo TLS legacy abilitato"


def test_testssl_extract_findings_maps_hsts():
    scanner = TestsslScanner(enable_live_scans=False)
    findings = scanner._extract_findings(
        [{"id": "hsts", "severity": "low", "finding": "strict-transport-security header missing"}]
    )
    assert findings
    assert findings[0]["title"] == "HSTS assente o non sicuro"


def test_theharvester_extract_findings():
    scanner = TheHarvesterScanner(enable_live_scans=False)
    findings = scanner._extract_findings(
        {"emails": ["a@example.com"], "hosts": ["api.example.com"], "ips": ["1.1.1.1"]}
    )
    assert findings
    assert "OSINT" in findings[0]["title"]


def test_arjun_extract_findings():
    scanner = ArjunScanner(enable_live_scans=False)
    findings = scanner._extract_findings({"params": ["id", "q"]}, "https://example.com")
    assert findings
    assert findings[0]["parameters"] == ["id", "q"]
    assert findings[0]["endpoint"] == "https://example.com"


def test_arjun_extract_findings_with_payload_list():
    scanner = ArjunScanner(enable_live_scans=False)
    findings = scanner._extract_findings(
        [{"url": "https://example.com", "params": ["search", "debug"]}],
        "https://example.com",
    )
    assert findings
    assert findings[0]["parameters"] == ["search", "debug"]


def test_arjun_extract_findings_with_target_key_normalization():
    scanner = ArjunScanner(enable_live_scans=False)
    findings = scanner._extract_findings({"https://example.com/": ["page"]}, "https://example.com")
    assert findings
    assert findings[0]["parameters"] == ["page"]


def test_dalfox_extract_findings():
    scanner = DalfoxScanner(enable_live_scans=False)
    findings = scanner._extract_findings(
        [{"evidence": "<script>alert(1)</script>", "param": "q", "method": "GET"}]
    )
    assert findings
    assert findings[0]["severity"] == "high"
    assert findings[0]["title"] == "Reflected XSS rilevato sul parametro 'q'"


def test_dalfox_extract_findings_dom_xss_and_dedup():
    scanner = DalfoxScanner(enable_live_scans=False)
    findings = scanner._extract_findings(
        [
            {
                "evidence": "javascript:alert(document.domain)",
                "param": "redirect",
                "method": "post",
                "type": "dom",
            },
            {
                "evidence": "javascript:alert(document.domain)",
                "param": "redirect",
                "method": "POST",
                "type": "dom",
            },
        ]
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["method"] == "POST"
    assert findings[0]["title"] == "DOM-based XSS rilevato sul parametro 'redirect'"


def test_httpx_extract_findings():
    scanner = HttpxScanner(enable_live_scans=False)
    findings = scanner._extract_findings(
        [{"url": "https://example.com", "status_code": 200, "header": {"Server": "nginx"}, "tech": ["nginx"]}]
    )
    assert findings
    assert any("Header di sicurezza mancanti" in finding["title"] for finding in findings)


def test_httpx_extract_findings_redirect_and_error_status():
    scanner = HttpxScanner(enable_live_scans=False)
    findings = scanner._extract_findings(
        [
            {
                "url": "https://example.com/login",
                "status_code": 302,
                "header": {"Location": "https://example.com/auth"},
                "tech": [],
            },
            {"url": "https://example.com/api", "status_code": 500, "header": {}, "tech": []},
        ]
    )
    assert any(finding["title"] == "Redirect chain rilevata" for finding in findings)
    assert any("status anomalo (500)" in finding["title"] for finding in findings)


def test_katana_extract_findings():
    scanner = KatanaScanner(enable_live_scans=False)
    findings = scanner._extract_findings(
        [{"request": {"endpoint": "https://example.com/admin"}}, {"request": {"endpoint": "https://example.com/api"}}]
    )
    assert findings
    assert "endpoint" in findings[0]["description"].lower()


def test_nosqlmap_extract_findings():
    scanner = NosqlmapScanner(enable_live_scans=False)
    findings = scanner._extract_findings("Target appears vulnerable to MongoDB injection")
    assert findings
    assert findings[0]["severity"] == "high"
