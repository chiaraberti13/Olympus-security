from __future__ import annotations

from types import SimpleNamespace

import scanner_engine
from scanners.wpscan_scanner import WpscanScanner


def test_wpscan_returns_simulated_when_live_disabled():
    scanner = WpscanScanner(enable_live_scans=False)
    result = scanner.run("https://example.com")

    assert result["tool"] == "wpscan"
    assert result["status"] == "simulated"
    assert result["findings"]


def test_get_scanner_classes_supports_wordpress_scan_type():
    classes = scanner_engine.get_scanner_classes("wordpress")
    assert classes == [
        scanner_engine.WpscanScanner,
        scanner_engine.WhatWebScanner,
        scanner_engine.NiktoScanner,
        scanner_engine.WordpressNucleiScanner,
        scanner_engine.NmapScanner,
        scanner_engine.Wafw00fScanner,
    ]


def test_wpscan_extracts_component_and_user_findings():
    scanner = WpscanScanner(enable_live_scans=False)
    payload = {
        "version": {
            "number": "6.5.1",
            "vulnerabilities": [
                {
                    "title": "WordPress core SQL Injection",
                    "cve": ["CVE-2026-9999"],
                    "references": {"url": ["https://example.com/core-cve"]},
                }
            ],
        },
        "plugins": {
            "contact-form-7": {
                "version": {"number": "5.8"},
                "vulnerabilities": [
                    {
                        "title": "Arbitrary file upload",
                        "cve": ["CVE-2026-1234"],
                        "references": {"url": ["https://example.com/cve"]},
                    }
                ],
            }
        },
        "users": {"admin": {"id": 1}},
    }

    findings = scanner._extract_findings(payload)

    titles = [item["title"] for item in findings]
    assert any("WordPress 6.5.1" in title for title in titles)
    assert any("Core WordPress vulnerabile" in title for title in titles)
    assert any("Plugin vulnerabile" in title for title in titles)
    assert any("User enumeration" in title for title in titles)


def test_wpscan_skips_when_binary_missing(monkeypatch):
    scanner = WpscanScanner(enable_live_scans=True)
    monkeypatch.setattr("scanners.wpscan_scanner.shutil.which", lambda _: None)
    monkeypatch.setattr(
        "scanners.wpscan_scanner.settings",
        SimpleNamespace(
            wpscan_api_token="",
            wpscan_enumerate="",
            scan_timeout_seconds=3,
            max_findings=50,
        ),
    )

    result = scanner.run("https://example.com")
    assert result["status"] == "skipped"
