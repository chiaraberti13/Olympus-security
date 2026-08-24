from types import SimpleNamespace

import enrichment_engine


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def test_enrich_findings_adds_owasp_mappings_without_live_calls(monkeypatch):
    monkeypatch.setattr(
        enrichment_engine,
        "settings",
        SimpleNamespace(
            enable_live_scans=False,
            nvd_api_key="",
            exploitdb_searchsploit_path="searchsploit",
            exploitdb_max_cves=10,
            nvd_max_cves=10,
            nvd_timeout_seconds=2,
            false_positive_medium_threshold=0.4,
            false_positive_high_threshold=0.7,
        ),
    )
    monkeypatch.setattr(enrichment_engine, "_apply_false_positive_model", lambda findings: None)
    monkeypatch.setattr(enrichment_engine, "_apply_mitre_mapping", lambda findings: None)
    monkeypatch.setattr(enrichment_engine, "_apply_correlation", lambda findings: None)

    findings = [{"title": "SQL Injection", "cwe": ["CWE-89"], "cve": []}]
    enriched = enrichment_engine.enrich_findings(findings)

    assert enriched[0]["owasp_2021"] == "A03:2021 - Injection"
    assert enriched[0]["owasp_2017"] == "A1:2017 - Injection"
    assert enriched[0]["owasp_2025"] == "A03:2025 - Injection"


def test_enrich_findings_adds_owasp_2025_non_injection_category(monkeypatch):
    monkeypatch.setattr(
        enrichment_engine,
        "settings",
        SimpleNamespace(
            enable_live_scans=False,
            nvd_api_key="",
            exploitdb_searchsploit_path="searchsploit",
            exploitdb_max_cves=10,
            nvd_max_cves=10,
            nvd_timeout_seconds=2,
            false_positive_medium_threshold=0.4,
            false_positive_high_threshold=0.7,
        ),
    )
    monkeypatch.setattr(enrichment_engine, "_apply_false_positive_model", lambda findings: None)
    monkeypatch.setattr(enrichment_engine, "_apply_mitre_mapping", lambda findings: None)
    monkeypatch.setattr(enrichment_engine, "_apply_correlation", lambda findings: None)

    findings = [{"title": "Rate limiting missing", "cwe": ["CWE-799"], "cve": []}]
    enriched = enrichment_engine.enrich_findings(findings)

    assert enriched[0]["owasp_2025"] == "A04:2025 - Insecure Design"


def test_enrich_findings_adds_epss_kev_and_fixed_version(monkeypatch):
    monkeypatch.setattr(
        enrichment_engine,
        "settings",
        SimpleNamespace(
            enable_live_scans=True,
            nvd_api_key="token",
            nvd_api_base_url="https://nvd.local/cves",
            nvd_timeout_seconds=2,
            nvd_max_cves=10,
            exploitdb_searchsploit_path="missing",
            exploitdb_max_cves=10,
            exploitdb_timeout_seconds=2,
            false_positive_medium_threshold=0.4,
            false_positive_high_threshold=0.7,
        ),
    )
    monkeypatch.setattr(enrichment_engine, "shutil", SimpleNamespace(which=lambda _: None))
    monkeypatch.setattr(enrichment_engine, "_apply_false_positive_model", lambda findings: None)
    monkeypatch.setattr(enrichment_engine, "_apply_mitre_mapping", lambda findings: None)
    monkeypatch.setattr(enrichment_engine, "_apply_correlation", lambda findings: None)

    def _fake_get(url, **kwargs):
        if "nvd.local" in url:
            return _FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "descriptions": [{"lang": "en", "value": "desc"}],
                                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1, "vectorString": "V"}}]},
                                "configurations": [
                                    {"nodes": [{"cpeMatch": [{"versionEndExcluding": "2.4.1"}]}]}
                                ],
                                "references": [{"url": "https://example.test/advisory"}],
                            }
                        }
                    ]
                }
            )
        if "api.first.org" in url:
            return _FakeResponse({"data": [{"cve": "CVE-2024-0001", "epss": "0.95", "percentile": "0.99"}]})
        if "known_exploited_vulnerabilities" in url:
            return _FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2024-0001",
                            "dateAdded": "2024-01-01",
                            "dueDate": "2024-01-21",
                            "knownRansomwareCampaignUse": "Known",
                        }
                    ]
                }
            )
        raise AssertionError(f"URL inatteso: {url}")

    monkeypatch.setattr(enrichment_engine.requests, "get", _fake_get)

    findings = [{"title": "test", "cve": ["CVE-2024-0001"], "cwe": []}]
    enriched = enrichment_engine.enrich_findings(findings)

    assert enriched[0]["cve_verified"] is True
    assert enriched[0]["epss_score"] == 0.95
    assert enriched[0]["epss_percentile"] == 0.99
    assert enriched[0]["cisa_kev"] is True
    assert enriched[0]["cve_details"][0]["fixed_in_version"] == "2.4.1"


def test_enrich_findings_uses_wpvulndb_fixed_version_when_nvd_missing(monkeypatch):
    monkeypatch.setattr(
        enrichment_engine,
        "settings",
        SimpleNamespace(
            enable_live_scans=True,
            nvd_api_key="token",
            nvd_api_base_url="https://nvd.local/cves",
            nvd_timeout_seconds=2,
            nvd_max_cves=10,
            exploitdb_searchsploit_path="missing",
            exploitdb_max_cves=10,
            exploitdb_timeout_seconds=2,
            wpscan_api_token="wp-token",
            wpscan_api_base_url="https://wpscan.local/api/v3",
            false_positive_medium_threshold=0.4,
            false_positive_high_threshold=0.7,
        ),
    )
    monkeypatch.setattr(enrichment_engine, "shutil", SimpleNamespace(which=lambda _: None))
    monkeypatch.setattr(enrichment_engine, "_apply_false_positive_model", lambda findings: None)
    monkeypatch.setattr(enrichment_engine, "_apply_mitre_mapping", lambda findings: None)
    monkeypatch.setattr(enrichment_engine, "_apply_correlation", lambda findings: None)

    def _fake_get(url, **kwargs):
        if "nvd.local" in url:
            return _FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "descriptions": [{"lang": "en", "value": "desc"}],
                                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.3, "vectorString": "V"}}]},
                                "references": [{"url": "https://nvd.local/ref"}],
                            }
                        }
                    ]
                }
            )
        if "wpscan.local" in url:
            return _FakeResponse(
                {
                    "vulnerability": {
                        "fixed_in": "5.9.4",
                        "references": {"url": ["https://wpscan.com/vulnerability/example"]},
                    }
                }
            )
        if "api.first.org" in url:
            return _FakeResponse({"data": []})
        if "known_exploited_vulnerabilities" in url:
            return _FakeResponse({"vulnerabilities": []})
        raise AssertionError(f"URL inatteso: {url}")

    monkeypatch.setattr(enrichment_engine.requests, "get", _fake_get)

    findings = [{"title": "test", "cve": ["CVE-2024-9999"], "cwe": []}]
    enriched = enrichment_engine.enrich_findings(findings)

    assert enriched[0]["cve_verified"] is True
    assert enriched[0]["cve_details"][0]["fixed_in_version"] == "5.9.4"
