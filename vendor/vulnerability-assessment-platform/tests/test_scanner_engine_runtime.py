from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from requests import RequestException

import scanner_engine


class DummyScanner:
    def __init__(self, enable_live_scans: bool):
        self.enable_live_scans = enable_live_scans

    def run(self, target: str):
        return {
            "tool": "dummy",
            "status": "completed",
            "findings": [{"id": target}],
        }


class TimeoutScanner:
    def __init__(self, enable_live_scans: bool):
        self.enable_live_scans = enable_live_scans

    def run(self, _target: str):
        raise TimeoutError("tempo scaduto")


class InvalidScanner:
    def __init__(self, enable_live_scans: bool):
        self.enable_live_scans = enable_live_scans

    def run(self, _target: str):
        raise ValueError("input non valido")


class CrashScanner:
    def __init__(self, enable_live_scans: bool):
        self.enable_live_scans = enable_live_scans

    def run(self, _target: str):
        raise RuntimeError("boom")


class PluginScanner:
    def __init__(self, enable_live_scans: bool):
        self.enable_live_scans = enable_live_scans

    def run(self, _target: str):
        return {"status": "completed", "findings": []}


def test_collect_findings_applies_max_limit(monkeypatch):
    monkeypatch.setattr(scanner_engine, "settings", SimpleNamespace(max_findings=2, enable_live_scans=False))
    findings = scanner_engine._collect_findings(
        [{"findings": [{"id": 1}, {"id": 2}]}, {"findings": [{"id": 3}]}]
    )
    assert findings == [
        {"id": 1, "found_by": "Active Testing"},
        {"id": 2, "found_by": "Active Testing"},
    ]


def test_collect_findings_normalizes_method_parameters_and_evidence(monkeypatch):
    monkeypatch.setattr(scanner_engine, "settings", SimpleNamespace(max_findings=10, enable_live_scans=False))
    findings = scanner_engine._collect_findings(
        [
            {
                "tool": "sqlmap",
                "findings": [
                    {
                        "title": "SQLi",
                        "method": "post",
                        "parameter": "id",
                        "evidence": "Payload di test inviato al target",
                    }
                ],
            }
        ]
    )
    assert findings[0]["method"] == "POST"
    assert findings[0]["parameters"] == ["id"]
    assert "Metodo HTTP: POST | Parametri: id" in findings[0]["evidence"]


def test_run_scanner_success(monkeypatch):
    monkeypatch.setattr(scanner_engine, "settings", SimpleNamespace(enable_live_scans=True, max_findings=100))
    result = scanner_engine._run_scanner(DummyScanner, "example.com")
    assert result["status"] == "completed"
    assert result["findings"]


@pytest.mark.parametrize(
    "scanner_cls,error_type,expected_message",
    [
        (TimeoutScanner, "timeout", "tempo scaduto"),
        (InvalidScanner, "validation", "input non valido"),
        (CrashScanner, "unexpected", "scanner runtime error"),
    ],
)
def test_run_scanner_error_mapping(monkeypatch, scanner_cls, error_type, expected_message):
    monkeypatch.setattr(scanner_engine, "settings", SimpleNamespace(enable_live_scans=False, max_findings=100))
    result = scanner_engine._run_scanner(scanner_cls, "example.com")
    assert result["status"] == "error"
    assert result["error_type"] == error_type
    assert result["message"] == expected_message



def test_get_scan_type_choices_stays_aligned_with_runtime_maps(monkeypatch):
    monkeypatch.setattr(scanner_engine, "SCANNERS_MAP", {"dummy": DummyScanner, "nmap": DummyScanner})
    monkeypatch.setattr(scanner_engine, "SCAN_TYPE_PROFILES", {"light": ["dummy"], "wordpress": ["dummy"]})

    assert scanner_engine.get_scan_type_choices() == ["full", "light", "wordpress", "dummy", "nmap"]


def test_get_scanner_classes_and_single_scanner(monkeypatch):
    monkeypatch.setattr(scanner_engine, "SCANNERS_MAP", {"dummy": DummyScanner})
    monkeypatch.setattr(
        scanner_engine,
        "SCAN_TYPE_PROFILES",
        {"light": ["dummy"], "wordpress": ["dummy"]},
    )

    full = scanner_engine.get_scanner_classes("full")
    only = scanner_engine.get_scanner_classes("dummy")
    light = scanner_engine.get_scanner_classes("light")
    wordpress = scanner_engine.get_scanner_classes("wordpress")
    assert full == [DummyScanner]
    assert only == [DummyScanner]
    assert light == [DummyScanner]
    assert wordpress == [DummyScanner]

    result = scanner_engine.run_single_scanner("dummy", "target")
    assert result["status"] == "completed"

    with pytest.raises(scanner_engine.ScanValidationError):
        scanner_engine.get_scanner_classes("missing")

    with pytest.raises(scanner_engine.ScanValidationError):
        scanner_engine.run_single_scanner("missing", "target")


def test_light_nikto_scanner_keeps_only_header_findings(monkeypatch):
    def fake_run(self, _target):
        return {
            "tool": "nikto",
            "status": "simulated",
            "findings": [
                {"title": "Missing HTTP Security Headers", "description": "CSP/HSTS absent"},
                {"title": "Backup file exposed", "description": "database.sql.bak reachable"},
            ],
        }

    monkeypatch.setattr(scanner_engine.NiktoScanner, "run", fake_run)
    scanner = scanner_engine.LightNiktoScanner(enable_live_scans=False)

    result = scanner.run("example.com")
    assert len(result["findings"]) == 1
    assert "header" in result["findings"][0]["title"].lower()


def test_light_nmap_scanner_forces_quick_profile():
    scanner = scanner_engine.LightNmapScanner(enable_live_scans=False)
    assert scanner._profile_args("full") == ["-T4", "-F"]
    assert scanner._profile_args("stealth") == ["-T4", "-F"]


def test_run_scan_nmap_path(monkeypatch):
    monkeypatch.setattr(scanner_engine, "SCANNERS_MAP", {"nmap": DummyScanner})
    monkeypatch.setattr(
        scanner_engine,
        "settings",
        SimpleNamespace(enable_live_scans=False, max_findings=10, max_concurrent_scanners=1),
    )
    monkeypatch.setattr(scanner_engine, "validate_nmap_target", lambda target: f"validated-{target}")
    monkeypatch.setattr(scanner_engine, "enrich_findings", lambda findings: [{"enriched": True, **f} for f in findings])

    result = scanner_engine.run_scan("127.0.0.1", "nmap")
    assert result.target == "validated-127.0.0.1"
    assert result.status == "completed"
    assert result.findings[0]["enriched"] is True


def test_register_scanner_plugin_updates_runtime_maps(monkeypatch):
    monkeypatch.setattr(scanner_engine, "SCANNERS_MAP", {"nmap": DummyScanner})
    monkeypatch.setattr(scanner_engine, "TOOL_DISPLAY_NAMES", {})
    monkeypatch.setattr(scanner_engine, "SCAN_TYPE_PROFILES", {"light": ["nmap"], "wordpress": []})

    scanner_engine.register_scanner_plugin(
        scanner_engine.ScannerPluginSpec(
            scanner_name="custom_plugin",
            scanner_class=PluginScanner,
            display_name="Custom Plugin",
            profile_assignments=["light"],
        )
    )

    assert "custom_plugin" in scanner_engine.SCANNERS_MAP
    assert scanner_engine.TOOL_DISPLAY_NAMES["custom_plugin"] == "Custom Plugin"
    assert "custom_plugin" in scanner_engine.SCAN_TYPE_PROFILES["light"]
    assert "custom_plugin" in scanner_engine.get_scan_type_choices()


def test_register_scanner_plugin_rejects_unsupported_contract_version(monkeypatch):
    monkeypatch.setattr(scanner_engine, "SCANNERS_MAP", {"nmap": DummyScanner})
    monkeypatch.setattr(scanner_engine, "SCAN_TYPE_PROFILES", {"light": ["nmap"], "wordpress": []})

    with pytest.raises(scanner_engine.ScanValidationError, match="Versione richiesta"):
        scanner_engine.register_scanner_plugin(
            scanner_engine.ScannerPluginSpec(
                scanner_name="legacy_plugin",
                scanner_class=PluginScanner,
                contract_version="0.9.0",
            )
        )


def test_register_scanner_plugin_rejects_invalid_profile_without_mutating_maps(monkeypatch):
    monkeypatch.setattr(scanner_engine, "SCANNERS_MAP", {"nmap": DummyScanner})
    monkeypatch.setattr(scanner_engine, "SCAN_TYPE_PROFILES", {"light": ["nmap"], "wordpress": []})

    with pytest.raises(scanner_engine.ScanValidationError, match="Profilo plugin non riconosciuto"):
        scanner_engine.register_scanner_plugin(
            scanner_engine.ScannerPluginSpec(
                scanner_name="bad_profile",
                scanner_class=PluginScanner,
                profile_assignments=["enterprise"],
            )
        )

    assert "bad_profile" not in scanner_engine.SCANNERS_MAP


def test_serialize_findings_and_cli_parser(monkeypatch, tmp_path):
    payload = scanner_engine.serialize_findings([{"x": 1}])
    assert json.loads(payload) == [{"x": 1}]

    output_file = tmp_path / "result.json"
    monkeypatch.setattr(
        scanner_engine,
        "run_scan",
        lambda **kwargs: scanner_engine.ScanResult(
            target=kwargs["target"],
            scan_type=kwargs["scan_type"],
            status="completed",
            started_at=scanner_engine.datetime.now(scanner_engine.timezone.utc),
            completed_at=scanner_engine.datetime.now(scanner_engine.timezone.utc),
            findings=[{"ok": True}],
            metadata={"tests_performed": 1},
        ),
    )

    monkeypatch.setattr(
        "sys.argv",
        ["scanner_engine.py", "--target", "example.com", "--scan-type", "full", "--output", str(output_file)],
    )
    assert scanner_engine.main() == 0
    assert output_file.exists()


def test_main_returns_2_for_validation_error(monkeypatch):
    monkeypatch.setattr(scanner_engine, "run_scan", lambda **_kwargs: (_ for _ in ()).throw(scanner_engine.ScanValidationError("bad")))
    monkeypatch.setattr("sys.argv", ["scanner_engine.py", "--target", "bad-target"])
    assert scanner_engine.main() == 2


def test_run_scan_full_uses_validate_target(monkeypatch):
    monkeypatch.setattr(scanner_engine, "SCANNERS_MAP", {"nmap": DummyScanner})
    monkeypatch.setattr(
        scanner_engine,
        "settings",
        SimpleNamespace(enable_live_scans=False, max_findings=10, max_concurrent_scanners=2),
    )
    monkeypatch.setattr(scanner_engine, "validate_target", lambda target: f"ok-{target}")
    monkeypatch.setattr(scanner_engine, "enrich_findings", lambda findings: findings)
    monkeypatch.setattr(
        scanner_engine,
        "detect_target_redirect",
        lambda _target: {"validated_target": "ok-example.com", "redirect_from": "http://example.com"},
    )

    result = scanner_engine.run_scan("example.com", "full")
    assert result.target == "ok-example.com"
    assert result.scan_type == "full"
    assert result.metadata["redirect_from"] == "http://example.com"


def test_validate_nmap_target_rejects_bad_range_octet():
    with pytest.raises(scanner_engine.ScanValidationError):
        scanner_engine.validate_nmap_target("192.168.1.10-999")


def test_validate_nmap_target_rejects_bad_cidr():
    with pytest.raises(scanner_engine.ScanValidationError):
        scanner_engine.validate_nmap_target("10.0.0.0/99")


def test_compute_scan_stats_collects_counters():
    results = [
        {
            "findings": [{"id": 1}],
            "tests_performed": 5,
            "urls_spidered": 4,
            "http_requests_total": 9,
            "avg_response_time_ms": 100,
        },
        {"findings": [{"id": 2}], "urls_spidered": 3, "http_requests_total": 3, "avg_response_time_ms": 50},
    ]
    findings = [
        {"evidence_url": "https://example.com/a", "parameters": ["q"], "method": "GET"},
        {"affected_url": "https://example.com/b", "parameters": {"id": "1"}},
    ]
    stats = scanner_engine._compute_scan_stats(results, findings)
    assert stats["tests_performed"] == 6
    assert stats["urls_spidered"] == 7
    assert stats["injection_points"] == 2
    assert stats["unique_injection_points"] == 2
    assert stats["http_requests_total"] == 12
    assert stats["total_http_requests"] == 12
    assert stats["avg_response_time_ms"] == 75.0


def test_compute_scan_stats_supports_total_http_requests_alias():
    results = [{"findings": [], "tests_performed": 1, "total_http_requests": 7}]
    stats = scanner_engine._compute_scan_stats(results, findings=[])
    assert stats["http_requests_total"] == 7
    assert stats["total_http_requests"] == 7


def test_compute_scan_stats_probes_target_when_scanners_do_not_provide_response_time(monkeypatch):
    monkeypatch.setattr(scanner_engine, "_measure_target_avg_response_time_ms", lambda *_args, **_kwargs: 123.45)
    results = [{"findings": [], "tests_performed": 2, "http_requests_total": 4}]
    stats = scanner_engine._compute_scan_stats(results, findings=[], target="example.com")
    assert stats["avg_response_time_ms"] == 123.45


def test_detect_target_redirect_handles_request_exception(monkeypatch):
    monkeypatch.setattr(
        scanner_engine.requests,
        "get",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RequestException("no network")),
    )
    result = scanner_engine.detect_target_redirect("example.com")
    assert result["validated_target"] == "example.com"
    assert result["redirect_from"] == ""
