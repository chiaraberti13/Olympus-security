"""Tests for command-independent Argus application use cases."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.argus.application import (
    DnsLookupRequest,
    DnsLookupService,
    DomainScanRequest,
    DomainScanService,
    FrontingAssessmentRequest,
    FrontingAssessmentService,
    WhoisLookupRequest,
    WhoisLookupService,
)
from olympus.argus.scope import OutOfScopeError
from olympus.core.http import HttpResponse

DOMAIN = "olympusdemocorp.example"


class RecordingResolver:
    """Offline resolver that records every requested DNS lookup."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def resolve(self, name: str, record_type: str) -> list[str]:
        self.calls.append((name, record_type))
        if name == DOMAIN and record_type == "A":
            return ["203.0.113.10"]
        return []


class RecordingCtClient:
    """Offline CT client that records its authorized invocations."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def discover(self, domain: str) -> list[str]:
        self.calls.append(domain)
        return [f"portal.{domain}"]


class RecordingHttpClient:
    """Offline HTTP port returning a deterministic DoH response."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        self.calls.append(url)
        return HttpResponse(status_code=200, body='{"Answer":[{"data":"203.0.113.20"}]}')


class RecordingRdapClient:
    """Offline HTTP port returning a deterministic RDAP response."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        self.calls.append(url)
        return HttpResponse(
            status_code=200,
            body=json.dumps({"ldhName": DOMAIN.upper(), "status": ["active"]}),
        )


def _scope(path: Path) -> Path:
    path.write_text(
        json.dumps({"engagement": "test", "allowed_domains": [DOMAIN]}),
        encoding="utf-8",
    )
    return path


def test_domain_scan_service_returns_recon_without_cli_dependency(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()
    service = DomainScanService(resolver, ct_client)

    result = service.run(
        DomainScanRequest(DOMAIN, _scope(tmp_path / "scope.json"), tmp_path / "audit.log")
    )

    assert result.domain == DOMAIN
    assert result.a_records == ["203.0.113.10"]
    assert result.subdomains == [f"portal.{DOMAIN}"]
    assert resolver.calls
    assert ct_client.calls == [DOMAIN]


def test_domain_scan_service_blocks_before_network_dependencies(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()
    audit_log = tmp_path / "audit.log"
    service = DomainScanService(resolver, ct_client)

    with pytest.raises(OutOfScopeError):
        service.run(
            DomainScanRequest(
                "outside.example",
                _scope(tmp_path / "scope.json"),
                audit_log,
            )
        )

    assert resolver.calls == []
    assert ct_client.calls == []
    assert "outside.example" in audit_log.read_text(encoding="utf-8")


def test_fronting_service_runs_without_cli_dependency(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()

    result = FrontingAssessmentService(resolver, ct_client).run(
        FrontingAssessmentRequest(DOMAIN, _scope(tmp_path / "scope.json"), tmp_path / "audit.log")
    )

    assert result.domain == DOMAIN
    assert resolver.calls == [(DOMAIN, "A"), (DOMAIN, "AAAA")]
    # A non-fronted apex intentionally avoids CT fan-out.
    assert ct_client.calls == []


def test_fronting_service_blocks_before_network_dependencies(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()
    audit_log = tmp_path / "audit.log"

    with pytest.raises(OutOfScopeError):
        FrontingAssessmentService(resolver, ct_client).run(
            FrontingAssessmentRequest(
                "outside.example", _scope(tmp_path / "scope.json"), audit_log
            )
        )

    assert resolver.calls == []
    assert ct_client.calls == []
    assert "outside.example" in audit_log.read_text(encoding="utf-8")


def test_fronting_service_rejects_invalid_limit_before_network(tmp_path: Path) -> None:
    resolver = RecordingResolver()
    ct_client = RecordingCtClient()

    with pytest.raises(ValueError, match="max_subdomains"):
        FrontingAssessmentService(resolver, ct_client).run(
            FrontingAssessmentRequest(
                DOMAIN,
                _scope(tmp_path / "scope.json"),
                tmp_path / "audit.log",
                max_subdomains=-1,
            )
        )

    assert resolver.calls == []
    assert ct_client.calls == []


def test_dns_lookup_service_runs_without_cli_dependency(tmp_path: Path) -> None:
    http = RecordingHttpClient()

    result = DnsLookupService(http).run(
        DnsLookupRequest(
            DOMAIN,
            _scope(tmp_path / "scope.json"),
            tmp_path / "audit.log",
            record_types=("a",),
        )
    )

    assert result.records == {"A": ["203.0.113.20"]}
    assert len(http.calls) == 1
    assert "type=A" in http.calls[0]


def test_dns_lookup_service_blocks_before_http(tmp_path: Path) -> None:
    http = RecordingHttpClient()
    audit_log = tmp_path / "audit.log"

    with pytest.raises(OutOfScopeError):
        DnsLookupService(http).run(
            DnsLookupRequest(
                "outside.example",
                _scope(tmp_path / "scope.json"),
                audit_log,
                record_types=("A",),
            )
        )

    assert http.calls == []
    assert "outside.example" in audit_log.read_text(encoding="utf-8")


def test_dns_lookup_service_rejects_empty_types_before_http(tmp_path: Path) -> None:
    http = RecordingHttpClient()

    with pytest.raises(ValueError, match="record_types"):
        DnsLookupService(http).run(
            DnsLookupRequest(
                DOMAIN,
                _scope(tmp_path / "scope.json"),
                tmp_path / "audit.log",
                record_types=(),
            )
        )

    assert http.calls == []


def test_whois_lookup_service_runs_without_cli_dependency(tmp_path: Path) -> None:
    http = RecordingRdapClient()

    result = WhoisLookupService(http).run(
        WhoisLookupRequest(DOMAIN, _scope(tmp_path / "scope.json"), tmp_path / "audit.log")
    )

    assert result.domain == DOMAIN.upper()
    assert result.status == ["active"]
    assert http.calls == [f"https://rdap.org/domain/{DOMAIN}"]


def test_whois_lookup_service_blocks_before_http(tmp_path: Path) -> None:
    http = RecordingRdapClient()
    audit_log = tmp_path / "audit.log"

    with pytest.raises(OutOfScopeError):
        WhoisLookupService(http).run(
            WhoisLookupRequest("outside.example", _scope(tmp_path / "scope.json"), audit_log)
        )

    assert http.calls == []
    assert "outside.example" in audit_log.read_text(encoding="utf-8")
