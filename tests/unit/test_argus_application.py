"""Tests for command-independent Argus application use cases."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.argus.application import DomainScanRequest, DomainScanService
from olympus.argus.scope import OutOfScopeError

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
