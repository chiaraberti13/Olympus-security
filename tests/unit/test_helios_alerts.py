"""Unit tests for Helios high-risk-exposure Alert generation."""

from __future__ import annotations

from olympus.core.enums import FindingStatus, Severity, Source
from olympus.core.models import Finding
from olympus.helios.alerts import ALERT_RULE_ID, build_alerts


def _finding(title: str, severity: Severity) -> Finding:
    return Finding(
        asset_id="AST-2026-00001",
        source=Source.HELIOS,
        title=title,
        description=f"{title} description",
        severity=severity,
    )


def test_build_alerts_raises_alert_for_high_severity_finding() -> None:
    findings = [_finding("Open port 3389/tcp (rdp)", Severity.HIGH)]
    alerts = build_alerts(findings)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.title == "Open port 3389/tcp (rdp)"
    assert alert.severity == Severity.HIGH
    assert alert.source == Source.HELIOS
    assert alert.rule_id == ALERT_RULE_ID
    assert alert.status == FindingStatus.NEW


def test_build_alerts_raises_alert_for_critical_severity_finding() -> None:
    findings = [_finding("Critical exposure", Severity.CRITICAL)]
    assert len(build_alerts(findings)) == 1


def test_build_alerts_ignores_medium_and_low_severity_findings() -> None:
    findings = [
        _finding("Open port 80/tcp (http)", Severity.MEDIUM),
        _finding("Open port 443/tcp (https)", Severity.LOW),
    ]
    assert build_alerts(findings) == []


def test_build_alerts_no_findings_yields_no_alerts() -> None:
    assert build_alerts([]) == []


def test_build_alerts_one_alert_per_qualifying_finding() -> None:
    findings = [
        _finding("Open port 3389/tcp (rdp)", Severity.HIGH),
        _finding("Open port 23/tcp (telnet)", Severity.HIGH),
        _finding("Open port 80/tcp (http)", Severity.MEDIUM),
    ]
    alerts = build_alerts(findings)
    assert len(alerts) == 2
    assert {a.title for a in alerts} == {
        "Open port 3389/tcp (rdp)",
        "Open port 23/tcp (telnet)",
    }
