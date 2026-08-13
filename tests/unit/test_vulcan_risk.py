"""Unit tests for Vulcan's CVSS + severity risk ranking."""

from __future__ import annotations

from olympus.core.enums import Severity, Source
from olympus.core.models import Finding
from olympus.vulcan.risk import rank_findings, risk_score


def _finding(title: str, severity: Severity, cvss: float | None = None) -> Finding:
    return Finding(
        asset_id="AST-2026-00001", source=Source.HELIOS, title=title, severity=severity, cvss=cvss
    )


def test_cvss_takes_priority_over_severity() -> None:
    low_severity_high_cvss = _finding("A", Severity.LOW, cvss=9.5)
    high_severity_no_cvss = _finding("B", Severity.CRITICAL)

    ranked = rank_findings([high_severity_no_cvss, low_severity_high_cvss])

    assert ranked[0].title == "A"
    assert ranked[1].title == "B"


def test_severity_breaks_ties_when_no_cvss() -> None:
    critical = _finding("A", Severity.CRITICAL)
    low = _finding("B", Severity.LOW)

    ranked = rank_findings([low, critical])

    assert ranked[0].title == "A"
    assert ranked[1].title == "B"


def test_higher_cvss_ranks_first_among_cvss_scored_findings() -> None:
    higher = _finding("A", Severity.MEDIUM, cvss=7.0)
    lower = _finding("B", Severity.MEDIUM, cvss=3.0)

    ranked = rank_findings([lower, higher])

    assert [f.title for f in ranked] == ["A", "B"]


def test_rank_findings_does_not_mutate_input_order() -> None:
    findings = [_finding("A", Severity.LOW), _finding("B", Severity.CRITICAL)]
    original = list(findings)

    rank_findings(findings)

    assert findings == original


def test_risk_score_defaults_cvss_to_zero_when_absent() -> None:
    assert risk_score(_finding("A", Severity.INFO)) == (0.0, 0)


def test_rank_findings_empty_list() -> None:
    assert rank_findings([]) == []
