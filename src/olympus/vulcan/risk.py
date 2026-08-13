"""Risk scoring: order aggregated Findings by CVSS then severity.

Vulcan's risk view ranks findings so the analyst sees the worst first.
CVSS (0.0-10.0, precise) takes priority when present since it's a
calibrated score; severity (a coarser 5-level scale) is the tiebreaker,
and the sole ranking signal for findings with no CVSS.
"""

from __future__ import annotations

from olympus.core.enums import Severity
from olympus.core.models import Finding

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def risk_score(finding: Finding) -> tuple[float, int]:
    """Return a sortable ``(cvss_or_zero, severity_rank)`` risk score for ``finding``."""
    return (finding.cvss or 0.0, _SEVERITY_RANK[finding.severity])


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Return ``findings`` sorted from highest to lowest risk."""
    return sorted(findings, key=risk_score, reverse=True)
