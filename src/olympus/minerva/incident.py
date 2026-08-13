"""Open an Incident by aggregating Alerts and Findings into one investigation.

Minerva's entry point into incident response: given a set of Alerts
and/or Findings that appear related (e.g. from the same asset, or the
same detection sweep), :func:`open_incident` builds a single
`core.Incident` referencing them, so the rest of the response workflow
has one object to work with instead of a loose pile of alerts.
"""

from __future__ import annotations

from olympus.core.enums import Severity, Source
from olympus.core.models import Alert, Finding, Incident

_SEVERITY_ORDER: list[Severity] = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def _highest_severity(severities: list[Severity]) -> Severity:
    """Return the highest of ``severities``, or MEDIUM if empty."""
    if not severities:
        return Severity.MEDIUM
    return max(severities, key=_SEVERITY_ORDER.index)


def open_incident(
    title: str,
    *,
    alerts: list[Alert] | None = None,
    findings: list[Finding] | None = None,
    description: str = "",
) -> Incident:
    """Open a new Incident aggregating ``alerts``/``findings``.

    Severity is the highest among all linked alerts/findings (MEDIUM if
    none given). ``asset_ids`` are collected from findings, deduplicated
    and sorted (alerts don't carry an asset reference in the schema).
    """
    alerts = alerts or []
    findings = findings or []
    severities = [alert.severity for alert in alerts] + [finding.severity for finding in findings]
    asset_ids = sorted({finding.asset_id for finding in findings})

    return Incident(
        title=title,
        description=description,
        severity=_highest_severity(severities),
        source=Source.MINERVA,
        asset_ids=asset_ids,
        finding_ids=[finding.finding_id for finding in findings],
        alert_ids=[alert.alert_id for alert in alerts],
    )
