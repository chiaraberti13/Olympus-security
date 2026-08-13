"""Generate detection-style Alerts for high-risk exposed services.

A Finding severe enough to indicate a high-risk exposure (telnet, RDP,
SMB, FTP...) also raises a `core.Alert` — the same object type Apollo's
detection engine produces — so Vulcan can later aggregate both uniformly
regardless of which module raised them.
"""

from __future__ import annotations

from olympus.core.enums import Severity, Source
from olympus.core.models import Alert, Finding

ALERT_RULE_ID = "HELIOS-HIGH-RISK-PORT-EXPOSED"
ALERTING_SEVERITIES = frozenset({Severity.HIGH, Severity.CRITICAL})


def build_alerts(findings: list[Finding]) -> list[Alert]:
    """Return one Alert per Finding severe enough to indicate high-risk exposure."""
    return [
        Alert(
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            source=Source.HELIOS,
            rule_id=ALERT_RULE_ID,
        )
        for finding in findings
        if finding.severity in ALERTING_SEVERITIES
    ]
