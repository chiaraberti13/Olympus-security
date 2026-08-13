"""Generate core.Alert objects from matched detection rules, with evidence linking.

Each event that matches a rule becomes one Alert, referencing the
triggering event's id and carrying an Evidence entry pointing back at it,
so an alert can always be traced to the exact event that raised it.
"""

from __future__ import annotations

from olympus.apollo.engine import match_events
from olympus.apollo.rules import DetectionRule
from olympus.core.enums import EvidenceType, Source
from olympus.core.models import Alert, Event, Evidence


def build_alert(rule: DetectionRule, event: Event) -> Alert:
    """Build the Alert raised by ``event`` matching ``rule``, with evidence linking."""
    evidence = Evidence(
        evidence_type=EvidenceType.LOG_EXCERPT,
        description=f"Event matched by rule {rule.rule_id}",
        reference=event.event_id,
    )
    return Alert(
        title=rule.name,
        description=rule.description,
        severity=rule.severity,
        source=Source.APOLLO,
        rule_id=rule.rule_id,
        mitre_technique_id=rule.mitre_technique_id,
        event_ids=[event.event_id],
        evidence=[evidence],
    )


def generate_alerts(rule: DetectionRule, events: list[Event]) -> list[Alert]:
    """Match ``rule`` against ``events`` and return one Alert per matching event."""
    return [build_alert(rule, event) for event in match_events(rule, events)]
