"""Apollo detection engine producing shared Alert objects."""

from olympus.apollo.rules import DetectionRule, matches
from olympus.core.enums import Source
from olympus.core.models import Alert, Event


def evaluate(rules: list[DetectionRule], event: Event) -> list[Alert]:
    """Evaluate rules against an event and return normalized alerts."""
    return [
        Alert(
            event_id=event.event_id,
            title=rule.title,
            source=Source.APOLLO,
            severity=rule.severity,
        )
        for rule in rules
        if matches(rule, event)
    ]


def evaluate_stream(rules: list[DetectionRule], events: list[Event]) -> list[Alert]:
    """Evaluate every rule against every event, returning all fired alerts."""
    return [alert for event in events for alert in evaluate(rules, event)]
