"""Incident status transitions: a small state machine over IncidentStatus.

Enforces a valid response lifecycle: an incident can advance one step at
a time through the standard NEW -> TRIAGED -> CONTAINED -> RESOLVED ->
CLOSED progression, or be closed directly from any non-closed state (a
false positive doesn't need to walk the whole lifecycle) — but it can
never move backward or skip an intermediate active step.
"""

from __future__ import annotations

from datetime import UTC, datetime

from olympus.core.enums import IncidentStatus
from olympus.core.models import Incident

_ORDER: list[IncidentStatus] = [
    IncidentStatus.NEW,
    IncidentStatus.TRIAGED,
    IncidentStatus.CONTAINED,
    IncidentStatus.RESOLVED,
    IncidentStatus.CLOSED,
]


class InvalidTransitionError(Exception):
    """Raised when an incident status transition violates the response lifecycle."""

    def __init__(self, current: IncidentStatus, target: IncidentStatus) -> None:
        super().__init__(f"cannot transition incident from {current} to {target}")
        self.current = current
        self.target = target


def is_valid_transition(current: IncidentStatus, target: IncidentStatus) -> bool:
    """Return ``True`` if moving from ``current`` to ``target`` is allowed."""
    if target == IncidentStatus.CLOSED:
        return current != IncidentStatus.CLOSED
    return _ORDER.index(target) == _ORDER.index(current) + 1


def transition(incident: Incident, target: IncidentStatus) -> Incident:
    """Return a copy of ``incident`` moved to ``target`` status.

    Raises :class:`InvalidTransitionError` if the transition is not allowed.
    Sets ``closed_at`` when (and only when) transitioning to CLOSED.
    """
    if not is_valid_transition(incident.status, target):
        raise InvalidTransitionError(incident.status, target)

    updates: dict[str, object] = {"status": target}
    if target == IncidentStatus.CLOSED:
        updates["closed_at"] = datetime.now(UTC)
    return incident.model_copy(update=updates)
