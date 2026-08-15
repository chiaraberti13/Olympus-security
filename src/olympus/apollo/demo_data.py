"""Synthetic "Olympus Demo Corp" event stream used by `apollo demo`.

A small, fully offline authentication log with a mix of failed and
successful logins plus one unrelated network event, so the demo rule
(``examples/input/apollo-rules/brute-force.yaml``) has something real to
fire on, and something real to correctly ignore.
"""

from __future__ import annotations

from olympus.core.enums import EventType, Source
from olympus.core.models import Event


def demo_events() -> list[Event]:
    """Return a synthetic authentication event stream for Olympus Demo Corp."""
    return [
        Event(
            event_type=EventType.AUTHENTICATION,
            source=Source.APOLLO,
            summary="login attempt for user admin",
            raw={"user": "admin", "outcome": "failure"},
        ),
        Event(
            event_type=EventType.AUTHENTICATION,
            source=Source.APOLLO,
            summary="login attempt for user admin",
            raw={"user": "admin", "outcome": "failure"},
        ),
        Event(
            event_type=EventType.AUTHENTICATION,
            source=Source.APOLLO,
            summary="login attempt for user admin",
            raw={"user": "admin", "outcome": "failure"},
        ),
        Event(
            event_type=EventType.AUTHENTICATION,
            source=Source.APOLLO,
            summary="login attempt for user jdoe",
            raw={"user": "jdoe", "outcome": "success"},
        ),
        Event(
            event_type=EventType.NETWORK,
            source=Source.APOLLO,
            summary="outbound HTTPS connection",
            raw={"dest_port": "443"},
        ),
    ]


def demo_web_events() -> list[Event]:
    """Return synthetic web-request events for the Metabase SQLi detection rule.

    The first is a (synthetic) exploitation attempt against the vulnerable
    ``/api/session/reset_password`` endpoint; the second is a benign password
    reset to the same path, so the rule has something real to fire on and
    something real to correctly ignore.
    """
    return [
        Event(
            event_type=EventType.NETWORK,
            source=Source.APOLLO,
            summary="POST /api/session/reset_password (suspicious)",
            raw={
                "http_method": "POST",
                "http_path": "/api/session/reset_password",
                "http_body": "token=x' UNION SELECT id,email,password FROM core_user--",
            },
        ),
        Event(
            event_type=EventType.NETWORK,
            source=Source.APOLLO,
            summary="POST /api/session/reset_password (benign reset)",
            raw={
                "http_method": "POST",
                "http_path": "/api/session/reset_password",
                "http_body": "token=6a3f2b18-0000-4c00-8000-000000000000",
            },
        ),
    ]
