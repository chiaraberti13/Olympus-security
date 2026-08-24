from __future__ import annotations

import json
from datetime import datetime, timezone

from starlette.requests import Request

from compliance import (
    anonymize_scan_for_export,
    get_subject_id,
    has_required_consents,
    record_audit_event,
)
from config import settings
from database import ConsentRecord, Scan, SessionLocal, init_db


def setup_module() -> None:
    init_db()


def _build_request(
    headers: dict[str, str] | None = None,
    query_string: str = b"",
    session: dict[str, str] | None = None,
) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [
            (key.lower().encode("latin-1"), value.encode("latin-1"))
            for key, value in (headers or {}).items()
        ],
        "query_string": query_string,
        "client": ("127.0.0.1", 4242),
        "session": session or {},
    }
    return Request(scope)


def test_get_subject_id_prefers_x_data_subject_header() -> None:
    request = _build_request(headers={"x-data-subject": "subject-from-header"}, session={"subject_id": "session-subject"})

    subject_id = get_subject_id(request)

    assert subject_id == "subject-from-header"
    assert request.session["subject_id"] == "session-subject"


def test_get_subject_id_bootstraps_session_subject_when_missing() -> None:
    request = _build_request(session={})

    subject_id = get_subject_id(request)

    assert subject_id
    assert request.session["subject_id"] == subject_id


def test_has_required_consents_requires_both_versions() -> None:
    subject_id = "compliance-required-consents"
    with SessionLocal() as session:
        session.query(ConsentRecord).filter(ConsentRecord.subject_id == subject_id).delete()
        session.add(
            ConsentRecord(
                subject_id=subject_id,
                consent_type="privacy_policy",
                version=settings.privacy_policy_version,
                accepted_at=datetime.now(timezone.utc),
            )
        )
        session.commit()

        assert has_required_consents(session, subject_id) is False

        session.add(
            ConsentRecord(
                subject_id=subject_id,
                consent_type="terms_of_service",
                version=settings.terms_of_service_version,
                accepted_at=datetime.now(timezone.utc),
            )
        )
        session.commit()

        assert has_required_consents(session, subject_id) is True


def test_record_audit_event_redacts_sensitive_metadata() -> None:
    request = _build_request(headers={"x-api-key": "vap-secret-key"})

    with SessionLocal() as session:
        event = record_audit_event(
            session,
            request=request,
            event="scan_requested",
            subject_id="subject-42",
            metadata={
                "api_key": "vap-secret-key",
                "authorization": "Bearer sensitive-token",
                "nested": {"token": "sensitive-token"},
            },
        )
        payload = json.loads(event.metadata_json)

    assert event.actor.startswith("api_key:")
    assert payload["api_key"].startswith("sha256:")
    assert payload["authorization"] == "<redacted>"
    assert payload["nested"]["token"] == "<redacted>"


def test_anonymize_scan_for_export_masks_target_host() -> None:
    with SessionLocal() as session:
        scan = Scan(
            target="https://security.example.com/admin",
            scan_type="full",
            status="completed",
            data_classification="restricted",
            findings_json="[]",
            logs_json="[]",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        session.expunge(scan)

    payload = anonymize_scan_for_export(scan)

    assert payload["target"] == "https://sec***"
    assert payload["scan_type"] == "full"
    assert payload["status"] == "completed"
