#!/usr/bin/env python3
"""Compliance utilities for privacy, consent, and audit trail."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional
from uuid import uuid4

from starlette.requests import Request
from sqlalchemy.orm import Session

from config import settings
from database import AuditEvent, ConsentRecord, Scan
from security import get_request_ip, redact_api_key, redact_sensitive_data, verify_jwt_token


CONSENT_TYPES = ("privacy_policy", "terms_of_service")
DATA_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")


def get_subject_id(request: Request) -> str:
    header_subject = request.headers.get("x-data-subject", "").strip()
    if header_subject:
        return header_subject
    subject_id = request.session.get("subject_id")
    if not subject_id:
        subject_id = uuid4().hex
        request.session["subject_id"] = subject_id
    return subject_id


def resolve_actor(request: Request) -> str:
    actor_header = request.headers.get("x-actor-id")
    if actor_header:
        return actor_header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        try:
            claims = verify_jwt_token(token)
            subject = claims.get("sub")
            if subject:
                return f"jwt:{subject}"
        except ValueError:
            pass
    api_key = request.headers.get("x-api-key") or request.query_params.get("api_key")
    if api_key:
        return f"api_key:{redact_api_key(api_key)}"
    return f"session:{get_subject_id(request)}"


def record_consent(
    db: Session,
    request: Request,
    subject_id: str,
    consent_type: str,
    version: str,
) -> ConsentRecord:
    consent = ConsentRecord(
        subject_id=subject_id,
        consent_type=consent_type,
        version=version,
        accepted_at=datetime.now(timezone.utc),
        ip_address=get_request_ip(request),
        user_agent=request.headers.get("user-agent", ""),
    )
    db.add(consent)
    db.commit()
    db.refresh(consent)
    return consent


def has_required_consents(db: Session, subject_id: str) -> bool:
    required_versions = {
        "privacy_policy": settings.privacy_policy_version,
        "terms_of_service": settings.terms_of_service_version,
    }
    for consent_type, version in required_versions.items():
        exists = (
            db.query(ConsentRecord)
            .filter(
                ConsentRecord.subject_id == subject_id,
                ConsentRecord.consent_type == consent_type,
                ConsentRecord.version == version,
            )
            .first()
        )
        if not exists:
            return False
    return True


def record_audit_event(
    db: Session,
    request: Request,
    event: str,
    subject_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    payload = json.dumps(redact_sensitive_data(metadata or {}), ensure_ascii=False)
    audit_event = AuditEvent(
        event=event,
        subject_id=subject_id,
        actor=resolve_actor(request),
        created_at=datetime.now(timezone.utc),
        ip_address=get_request_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        metadata_json=payload,
    )
    db.add(audit_event)
    db.commit()
    db.refresh(audit_event)
    return audit_event


def anonymize_scan_for_export(scan: Scan) -> Dict[str, Any]:
    target = scan.target
    redacted_target = target
    if "@" in target:
        redacted_target = target.split("@", 1)[-1]
    if "://" in target:
        scheme, rest = target.split("://", 1)
        host = rest.split("/", 1)[0]
        redacted_target = f"{scheme}://{host[:3]}***"
    return {
        "id": scan.id,
        "target": redacted_target,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "created_at": scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "data_classification": scan.data_classification,
    }
