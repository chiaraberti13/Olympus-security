from contextlib import contextmanager
import os
from pathlib import Path
import sys
from typing import Any, Callable, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Disabilita il refresh dei feed all'avvio durante i test: evita chiamate di
# rete e scritture su disco quando il lifespan dell'app viene attivato da
# TestClient. Va impostato prima di importare `app`/`config`.
os.environ.setdefault("VAP_FEED_UPDATE_ON_STARTUP", "false")

import pytest
from fastapi.testclient import TestClient

import app
from database import (
    AuditEvent,
    LearningFeedback,
    LearningPathProgress,
    Scan,
    ScanConfigurationPreset,
    SessionLocal,
    init_db,
)


def clear_persistent_state(include_learning_artifacts: bool = True) -> None:
    """
    Ripulisce lo stato persistente condiviso tra test.

    include_learning_artifacts=False mantiene il cleanup minimale usato dalle suite
    che non toccano direttamente preset/progress didattici.
    """
    init_db()
    with SessionLocal() as session:
        session.query(Scan).delete()
        session.query(AuditEvent).delete()
        if include_learning_artifacts:
            session.query(LearningFeedback).delete()
            session.query(LearningPathProgress).delete()
            session.query(ScanConfigurationPreset).delete()
        session.commit()


@pytest.fixture(autouse=True)
def reset_runtime_state():
    """Isola lo stato runtime tra i test API (override dependency + rate limit)."""
    app.app.dependency_overrides.clear()
    limiter_storage = getattr(app.limiter, "_storage", None)
    if limiter_storage is not None:
        limiter_storage.reset()

    yield

    app.app.dependency_overrides.clear()
    limiter_storage = getattr(app.limiter, "_storage", None)
    if limiter_storage is not None:
        limiter_storage.reset()


@pytest.fixture
def seed_scan() -> Callable[..., Scan]:
    """Factory per creare scansioni nei test UI/API riducendo boilerplate."""

    def _seed_scan(**overrides: Any) -> Scan:
        defaults = {
            "target": "example.com",
            "scan_type": "full",
            "status": "completed",
            "data_classification": "internal",
            "logs_json": "[]",
            "findings_json": "[]",
        }
        defaults.update(overrides)
        with SessionLocal() as session:
            scan = Scan(**defaults)
            session.add(scan)
            session.commit()
            session.refresh(scan)
            session.expunge(scan)
            return scan

    return _seed_scan


@pytest.fixture
def seed_audit_event() -> Callable[..., AuditEvent]:
    """Factory per creare eventi audit espliciti nei test API/analytics."""

    def _seed_audit_event(**overrides: Any) -> AuditEvent:
        defaults = {
            "event": "test_event",
            "subject_id": "test-subject",
            "actor": "session:test-subject",
            "metadata_json": "{}",
        }
        defaults.update(overrides)
        with SessionLocal() as session:
            event = AuditEvent(**defaults)
            session.add(event)
            session.commit()
            session.refresh(event)
            session.expunge(event)
            return event

    return _seed_audit_event


@pytest.fixture
def bootstrap_guided_form_client() -> Callable[[], Iterator[tuple[TestClient, str]]]:
    """
    Bootstrap condiviso per i test journey/compliance del form guidato.

    Esegue:
    1) override API key form-only;
    2) homepage GET per inizializzare cookie CSRF;
    3) esposizione di (client, csrf_token) pronto all'uso.
    """

    @contextmanager
    def _bootstrap() -> Iterator[tuple[TestClient, str]]:
        app.app.dependency_overrides[app.enforce_api_key_form_dependency] = lambda: None
        try:
            with TestClient(app.app) as client:
                homepage = client.get("/")
                assert homepage.status_code == 200
                csrf_cookie = client.cookies.get(app.settings.csrf_cookie_name)
                assert csrf_cookie
                yield client, csrf_cookie
        finally:
            app.app.dependency_overrides.pop(app.enforce_api_key_form_dependency, None)

    return _bootstrap


@pytest.fixture
def bootstrap_csrf_json_client() -> Callable[..., Iterator[tuple[TestClient, dict[str, str]]]]:
    """
    Bootstrap condiviso per endpoint JSON protetti da CSRF.

    Esegue:
    1) homepage GET per inizializzare cookie CSRF;
    2) costruzione header base con x-csrf-token;
    3) merge opzionale con header custom (es. x-data-subject).
    """

    @contextmanager
    def _bootstrap(extra_headers: dict[str, str] | None = None) -> Iterator[tuple[TestClient, dict[str, str]]]:
        with TestClient(app.app) as client:
            homepage = client.get("/")
            assert homepage.status_code == 200
            csrf_cookie = client.cookies.get(app.settings.csrf_cookie_name)
            assert csrf_cookie
            headers = {"x-csrf-token": csrf_cookie}
            if extra_headers:
                headers.update(extra_headers)
            yield client, headers

    return _bootstrap


@pytest.fixture
def subject_headers() -> Callable[..., dict[str, str]]:
    """
    Helper read-only per header di subject routing negli endpoint GET.

    Riduce boilerplate e mantiene semantica coerente tra test KPI/trend/read API.
    """

    def _subject_headers(subject_id: str, extra_headers: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"x-data-subject": subject_id}
        if extra_headers:
            headers.update(extra_headers)
        return headers

    return _subject_headers
