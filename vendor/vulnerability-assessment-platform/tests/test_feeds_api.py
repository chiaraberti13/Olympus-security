"""Test degli endpoint API per lo stato e l'aggiornamento dei feed."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

import app


def test_feeds_status_endpoint_returns_definitions():
    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_viewer_role] = lambda: "viewer"
    try:
        with TestClient(app.app) as client:
            response = client.get("/api/v1/feeds/status")
        assert response.status_code == 200
        payload = response.json()
        assert "overall_status" in payload
        assert any(d["key"] == "nvd" for d in payload.get("definitions", []))
    finally:
        app.app.dependency_overrides.clear()


def test_feeds_refresh_endpoint_invokes_updater(monkeypatch):
    canned = {
        "last_run_at": "2026-06-10T12:00:00+00:00",
        "overall_status": "ok",
        "feeds": {"nvd": {"key": "nvd", "status": "ok", "count": 3}},
    }
    monkeypatch.setattr(app, "refresh_all_feeds", lambda force=False: canned)

    app.app.dependency_overrides[app.enforce_api_key] = lambda: None
    app.app.dependency_overrides[app.enforce_admin_role] = lambda: "admin"
    try:
        with TestClient(app.app) as client:
            response = client.post("/api/v1/feeds/refresh")
        assert response.status_code == 200
        assert response.json()["overall_status"] == "ok"
        assert response.json()["feeds"]["nvd"]["count"] == 3
    finally:
        app.app.dependency_overrides.clear()
