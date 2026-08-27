from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from olympus.aegis.api import ApiSettings, create_app
from olympus.cli import app

API_KEY = "a" * 32
AUTH = {"X-Olympus-API-Key": API_KEY}


def _scope(directory: Path, name: str = "engagement") -> Path:
    directory.mkdir(parents=True)
    path = directory / f"{name}.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "olympus.aegis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_cidrs": ["127.0.0.0/8"],
            }
        ),
        encoding="utf-8",
    )
    return path


def _client(tmp_path: Path) -> TestClient:
    scopes = tmp_path / "scopes"
    _scope(scopes)
    return TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=scopes,
                api_key=API_KEY,
            )
        )
    )


def test_health_is_public_but_operational_routes_require_auth(tmp_path: Path) -> None:
    client = _client(tmp_path)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.headers["cache-control"] == "no-store"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert client.get("/ready").status_code == 401
    ready = client.get("/ready", headers=AUTH)
    assert ready.status_code == 200
    assert ready.json()["control_plane"] is True


def test_authenticated_job_lifecycle_uses_registered_scope(tmp_path: Path) -> None:
    client = _client(tmp_path)
    payload = {
        "scanner": "nmap",
        "target": "127.0.0.1",
        "target_kind": "host",
        "scope_id": "engagement",
        "authorized": True,
    }
    submitted = client.post("/api/v1/jobs", headers=AUTH, json=payload)
    assert submitted.status_code == 201, submitted.text
    job_id = submitted.json()["job_id"]
    listed = client.get("/api/v1/jobs?state=queued", headers=AUTH)
    assert listed.status_code == 200 and listed.json()["count"] == 1
    assert client.get(f"/api/v1/jobs/{job_id}", headers=AUTH).status_code == 200
    cancelled = client.post(f"/api/v1/jobs/{job_id}/cancel", headers=AUTH)
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"


def test_api_refuses_unconfirmed_or_unregistered_work(tmp_path: Path) -> None:
    client = _client(tmp_path)
    payload = {
        "scanner": "nmap",
        "target": "127.0.0.1",
        "scope_id": "missing",
        "authorized": False,
    }
    assert client.post("/api/v1/jobs", headers=AUTH, json=payload).status_code == 403
    payload["authorized"] = True
    assert client.post("/api/v1/jobs", headers=AUTH, json=payload).status_code == 404
    payload["scope_id"] = "../escape"
    assert client.post("/api/v1/jobs", headers=AUTH, json=payload).status_code == 422


def test_api_rejects_symlink_scope_and_oversized_body(tmp_path: Path) -> None:
    client = _client(tmp_path)
    real = _scope(tmp_path / "outside", "real")
    (tmp_path / "scopes" / "linked.json").symlink_to(real)
    payload = {
        "scanner": "nmap",
        "target": "127.0.0.1",
        "scope_id": "linked",
        "authorized": True,
    }
    assert client.post("/api/v1/jobs", headers=AUTH, json=payload).status_code == 404
    headers = {**AUTH, "Content-Length": str(64 * 1024 + 1)}
    assert client.post("/api/v1/jobs", headers=headers, json=payload).status_code == 413


def test_cli_requires_secret_and_tls_for_remote_bind(tmp_path: Path) -> None:
    runner = CliRunner()
    scopes = tmp_path / "scopes"
    scopes.mkdir()
    missing = runner.invoke(app, ["aegis", "api", "--scope-directory", str(scopes)])
    assert missing.exit_code == 2
    assert "environment variable is not set" in missing.output
    remote = runner.invoke(
        app,
        ["aegis", "api", "--scope-directory", str(scopes), "--host", "0.0.0.0"],  # noqa: S104
        env={"OLYMPUS_AEGIS_API_KEY": API_KEY},
    )
    assert remote.exit_code == 2
    assert "require TLS" in remote.output
