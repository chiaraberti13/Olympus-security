from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.aegis.application import AegisApplicationService
from olympus.aegis.base import ScannerAdapter
from olympus.aegis.jobs import AegisJobStore, AegisWorker, JobState
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.cli import app

runner = CliRunner()


class _Adapter(ScannerAdapter):
    name = "test-engine"
    binary = "true"

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        return ["true"]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list:
        return []


def _scope(path: Path) -> Path:
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


def test_durable_job_lifecycle(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "state" / "jobs.sqlite3")
    job = store.submit(
        scanner="test-engine",
        target="127.0.0.1",
        target_kind="host",
        scope_path=_scope(tmp_path / "scope.json"),
        authorized=True,
    )
    assert job.state is JobState.QUEUED
    worker = AegisWorker(
        store,
        AegisApplicationService(lambda name: _Adapter()),
        live_scans=True,
    )
    completed = worker.run_next(audit_path=tmp_path / "audit.ndjson")
    assert completed is not None and completed.state is JobState.SUCCEEDED
    assert completed.result is not None and completed.result["state"] == "live"
    assert store.get(job.job_id) == completed
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_atomic_claim_and_queue_order(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    scope = _scope(tmp_path / "scope.json")
    first = store.submit(
        scanner="test-engine", target="127.0.0.1", target_kind="host",
        scope_path=scope, authorized=True,
    )
    store.submit(
        scanner="test-engine", target="127.0.0.1", target_kind="host",
        scope_path=scope, authorized=True,
    )
    claimed = store.claim_next()
    assert claimed is not None and claimed.job_id == first.job_id
    assert store.list(state=JobState.RUNNING) == [claimed]


def test_queued_cancel_is_terminal_and_idempotent(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    job = store.submit(
        scanner="test-engine", target="127.0.0.1", target_kind="host",
        scope_path=_scope(tmp_path / "scope.json"), authorized=True,
    )
    cancelled = store.cancel(job.job_id)
    assert cancelled.state is JobState.CANCELLED
    assert store.cancel(job.job_id) == cancelled
    assert store.claim_next() is None


def test_failure_is_persisted_without_secret_fields(tmp_path: Path) -> None:
    class _Broken(_Adapter):
        def run(self, request: ScanRequest):
            raise RuntimeError("controlled failure")

    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    job = store.submit(
        scanner="test-engine", target="127.0.0.1", target_kind="host",
        scope_path=_scope(tmp_path / "scope.json"), authorized=True,
    )
    result = AegisWorker(
        store,
        AegisApplicationService(lambda name: _Broken()),
        live_scans=True,
    ).run_next()
    assert result is not None and result.state is JobState.FAILED
    assert result.error == "RuntimeError: controlled failure"
    assert job.job_id == result.job_id


def test_store_rejects_symlink_database(tmp_path: Path) -> None:
    target = tmp_path / "real.sqlite3"
    target.touch()
    link = tmp_path / "link.sqlite3"
    link.symlink_to(target)
    with pytest.raises(OSError, match="non-symlink"):
        AegisJobStore(link).initialize()


def test_job_cli_submit_list_status_cancel(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    scope = _scope(tmp_path / "scope.json")
    submitted = runner.invoke(
        app,
        [
            "aegis", "jobs", "submit", "nmap", "--target", "127.0.0.1",
            "--scope", str(scope), "--database", str(database), "--i-am-authorized",
        ],
    )
    assert submitted.exit_code == 0, submitted.output
    job_id = json.loads(submitted.output)["job_id"]
    listed = runner.invoke(app, ["aegis", "jobs", "list", "-d", str(database)])
    assert listed.exit_code == 0 and json.loads(listed.output)["count"] == 1
    status = runner.invoke(app, ["aegis", "jobs", "status", job_id, "-d", str(database)])
    assert status.exit_code == 0 and json.loads(status.output)["state"] == "queued"
    cancelled = runner.invoke(app, ["aegis", "jobs", "cancel", job_id, "-d", str(database)])
    assert cancelled.exit_code == 0 and json.loads(cancelled.output)["state"] == "cancelled"


def test_job_cli_refuses_unconfirmed_authorization(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "aegis", "jobs", "submit", "nmap", "--target", "127.0.0.1",
            "--scope", str(_scope(tmp_path / "scope.json")),
            "--database", str(tmp_path / "jobs.sqlite3"),
        ],
    )
    assert result.exit_code == 4
    assert "requires --i-am-authorized" in result.output
