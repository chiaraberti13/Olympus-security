"""Durable, dependency-light AEGIS job control plane.

This module replaces the legacy VAP/Celery ownership boundary for local and
single-node deployments.  SQLite owns job lifecycle and cancellation intent;
the existing AEGIS application service remains the only path that may execute
an adapter, so authorization, scope, SSRF controls, audit and output limits are
not bypassed by queued work.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from olympus.aegis.application import AegisApplicationService, AegisRunRequest
from olympus.aegis.config import live_enabled
from olympus.core.execution import Cancellation


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATES = frozenset({JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED})


class AegisJob(BaseModel):
    """Versioned job document returned consistently by CLI, API and workers."""

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.aegis-job"] = "olympus.aegis-job"
    schema_version: Literal["1.0.0"] = "1.0.0"
    job_id: str = Field(pattern=r"^AEGIS-[A-F0-9]{32}$")
    scanner: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    target: str = Field(min_length=1, max_length=2_048)
    target_kind: Literal["host", "domain", "url"]
    scope_path: str = Field(min_length=1, max_length=4_096)
    state: JobState
    authorized: bool
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: dict[str, object] | None = None
    error: str | None = Field(default=None, max_length=2_000)


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class AegisJobStore:
    """SQLite repository with atomic claim and state transitions."""

    path: Path

    def initialize(self) -> None:
        self._validate_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS aegis_jobs (
                    job_id TEXT PRIMARY KEY,
                    scanner TEXT NOT NULL,
                    target TEXT NOT NULL,
                    target_kind TEXT NOT NULL,
                    scope_path TEXT NOT NULL,
                    authorized INTEGER NOT NULL CHECK (authorized IN (0, 1)),
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    result_json TEXT,
                    error TEXT,
                    cancel_requested INTEGER NOT NULL DEFAULT 0
                        CHECK (cancel_requested IN (0, 1))
                );
                CREATE INDEX IF NOT EXISTS idx_aegis_jobs_state_created
                    ON aegis_jobs(state, created_at);
                """
            )
        self.path.chmod(0o600)

    def submit(
        self,
        *,
        scanner: str,
        target: str,
        target_kind: str,
        scope_path: Path,
        authorized: bool,
    ) -> AegisJob:
        self.initialize()
        # Reuse the strict request validation before persisting untrusted data.
        AegisRunRequest(
            scanner=scanner,
            target=target,
            target_kind=target_kind,
            scope_path=scope_path,
            authorized=authorized,
            live_enabled=False,
        )
        timestamp = _now()
        job_id = f"AEGIS-{uuid4().hex.upper()}"
        with self._connect() as db:
            db.execute(
                """INSERT INTO aegis_jobs
                (job_id, scanner, target, target_kind, scope_path, authorized,
                 state, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    job_id,
                    scanner,
                    target,
                    target_kind,
                    str(scope_path.resolve()),
                    int(authorized),
                    JobState.QUEUED.value,
                    timestamp,
                    timestamp,
                ),
            )
        return self.get(job_id)

    def get(self, job_id: str) -> AegisJob:
        self.initialize()
        with self._connect() as db:
            row = db.execute("SELECT * FROM aegis_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown AEGIS job: {job_id}")
        return _job(row)

    def list(self, *, limit: int = 100, state: JobState | None = None) -> list[AegisJob]:
        self.initialize()
        if not 1 <= limit <= 1_000:
            raise ValueError("job list limit must be between 1 and 1000")
        query = "SELECT * FROM aegis_jobs"
        params: tuple[object, ...]
        if state is None:
            params = (limit,)
        else:
            query += " WHERE state = ?"
            params = (state.value, limit)
        query += " ORDER BY created_at DESC LIMIT ?"
        with self._connect() as db:
            return [_job(row) for row in db.execute(query, params).fetchall()]

    def claim_next(self) -> AegisJob | None:
        self.initialize()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT job_id FROM aegis_jobs
                WHERE state = ? AND cancel_requested = 0
                ORDER BY created_at ASC LIMIT 1""",
                (JobState.QUEUED.value,),
            ).fetchone()
            if row is None:
                db.commit()
                return None
            timestamp = _now()
            changed = db.execute(
                """UPDATE aegis_jobs SET state = ?, started_at = ?, updated_at = ?
                WHERE job_id = ? AND state = ?""",
                (
                    JobState.RUNNING.value,
                    timestamp,
                    timestamp,
                    row["job_id"],
                    JobState.QUEUED.value,
                ),
            ).rowcount
            db.commit()
        return self.get(row["job_id"]) if changed == 1 else None

    def cancel(self, job_id: str) -> AegisJob:
        job = self.get(job_id)
        if job.state in TERMINAL_STATES:
            return job
        timestamp = _now()
        with self._connect() as db:
            if job.state is JobState.QUEUED:
                db.execute(
                    """UPDATE aegis_jobs SET state = ?, cancel_requested = 1,
                    finished_at = ?, updated_at = ? WHERE job_id = ?""",
                    (JobState.CANCELLED.value, timestamp, timestamp, job_id),
                )
            else:
                db.execute(
                    "UPDATE aegis_jobs SET cancel_requested = 1, updated_at = ? WHERE job_id = ?",
                    (timestamp, job_id),
                )
        return self.get(job_id)

    def cancellation_requested(self, job_id: str) -> bool:
        with self._connect() as db:
            row = db.execute(
                "SELECT cancel_requested FROM aegis_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return bool(row and row["cancel_requested"])

    def finish(self, job_id: str, result: dict[str, object]) -> AegisJob:
        return self._terminal(job_id, JobState.SUCCEEDED, result=result)

    def fail(self, job_id: str, error: str) -> AegisJob:
        return self._terminal(job_id, JobState.FAILED, error=error[:2_000])

    def mark_cancelled(self, job_id: str) -> AegisJob:
        return self._terminal(job_id, JobState.CANCELLED)

    def _terminal(
        self,
        job_id: str,
        state: JobState,
        *,
        result: dict[str, object] | None = None,
        error: str | None = None,
    ) -> AegisJob:
        timestamp = _now()
        with self._connect() as db:
            changed = db.execute(
                """UPDATE aegis_jobs SET state = ?, result_json = ?, error = ?,
                finished_at = ?, updated_at = ? WHERE job_id = ? AND state = ?""",
                (
                    state.value,
                    json.dumps(result, sort_keys=True) if result is not None else None,
                    error,
                    timestamp,
                    timestamp,
                    job_id,
                    JobState.RUNNING.value,
                ),
            ).rowcount
        if changed != 1:
            raise RuntimeError(f"job {job_id} is not running")
        return self.get(job_id)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA busy_timeout = 10000")
        return db

    def _validate_path(self) -> None:
        if self.path.exists() and (self.path.is_symlink() or not self.path.is_file()):
            raise OSError("AEGIS job database must be a regular non-symlink file")


@dataclass(frozen=True)
class _JobCancellation(Cancellation):
    store: AegisJobStore
    job_id: str

    def is_cancelled(self) -> bool:
        return self.store.cancellation_requested(self.job_id)


@dataclass(frozen=True)
class AegisWorker:
    """Claim and execute one durable job through the canonical application service."""

    store: AegisJobStore
    application: AegisApplicationService = field(default_factory=AegisApplicationService)
    live_scans: bool | None = None

    def run_next(self, *, audit_path: Path | None = None) -> AegisJob | None:
        job = self.store.claim_next()
        if job is None:
            return None
        if self.store.cancellation_requested(job.job_id):
            return self.store.mark_cancelled(job.job_id)
        try:
            result = self.application.run(
                AegisRunRequest(
                    scanner=job.scanner,
                    target=job.target,
                    target_kind=job.target_kind,
                    scope_path=Path(job.scope_path),
                    authorized=job.authorized,
                    live_enabled=live_enabled() if self.live_scans is None else self.live_scans,
                    audit_path=audit_path,
                    cancellation=_JobCancellation(self.store, job.job_id),
                )
            )
        except BaseException as exc:
            if self.store.cancellation_requested(job.job_id):
                return self.store.mark_cancelled(job.job_id)
            return self.store.fail(job.job_id, f"{type(exc).__name__}: {exc}")
        if self.store.cancellation_requested(job.job_id):
            return self.store.mark_cancelled(job.job_id)
        return self.store.finish(job.job_id, result.to_dict())


def _job(row: sqlite3.Row) -> AegisJob:
    return AegisJob(
        job_id=row["job_id"],
        scanner=row["scanner"],
        target=row["target"],
        target_kind=row["target_kind"],
        scope_path=row["scope_path"],
        state=row["state"],
        authorized=bool(row["authorized"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        result=json.loads(row["result_json"]) if row["result_json"] else None,
        error=row["error"],
    )
