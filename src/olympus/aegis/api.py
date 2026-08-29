"""Authenticated native HTTP API for the AEGIS control plane."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

from olympus import __version__
from olympus.aegis.jobs import AegisJob, AegisJobStore, JobState
from olympus.integrations.capabilities import inventory_document

MAX_REQUEST_BYTES = 64 * 1024
_API_KEY_HEADER = APIKeyHeader(name="X-Olympus-API-Key", auto_error=False)


@dataclass(frozen=True)
class ApiSettings:
    """Server-owned settings; secrets and filesystem roots never enter requests."""

    database: Path
    scope_directory: Path
    api_key: str

    def validate(self) -> None:
        if len(self.api_key) < 32:
            raise ValueError("AEGIS API key must contain at least 32 characters")
        root = self.scope_directory.resolve()
        if not root.exists() or not root.is_dir() or root.is_symlink():
            raise ValueError("AEGIS scope directory must be an existing non-symlink directory")


class JobSubmission(BaseModel):
    """Bounded request body for one authorized job."""

    model_config = ConfigDict(extra="forbid")

    scanner: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    target: str = Field(min_length=1, max_length=2_048)
    target_kind: Literal["host", "domain", "url"] = "host"
    scope_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    authorized: bool


class JobList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.aegis-job-list"] = "olympus.aegis-job-list"
    schema_version: Literal["1.0.0"] = "1.0.0"
    count: int
    jobs: list[AegisJob]


def create_app(settings: ApiSettings) -> FastAPI:
    """Build a fail-closed AEGIS API around the canonical durable job store."""
    settings.validate()
    store = AegisJobStore(settings.database)
    store.initialize()
    scope_root = settings.scope_directory.resolve()

    app = FastAPI(
        title="Olympus AEGIS API",
        version=__version__,
        description="Authorized specialist-engine orchestration and evidence lifecycle.",
    )
    async def authenticate(
        supplied: Annotated[str | None, Depends(_API_KEY_HEADER)],
    ) -> None:
        if not secrets.compare_digest(supplied or "", settings.api_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing or invalid API credential",
                headers={"WWW-Authenticate": "ApiKey"},
            )

    auth = Depends(authenticate)

    @app.middleware("http")
    async def security_boundary(request: Request, call_next):  # type: ignore[no-untyped-def]
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared_length = int(content_length)
                too_large = declared_length < 0 or declared_length > MAX_REQUEST_BYTES
            except ValueError:
                too_large = True
            if too_large:
                return JSONResponse(status_code=413, content={"detail": "request body too large"})

        # Content-Length is optional and cannot be trusted. Consume the ASGI body
        # stream incrementally, stop at the first byte above the limit, then cache
        # only the bounded body for FastAPI's downstream parser.
        bounded_body = bytearray()
        async for chunk in request.stream():
            if len(bounded_body) + len(chunk) > MAX_REQUEST_BYTES:
                return JSONResponse(status_code=413, content={"detail": "request body too large"})
            bounded_body.extend(chunk)
        request._body = bytes(bounded_body)  # type: ignore[attr-defined]

        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/health", tags=["operations"])
    def health() -> dict[str, str]:
        return {
            "schema_name": "olympus.health",
            "schema_version": "1.0.0",
            "service": "aegis",
            "status": "ok",
            "version": __version__,
        }

    @app.get("/ready", dependencies=[auth], tags=["operations"])
    def ready() -> dict[str, object]:
        store.initialize()
        return {
            "schema_name": "olympus.aegis-readiness",
            "schema_version": "1.0.0",
            "status": "ready",
            "control_plane": True,
            "capabilities": inventory_document(),
        }

    @app.get("/api/v1/capabilities", dependencies=[auth], tags=["capabilities"])
    def capabilities() -> dict[str, object]:
        return inventory_document()

    @app.post(
        "/api/v1/jobs",
        response_model=AegisJob,
        status_code=status.HTTP_201_CREATED,
        dependencies=[auth],
        tags=["jobs"],
    )
    def submit(body: JobSubmission) -> AegisJob:
        if not body.authorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="documented authorization must be confirmed",
            )
        scope_path = _registered_scope(scope_root, body.scope_id)
        try:
            return store.submit(
                scanner=body.scanner,
                target=body.target,
                target_kind=body.target_kind,
                scope_path=scope_path,
                authorized=True,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get(
        "/api/v1/jobs",
        response_model=JobList,
        dependencies=[auth],
        tags=["jobs"],
    )
    def list_jobs(
        limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
        state_filter: Annotated[JobState | None, Query(alias="state")] = None,
    ) -> JobList:
        jobs = store.list(limit=limit, state=state_filter)
        return JobList(count=len(jobs), jobs=jobs)

    @app.get(
        "/api/v1/jobs/{job_id}",
        response_model=AegisJob,
        dependencies=[auth],
        tags=["jobs"],
    )
    def get_job(job_id: str) -> AegisJob:
        return _get(store, job_id)

    @app.post(
        "/api/v1/jobs/{job_id}/cancel",
        response_model=AegisJob,
        dependencies=[auth],
        tags=["jobs"],
    )
    def cancel_job(job_id: str) -> AegisJob:
        try:
            return store.cancel(job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=exc.args[0]) from exc

    return app


def _registered_scope(root: Path, scope_id: str) -> Path:
    unresolved = root / f"{scope_id}.json"
    if unresolved.is_symlink():
        raise HTTPException(status_code=404, detail="registered scope not found")
    candidate = unresolved.resolve()
    if not candidate.is_relative_to(root):
        raise HTTPException(status_code=400, detail="invalid scope identifier")
    if not candidate.exists() or not candidate.is_file() or candidate.is_symlink():
        raise HTTPException(status_code=404, detail="registered scope not found")
    return candidate


def _get(store: AegisJobStore, job_id: str) -> AegisJob:
    try:
        return store.get(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=exc.args[0]) from exc
