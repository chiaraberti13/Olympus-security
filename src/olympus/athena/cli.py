"""Command-line interface for Athena — assessment orchestration.

The CLI contains no domain decisions: it validates input, wires real adapters
into the application use cases, and translates outcomes into stable exit codes:

* ``0`` succeeded with no findings;
* ``1`` partial, or succeeded with findings to review;
* ``2`` invalid input or configuration;
* ``3`` authorization/scope denial;
* ``4`` execution or infrastructure failure (including cancellation).
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.athena.adapters.audit import SqliteAuditSink
from olympus.athena.adapters.report import VulcanReportRenderer
from olympus.athena.adapters.sqlite import SqliteAssessmentRepository
from olympus.athena.adapters.system import CoreIdProvider, SystemClock
from olympus.athena.application.coordinator import Coordinator, RunOutcome
from olympus.athena.application.planning import load_plan_file
from olympus.athena.application.registry import (
    UnknownAdapterError,
    available_adapters,
    resolve_adapters,
)
from olympus.athena.domain.assessment import AssessmentState
from olympus.athena.domain.contracts import AssessmentPlan, PlanValidationError
from olympus.athena.scope import ensure_web_target_allowed
from olympus.core.http import UrllibHttpClient

app = typer.Typer(help="Athena — assessment orchestration.", no_args_is_help=True)
plan_app = typer.Typer(help="Plan validation utilities.", no_args_is_help=True)
app.add_typer(plan_app, name="plan")

_DB_NAME = "athena.db"


def _open_repository(storage: Path) -> SqliteAssessmentRepository:
    return SqliteAssessmentRepository(storage / _DB_NAME)


@plan_app.command("validate")
def plan_validate(
    path: Path = typer.Argument(..., help="Path to the assessment plan JSON file."),
) -> None:
    """Validate a plan file against the Athena contract and adapter registry."""
    try:
        plan = load_plan_file(path)
    except PlanValidationError as exc:
        typer.echo(f"athena: invalid plan: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        json.dumps(
            {
                "valid": True,
                "engagement_id": plan.engagement_id,
                "name": plan.name,
                "targets": len(plan.targets),
                "adapters": list(plan.adapters),
                "plan_digest": plan.digest(),
                "scope_digest": plan.scope_digest(),
            },
            indent=2,
            sort_keys=True,
        )
    )


def _exit_code_for(outcome: RunOutcome) -> int:
    if outcome.state is AssessmentState.SUCCEEDED:
        return 1 if outcome.findings else 0
    if outcome.state is AssessmentState.PARTIAL:
        return 1
    return 4  # failed or cancelled


@app.command()
def run(
    path: Path = typer.Argument(..., help="Path to the assessment plan JSON file."),
    storage: Path = typer.Option(..., "--storage", help="Directory for the Athena database."),
    report: bool = typer.Option(
        False, "--report", help="Write a findings report into the storage directory."
    ),
) -> None:
    """Execute an assessment plan end to end and persist its results."""
    try:
        plan = load_plan_file(path)
    except PlanValidationError as exc:
        typer.echo(f"athena: invalid plan: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    repository = _open_repository(storage)
    try:
        coordinator = _build_coordinator(plan, repository)
        try:
            outcome = coordinator.run(plan)
        except UnknownAdapterError as exc:
            typer.echo(f"athena: {exc}", err=True)
            raise typer.Exit(code=2) from exc

        typer.echo(
            json.dumps(
                {
                    "assessment_id": outcome.assessment_id,
                    "state": outcome.state.value,
                    "findings": len(outcome.findings),
                },
                indent=2,
                sort_keys=True,
            )
        )
        if report:
            _write_report(plan, outcome, storage)
    finally:
        repository.close()
    raise typer.Exit(code=_exit_code_for(outcome))


def _build_coordinator(
    plan: AssessmentPlan, repository: SqliteAssessmentRepository
) -> Coordinator:
    def validate_redirect(url: str) -> None:
        # urllib invokes this before every redirect hop is followed. Re-run both
        # the engagement-scope and DNS-aware SSRF checks for the new location.
        ensure_web_target_allowed("url", url, plan.scope.allowed_domains)

    http = UrllibHttpClient.from_config(redirect_validator=validate_redirect)
    return Coordinator(
        repository=repository,
        audit=SqliteAuditSink(repository),
        clock=SystemClock(),
        ids=CoreIdProvider(),
        resolver=lambda names: resolve_adapters(names, http),
    )


def _write_report(plan: AssessmentPlan, outcome: RunOutcome, storage: Path) -> None:
    renderer = VulcanReportRenderer(plan.engagement_id)
    for fmt in plan.output.report_formats:
        content = renderer.render(outcome.findings, fmt)
        suffix = "md" if fmt == "markdown" else "json"
        target = storage / f"{outcome.assessment_id}.report.{suffix}"
        target.write_text(content, encoding="utf-8")
        typer.echo(f"athena: wrote {fmt} report to {target}", err=True)


@app.command()
def status(
    assessment_id: str = typer.Argument(..., help="Assessment ID to inspect."),
    storage: Path = typer.Option(..., "--storage", help="Directory for the Athena database."),
) -> None:
    """Print the persisted state of an assessment and its jobs."""
    repository = _open_repository(storage)
    try:
        assessment = repository.load_assessment(assessment_id)
        if assessment is None:
            typer.echo(f"athena: assessment not found: {assessment_id}", err=True)
            raise typer.Exit(code=2)
        payload = {
            "assessment_id": assessment.assessment_id,
            "plan_id": assessment.plan_id,
            "state": assessment.state.value,
            "jobs": [
                {
                    "job_id": job.job_id,
                    "adapter": job.adapter,
                    "target": job.target_value,
                    "state": job.state.value,
                    "error_code": job.error_code,
                }
                for job in assessment.jobs
            ],
        }
    finally:
        repository.close()
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command()
def cancel(
    assessment_id: str = typer.Argument(..., help="Assessment ID to cancel."),
    storage: Path = typer.Option(..., "--storage", help="Directory for the Athena database."),
) -> None:
    """Cancel a persisted, non-terminal assessment and its open jobs."""
    repository = _open_repository(storage)
    try:
        coordinator = Coordinator(
            repository=repository,
            audit=SqliteAuditSink(repository),
            clock=SystemClock(),
            ids=CoreIdProvider(),
            resolver=lambda names: {},
        )
        try:
            state = coordinator.cancel(assessment_id)
        except LookupError as exc:
            typer.echo(f"athena: {exc}", err=True)
            raise typer.Exit(code=2) from exc
    finally:
        repository.close()
    typer.echo(json.dumps({"assessment_id": assessment_id, "state": state.value}, sort_keys=True))


@app.command()
def recover(
    storage: Path = typer.Option(..., "--storage", help="Directory for the Athena database."),
) -> None:
    """Settle assessments left running after a crash (interrupted jobs fail closed)."""
    repository = _open_repository(storage)
    try:
        coordinator = Coordinator(
            repository=repository,
            audit=SqliteAuditSink(repository),
            clock=SystemClock(),
            ids=CoreIdProvider(),
            resolver=lambda names: {},
        )
        settled = coordinator.recover()
    finally:
        repository.close()
    typer.echo(json.dumps({"recovered": settled}, sort_keys=True))


@app.command()
def adapters() -> None:
    """List the assessment adapters available in the closed registry."""
    typer.echo(json.dumps({"adapters": list(available_adapters())}, sort_keys=True))
