#!/usr/bin/env python3
"""Celery tasks for asynchronous scans and maintenance."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Dict, List
from uuid import uuid4

from celery import chord
from sqlalchemy.orm.exc import ObjectDeletedError, StaleDataError

from celery_app import celery_app
from config import settings
from execution_guardrails import should_auto_abort_scan
from database import SessionLocal, Scan
from enrichment_engine import enrich_findings
from performance_budget import evaluate_performance_budget
from report_generator import generate_report
from scanner_engine import (
    ScanValidationError,
    _compute_scan_stats,
    detect_target_redirect,
    get_scanner_classes,
    run_single_scanner,
    serialize_findings,
)


_LOGGER = logging.getLogger("vap.tasks")


def _safe_commit(db, context: str) -> bool:
    """Commit scan updates, tolerating concurrent deletion of the scan row.

    Background scanner threads can still be running when a scan is canceled or
    deleted (e.g. via the DELETE API or test teardown). In that case the UPDATE
    matches no rows and SQLAlchemy raises StaleDataError. We roll back and stop
    quietly instead of crashing the worker thread with an unhandled exception.
    """
    try:
        db.commit()
        return True
    except (StaleDataError, ObjectDeletedError):
        db.rollback()
        _LOGGER.info("scan row removed during %s; skipping update", context)
        return False


def _append_log(scan: Scan, message: str, level: str = "info") -> None:
    payload = json.loads(scan.logs_json or "[]")
    payload.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
        }
    )
    scan.logs_json = json.dumps(payload, ensure_ascii=False)


def _append_notifications(scan: Scan, notifications: List[Dict[str, Any]]) -> None:
    payload = json.loads(scan.notifications_json or "[]")
    payload.extend(notifications)
    scan.notifications_json = json.dumps(payload, ensure_ascii=False)


def _scan_error_count(scan: Scan) -> int:
    logs = json.loads(scan.logs_json or "[]")
    return sum(1 for log in logs if "stato error" in str(log.get("message", "")).lower())


def _duration_seconds(start: datetime | None, end: datetime | None) -> float:
    if not start or not end:
        return 0.0
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    return max((end - start).total_seconds(), 0.0)


def _record_performance_budget(
    scan: Scan,
    *,
    report_render_seconds: float | None,
) -> None:
    evaluation = evaluate_performance_budget(
        scan_runtime_seconds=_duration_seconds(scan.created_at, scan.completed_at),
        report_render_seconds=report_render_seconds,
        scan_runtime_budget_seconds=settings.scan_runtime_sla_seconds,
        report_render_budget_seconds=settings.report_render_sla_seconds,
    )
    _append_log(
        scan,
        (
            "Performance budget — "
            f"runtime={evaluation['scan_runtime_seconds']}s "
            f"(SLA {settings.scan_runtime_sla_seconds}s), "
            f"report={evaluation['report_render_seconds']}s "
            f"(SLA {settings.report_render_sla_seconds}s)."
        ),
        "info",
    )
    for breach in evaluation["breaches"]:
        _append_log(
            scan,
            (
                "Performance budget superato: "
                f"{breach['dimension']} {breach['observed_seconds']}s "
                f"> {breach['budget_seconds']}s."
            ),
            "warning",
        )


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def run_scanner_task(self, scan_id: int, scanner_name: str, target: str) -> Dict[str, Any]:
    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.status == "canceled":
            return {"tool": scanner_name, "status": "canceled", "findings": []}

        _append_log(scan, f"Avvio scanner {scanner_name}.")
        db.commit()

    try:
        result = run_single_scanner(scanner_name, target)
    except ScanValidationError as exc:
        result = {"tool": scanner_name, "status": "error", "message": str(exc), "findings": []}

    critical_notifications = [
        {
            "title": finding.get("title", "Finding critico"),
            "severity": finding.get("severity", "critical"),
            "description": finding.get("description", ""),
        }
        for finding in result.get("findings", [])
        if str(finding.get("severity", "")).lower() in {"critical", "high"}
    ]

    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return result

        scan.completed_scanners = (scan.completed_scanners or 0) + 1
        total_scanners = max(1, scan.total_scanners or 1)
        scan.progress = min(100, int((scan.completed_scanners / total_scanners) * 100))
        _append_log(scan, f"Scanner {scanner_name} completato con stato {result.get('status')}.")
        if critical_notifications:
            _append_notifications(scan, critical_notifications)
            _append_log(scan, f"Notifiche critiche: {len(critical_notifications)}", "warning")

        error_count = _scan_error_count(scan)
        if should_auto_abort_scan(
            error_count,
            scan.completed_scanners or 0,
            total_scanners,
            settings.scan_guardrails_auto_abort_error_threshold,
        ):
            scan.status = "canceled"
            _append_log(
                scan,
                "Auto-abort attivato: pattern anomalo rilevato (tasso errori scanner elevato).",
                "warning",
            )

        db.commit()

    return result


@celery_app.task(bind=True)
def orchestrate_scan(self, scan_id: int, scan_type: str, target: str) -> str:
    scanner_classes = get_scanner_classes(scan_type)
    scanner_names = [scanner.__name__.replace("Scanner", "").lower() for scanner in scanner_classes]

    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return "scan_not_found"
        if settings.scan_kill_switch_enabled:
            scan.status = "canceled"
            _append_log(scan, "Scansione annullata: kill switch globale attivo.", "warning")
            db.commit()
            return "killed"
        scan.status = "running"
        scan.total_scanners = len(scanner_names)
        scan.completed_scanners = 0
        scan.progress = 0
        priority = scan.priority or 5
        _append_log(scan, "Scansione in esecuzione.")
        db.commit()

    tasks = []
    for scanner_name in scanner_names:
        task_id = str(uuid4())
        tasks.append(
            run_scanner_task.s(scan_id, scanner_name, target).set(task_id=task_id, priority=priority)
        )

    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.child_task_ids_json = json.dumps([task.options.get("task_id") for task in tasks])
            db.commit()

    callback = finalize_scan.s(scan_id=scan_id, target=target, scan_type=scan_type)
    chord(tasks)(callback)
    return "queued"


@celery_app.task(bind=True)
def finalize_scan(self, results: List[Dict[str, Any]], scan_id: int, target: str, scan_type: str) -> str:
    findings: List[Dict[str, Any]] = []
    for result in results:
        tool_name = result.get("tool", "")
        for finding in result.get("findings", []):
            if tool_name and not finding.get("tool"):
                finding = dict(finding)
                finding["tool"] = tool_name
            finding.setdefault("found_by", f"{tool_name.title()} – Active Testing" if tool_name else "Active Testing")
            findings.append(finding)
    findings = enrich_findings(findings)
    stats = _compute_scan_stats(results, findings, target=target)
    redirect_from = ""
    if scan_type.lower() != "nmap":
        redirect_from = detect_target_redirect(target).get("redirect_from", "")

    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return "scan_not_found"
        if scan.status == "canceled":
            _append_log(scan, "Scansione annullata. Nessun report generato.", "warning")
            db.commit()
            return "canceled"

        scan.completed_at = datetime.now(timezone.utc)
        scan.status = "completed"
        scan.progress = 100
        scan.findings_json = serialize_findings(findings)
        scan.tests_performed = stats["tests_performed"]
        scan.urls_spidered = stats["urls_spidered"]
        scan.injection_points = stats["injection_points"]
        scan.http_requests_total = stats["http_requests_total"]
        scan.avg_response_time_ms = stats["avg_response_time_ms"]
        scan.redirect_from = redirect_from or None

        report_render_seconds: float | None = None
        try:
            report_render_started_at = time.perf_counter()
            report_path = generate_report(
                scan.id, target, scan_type, findings,
                start_time=scan.created_at,
                end_time=scan.completed_at,
                redirect_from=scan.redirect_from,
                tests_performed=scan.tests_performed,
                scan_stats={
                    "urls_spidered": scan.urls_spidered,
                    "unique_injection_points": scan.injection_points,
                    "total_http_requests": scan.http_requests_total,
                    "average_response_time": scan.avg_response_time_ms,
                },
            )
            report_render_seconds = max(time.perf_counter() - report_render_started_at, 0.0)
        except Exception as exc:
            scan.status = "report_failed"
            scan.report_path = None
            _append_log(scan, f"Errore report PDF: {exc}", "error")
        else:
            scan.report_path = str(report_path)
            _append_log(scan, "Report PDF generato.")
        _record_performance_budget(scan, report_render_seconds=report_render_seconds)

        db.commit()
    return "completed"


def _run_single_scanner_sync(scan_id: int, scanner_name: str, target: str, total_scanners: int) -> Dict[str, Any]:
    """Run a single scanner synchronously and update DB progress (used by run_scan_in_process)."""
    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.status == "canceled":
            return {"tool": scanner_name, "status": "canceled", "findings": []}
        _append_log(scan, f"Avvio scanner {scanner_name}.")
        _safe_commit(db, f"scanner {scanner_name} start")

    try:
        result = run_single_scanner(scanner_name, target)
    except ScanValidationError as exc:
        result = {"tool": scanner_name, "status": "error", "message": str(exc), "findings": []}

    critical_notifications = [
        {
            "title": finding.get("title", "Finding critico"),
            "severity": finding.get("severity", "critical"),
            "description": finding.get("description", ""),
        }
        for finding in result.get("findings", [])
        if str(finding.get("severity", "")).lower() in {"critical", "high"}
    ]

    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.completed_scanners = (scan.completed_scanners or 0) + 1
            scan.progress = min(100, int((scan.completed_scanners / max(1, total_scanners)) * 100))
            _append_log(scan, f"Scanner {scanner_name} completato con stato {result.get('status')}.")
            if critical_notifications:
                _append_notifications(scan, critical_notifications)
                _append_log(scan, f"Notifiche critiche: {len(critical_notifications)}", "warning")
            _safe_commit(db, f"scanner {scanner_name} progress")

    return result


def run_scan_in_process(scan_id: int, scan_type: str, target: str) -> None:
    """Run a scan entirely in-process (fallback when Celery broker is unavailable).

    Replicates the orchestrate_scan → run_scanner_task(×N) → finalize_scan pipeline
    using a ThreadPoolExecutor instead of a Celery chord.
    """
    _log = logging.getLogger("vap.sync_runner")

    scanner_classes = get_scanner_classes(scan_type)
    scanner_names = [sc.__name__.replace("Scanner", "").lower() for sc in scanner_classes]
    total = len(scanner_names)

    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            _log.error("run_scan_in_process: scan %d not found", scan_id)
            return
        scan.status = "running"
        scan.total_scanners = total
        scan.completed_scanners = 0
        scan.progress = 0
        _append_log(scan, "Scansione in esecuzione (modalità diretta, senza broker Celery).")
        _safe_commit(db, "scan start")

    results: List[Dict[str, Any]] = []
    scanner_timeout = settings.celery_task_time_limit or 900
    with ThreadPoolExecutor(max_workers=max(1, total)) as pool:
        futures = {
            pool.submit(_run_single_scanner_sync, scan_id, name, target, total): name
            for name in scanner_names
        }
        try:
            for future in as_completed(futures, timeout=scanner_timeout * total):
                name = futures[future]
                try:
                    results.append(future.result(timeout=scanner_timeout))
                except TimeoutError:
                    _log.error("scanner %s timed out in sync run", name)
                    results.append({"tool": name, "status": "timeout", "message": "Scanner timed out", "findings": []})
                except Exception as exc:
                    _log.error("scanner %s failed in sync run: %s", name, exc)
                    results.append({"tool": name, "status": "error", "message": str(exc), "findings": []})
        except TimeoutError:
            for future, name in futures.items():
                if not future.done():
                    _log.error("scanner %s timed out (global pool timeout)", name)
                    results.append({"tool": name, "status": "timeout", "message": "Scanner timed out", "findings": []})

    findings: List[Dict[str, Any]] = []
    for r in results:
        findings.extend(r.get("findings", []))
    for finding in findings:
        tool_name = finding.get("tool", "")
        finding.setdefault("found_by", f"{tool_name.title()} – Active Testing" if tool_name else "Active Testing")
    findings = enrich_findings(findings)
    stats = _compute_scan_stats(results, findings, target=target)
    redirect_from = ""
    if scan_type.lower() != "nmap":
        redirect_from = detect_target_redirect(target).get("redirect_from", "")

    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        if scan.status == "canceled":
            _append_log(scan, "Scansione annullata. Nessun report generato.", "warning")
            _safe_commit(db, "scan cancel finalize")
            return
        scan.completed_at = datetime.now(timezone.utc)
        scan.status = "completed"
        scan.progress = 100
        scan.findings_json = serialize_findings(findings)
        scan.tests_performed = stats["tests_performed"]
        scan.urls_spidered = stats["urls_spidered"]
        scan.injection_points = stats["injection_points"]
        scan.http_requests_total = stats["http_requests_total"]
        scan.avg_response_time_ms = stats["avg_response_time_ms"]
        scan.redirect_from = redirect_from or None
        report_render_seconds: float | None = None
        try:
            report_render_started_at = time.perf_counter()
            report_path = generate_report(
                scan.id, target, scan_type, findings,
                start_time=scan.created_at,
                end_time=scan.completed_at,
                redirect_from=scan.redirect_from,
                tests_performed=scan.tests_performed,
                scan_stats={
                    "urls_spidered": scan.urls_spidered,
                    "unique_injection_points": scan.injection_points,
                    "total_http_requests": scan.http_requests_total,
                    "average_response_time": scan.avg_response_time_ms,
                },
            )
            report_render_seconds = max(time.perf_counter() - report_render_started_at, 0.0)
            scan.report_path = str(report_path)
            _append_log(scan, "Report PDF generato.")
        except Exception as exc:
            scan.status = "report_failed"
            scan.report_path = None
            _append_log(scan, f"Errore report PDF: {exc}", "error")
        _record_performance_budget(scan, report_render_seconds=report_render_seconds)
        _safe_commit(db, "scan completion")
    _log.info("run_scan_in_process: scan %d completed (sync)", scan_id)
