#!/usr/bin/env python3
"""Recurring background jobs for maintenance and scheduled scans."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from config import settings
from database import AuditEvent, ConsentRecord, SessionLocal, Scan
from feed_updater import refresh_all_feeds
from tasks import orchestrate_scan


def _schedule_scans(scheduler: AsyncIOScheduler) -> None:
    try:
        scheduled_scans: List[Dict[str, Any]] = json.loads(settings.scheduled_scans)
    except json.JSONDecodeError:
        scheduled_scans = []

    for idx, scan_config in enumerate(scheduled_scans):
        target = str(scan_config.get("target", "")).strip()
        scan_type = str(scan_config.get("scan_type", "full")).strip().lower()
        cron_expr = str(scan_config.get("cron", "")).strip()
        if not target or not cron_expr:
            continue

        scheduler.add_job(
            enqueue_scheduled_scan,
            CronTrigger.from_crontab(cron_expr),
            args=[target, scan_type],
            id=f"scheduled_scan_{idx}_{scan_type}",
            replace_existing=True,
        )


def enqueue_scheduled_scan(target: str, scan_type: str) -> None:
    with SessionLocal() as db:
        scan = Scan(
            target=target,
            scan_type=scan_type,
            status="queued",
            progress=0,
            created_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        orchestrate_scan.delay(scan.id, scan.scan_type, scan.target)


def cleanup_old_reports() -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.scan_retention_days)
    audit_cutoff = datetime.now(timezone.utc) - timedelta(days=settings.audit_retention_days)
    consent_cutoff = datetime.now(timezone.utc) - timedelta(days=settings.consent_retention_days)
    with SessionLocal() as db:
        scans = (
            db.query(Scan)
            .filter(Scan.created_at < cutoff, Scan.deleted_at.is_(None))
            .all()
        )
        for scan in scans:
            if scan.report_path:
                try:
                    Path(scan.report_path).unlink(missing_ok=True)
                except OSError:
                    pass
            scan.status = "archived"
        db.query(AuditEvent).filter(AuditEvent.created_at < audit_cutoff).delete()
        db.query(ConsentRecord).filter(ConsentRecord.accepted_at < consent_cutoff).delete()
        db.commit()


def compress_old_reports() -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.scan_archive_after_days)
    archive_dir = settings.reports_dir / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)
    with SessionLocal() as db:
        scans = (
            db.query(Scan)
            .filter(
                Scan.created_at < cutoff,
                Scan.report_path.isnot(None),
                Scan.deleted_at.is_(None),
            )
            .all()
        )
        for scan in scans:
            report_path = Path(scan.report_path)
            if not report_path.exists():
                continue
            archive_path = archive_dir / f"scan_{scan.id}.zip"
            if archive_path.exists():
                continue
            try:
                import zipfile

                with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
                    archive.write(report_path, report_path.name)
            except OSError:
                continue
        db.commit()


def update_threat_intelligence_feeds() -> None:
    """Aggiorna i feed di vulnerabilità/scanner da fonti ufficiali.

    Delega al gestore unificato in :mod:`feed_updater`, che scarica CVE/CVSS da
    NVD, il catalogo CISA KEV, il modello EPSS e (se i tool sono installati) i
    template di Nuclei e il database Exploit-DB, scrivendo un manifest di stato.
    """
    try:
        refresh_all_feeds()
    except Exception:  # noqa: BLE001 - un job periodico non deve mai propagare eccezioni
        logging.getLogger("vap.feeds").exception("Aggiornamento feed periodico non riuscito.")


def start_background_jobs() -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()
    scheduler.add_job(cleanup_old_reports, "interval", hours=24, id="cleanup_reports", replace_existing=True)
    scheduler.add_job(compress_old_reports, "interval", hours=24, id="compress_reports", replace_existing=True)
    if settings.feed_update_enabled:
        scheduler.add_job(
            update_threat_intelligence_feeds,
            "interval",
            hours=max(1, settings.feed_update_interval_hours),
            id="update_threat_intel_feeds",
            replace_existing=True,
        )
    _schedule_scans(scheduler)
    scheduler.start()
    return scheduler
