"""Resilience tests for in-process background scan execution (tasks.py).

Regression guard for the StaleDataError that previously surfaced as an
unhandled thread exception ("UPDATE statement on table 'scans' expected to
update 1 row(s); 0 were matched") when a scan row was removed — via cancel,
the DELETE API, or test teardown — while a background scanner thread was still
committing progress updates.
"""
from database import Scan, SessionLocal
import tasks

from conftest import clear_persistent_state


def test_safe_commit_tolerates_concurrently_deleted_scan(seed_scan):
    clear_persistent_state(include_learning_artifacts=False)
    scan_id = seed_scan(status="running", progress=10).id

    # Session A loads the scan and stages an UPDATE, exactly like a worker thread
    # mutating progress before committing.
    session_a = SessionLocal()
    try:
        loaded = session_a.query(Scan).filter(Scan.id == scan_id).first()
        assert loaded is not None
        loaded.progress = 80  # pending UPDATE, not yet flushed

        # Meanwhile another session removes the row (cancel / DELETE / teardown).
        with SessionLocal() as session_b:
            session_b.query(Scan).filter(Scan.id == scan_id).delete()
            session_b.commit()

        # A raw db.commit() here would raise StaleDataError; _safe_commit must
        # swallow it, roll back, and report failure instead of crashing.
        assert tasks._safe_commit(session_a, "progress update") is False
    finally:
        session_a.close()


def test_safe_commit_persists_normal_update(seed_scan):
    clear_persistent_state(include_learning_artifacts=False)
    scan_id = seed_scan(status="running", progress=10).id

    with SessionLocal() as session:
        loaded = session.query(Scan).filter(Scan.id == scan_id).first()
        loaded.progress = 55
        assert tasks._safe_commit(session, "progress update") is True

    with SessionLocal() as verify:
        persisted = verify.query(Scan).filter(Scan.id == scan_id).first()
        assert persisted is not None
        assert persisted.progress == 55
