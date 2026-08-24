from __future__ import annotations

import importlib.util
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_init_db_bootstraps_schema_with_or_without_alembic(tmp_path):
    db_path = tmp_path / "migration_test.db"
    env = os.environ.copy()
    env.update(
        {
            "VAP_DATABASE_URL": f"sqlite:///{db_path}",
            "PYTHONPATH": str(REPO_ROOT),
        }
    )

    subprocess.run(
        [sys.executable, "-c", "from database import init_db; init_db()"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
    )

    with sqlite3.connect(db_path) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "scans" in tables
        assert "scan_configuration_presets" in tables

        scan_columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        assert "tests_performed" in scan_columns
        assert "redirect_from" in scan_columns
        assert "scan_configuration_json" in scan_columns
        assert "scan_configuration_version" in scan_columns
        assert "scan_configuration_checksum" in scan_columns

        if importlib.util.find_spec("alembic"):
            assert "alembic_version" in tables

        preset_columns = {row[1] for row in conn.execute("PRAGMA table_info(scan_configuration_presets)")}
        assert "lifecycle_state" in preset_columns
