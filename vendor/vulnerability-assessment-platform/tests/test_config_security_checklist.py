from types import SimpleNamespace

import config


def test_build_startup_security_checklist_returns_empty_outside_production(monkeypatch):
    monkeypatch.setattr(config, "settings", SimpleNamespace(app_env="development"))
    assert config.build_startup_security_checklist() == []


def test_build_startup_security_checklist_returns_expected_findings(monkeypatch):
    monkeypatch.setattr(
        config,
        "settings",
        SimpleNamespace(
            app_env="production",
            csrf_secret="",
            jwt_secret="",
            api_key="",
            api_key_hash="",
            csrf_last_rotated_at="",
            csrf_rotation_max_days=180,
            jwt_last_rotated_at="",
            jwt_rotation_max_days=90,
            api_key_last_rotated_at="",
            api_key_rotation_max_days=90,
            require_https=False,
            host="0.0.0.0",
            rbac_enabled=False,
            target_allowlist=[],
        ),
    )

    checks = config.build_startup_security_checklist()
    codes = {check["code"] for check in checks}

    assert len(checks) == 7
    assert "jwt_secret_missing" in codes
    assert "csrf_secret_missing" in codes
    assert "api_key_missing" in codes
    assert "https_not_enforced" in codes
    assert "host_exposed" in codes
    assert "rbac_disabled" in codes
    assert "target_allowlist_missing" in codes


def test_build_startup_security_checklist_skips_passing_controls(monkeypatch):
    monkeypatch.setattr(
        config,
        "settings",
        SimpleNamespace(
            app_env="production",
            csrf_secret="csrf",
            csrf_last_rotated_at="2026-03-30",
            csrf_rotation_max_days=180,
            jwt_secret="jwt",
            jwt_last_rotated_at="2026-03-30",
            jwt_rotation_max_days=90,
            api_key_hash="sha256:test",
            api_key="",
            api_key_last_rotated_at="2026-03-30",
            api_key_rotation_max_days=90,
            require_https=True,
            host="127.0.0.1",
            rbac_enabled=True,
            target_allowlist=["example.com"],
        ),
    )

    assert config.build_startup_security_checklist() == []


def test_build_startup_security_checklist_reports_missing_rotation_dates(monkeypatch):
    monkeypatch.setattr(
        config,
        "settings",
        SimpleNamespace(
            app_env="production",
            csrf_secret="csrf",
            csrf_last_rotated_at="",
            csrf_rotation_max_days=180,
            jwt_secret="jwt",
            jwt_last_rotated_at="",
            jwt_rotation_max_days=90,
            api_key_hash="sha256:test",
            api_key="",
            api_key_last_rotated_at="",
            api_key_rotation_max_days=90,
            require_https=True,
            host="127.0.0.1",
            rbac_enabled=True,
            target_allowlist=["example.com"],
        ),
    )

    checks = config.build_startup_security_checklist()
    codes = {check["code"] for check in checks}
    assert "jwt_rotation_date_missing" in codes
    assert "csrf_rotation_date_missing" in codes
    assert "api_key_rotation_date_missing" in codes


def test_build_startup_security_checklist_reports_overdue_rotation(monkeypatch):
    monkeypatch.setattr(
        config,
        "settings",
        SimpleNamespace(
            app_env="production",
            csrf_secret="csrf",
            csrf_last_rotated_at="2025-01-01",
            csrf_rotation_max_days=180,
            jwt_secret="jwt",
            jwt_last_rotated_at="2025-01-01",
            jwt_rotation_max_days=90,
            api_key_hash="sha256:test",
            api_key="",
            api_key_last_rotated_at="2025-01-01",
            api_key_rotation_max_days=90,
            require_https=True,
            host="127.0.0.1",
            rbac_enabled=True,
            target_allowlist=["example.com"],
        ),
    )

    checks = config.build_startup_security_checklist()
    codes = {check["code"] for check in checks}
    assert "jwt_rotation_overdue" in codes
    assert "csrf_rotation_overdue" in codes
    assert "api_key_rotation_overdue" in codes
