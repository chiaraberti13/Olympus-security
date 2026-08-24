#!/usr/bin/env python3
"""
Configurazione centrale per Vulnerability Assessment Platform.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
import os
from pathlib import Path
import secrets
from typing import Dict, List, Optional

from dotenv import load_dotenv


load_dotenv()


def _split_env_list(value: str) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _split_env_roles(value: str) -> List[str]:
    return [item.lower() for item in _split_env_list(value)]


def _parse_iso_date(value: str) -> Optional[date]:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError:
        return None


@dataclass(frozen=True)
class Settings:
    app_name: str = "Vulnerability Assessment Platform"
    app_env: str = os.getenv("VAP_ENV", "development")
    host: str = os.getenv("VAP_HOST", "0.0.0.0")
    port: int = int(os.getenv("VAP_PORT", "8000"))
    database_url: str = os.getenv("VAP_DATABASE_URL", "sqlite:///./vap.db")
    sqlcipher_key: str = os.getenv("VAP_SQLCIPHER_KEY", "")
    reports_dir: Path = Path(os.getenv("VAP_REPORTS_DIR", "reports"))
    scan_timeout_seconds: int = int(os.getenv("VAP_SCAN_TIMEOUT", "300"))
    enable_live_scans: bool = os.getenv("VAP_ENABLE_LIVE_SCANS", "false").lower() == "true"
    max_findings: int = int(os.getenv("VAP_MAX_FINDINGS", "200"))
    max_concurrent_scanners: int = int(os.getenv("VAP_MAX_CONCURRENT_SCANNERS", "5"))
    api_key: str = os.getenv("VAP_API_KEY", "")
    api_key_hash: str = os.getenv("VAP_API_KEY_HASH", "")
    api_key_rotation_max_days: int = int(os.getenv("VAP_API_KEY_ROTATION_MAX_DAYS", "90"))
    api_key_last_rotated_at: str = os.getenv("VAP_API_KEY_LAST_ROTATED_AT", "")
    require_https: bool = os.getenv("VAP_REQUIRE_HTTPS", "false").lower() == "true"
    csrf_secret: str = os.getenv("VAP_CSRF_SECRET", "") or secrets.token_urlsafe(32)
    csrf_rotation_max_days: int = int(os.getenv("VAP_CSRF_ROTATION_MAX_DAYS", "180"))
    csrf_last_rotated_at: str = os.getenv("VAP_CSRF_LAST_ROTATED_AT", "")
    csrf_cookie_name: str = os.getenv("VAP_CSRF_COOKIE", "vap_csrf")
    csrf_token_ttl_seconds: int = int(os.getenv("VAP_CSRF_TTL", "3600"))
    jwt_secret: str = os.getenv("VAP_JWT_SECRET", "")
    jwt_rotation_max_days: int = int(os.getenv("VAP_JWT_ROTATION_MAX_DAYS", "90"))
    jwt_last_rotated_at: str = os.getenv("VAP_JWT_LAST_ROTATED_AT", "")
    jwt_algorithm: str = os.getenv("VAP_JWT_ALGORITHM", "HS256")
    jwt_issuer: str = os.getenv("VAP_JWT_ISSUER", "vap")
    jwt_audience: str = os.getenv("VAP_JWT_AUDIENCE", "vap-users")
    jwt_exp_minutes: int = int(os.getenv("VAP_JWT_EXP_MINUTES", "60"))
    jwt_required: bool = os.getenv("VAP_JWT_REQUIRED", "false").lower() == "true"
    jwt_demo_user: str = os.getenv("VAP_JWT_DEMO_USER", "")
    jwt_demo_password: str = os.getenv("VAP_JWT_DEMO_PASSWORD", "")
    jwt_demo_role: str = os.getenv("VAP_JWT_DEMO_ROLE", "admin").lower()
    rbac_enabled: bool = os.getenv("VAP_RBAC_ENABLED", "true").lower() == "true"
    rbac_viewer_roles: List[str] = field(
        default_factory=lambda: _split_env_roles(os.getenv("VAP_RBAC_VIEWER_ROLES", "viewer,operator,admin"))
    )
    rbac_operator_roles: List[str] = field(
        default_factory=lambda: _split_env_roles(os.getenv("VAP_RBAC_OPERATOR_ROLES", "operator,admin"))
    )
    rbac_admin_roles: List[str] = field(
        default_factory=lambda: _split_env_roles(os.getenv("VAP_RBAC_ADMIN_ROLES", "admin"))
    )
    rbac_capability_create_config_roles: List[str] = field(
        default_factory=lambda: _split_env_roles(
            os.getenv("VAP_RBAC_CAPABILITY_CREATE_CONFIG_ROLES", "operator,admin")
        )
    )
    rbac_capability_run_high_risk_scan_roles: List[str] = field(
        default_factory=lambda: _split_env_roles(
            os.getenv("VAP_RBAC_CAPABILITY_RUN_HIGH_RISK_SCAN_ROLES", "admin")
        )
    )
    rbac_capability_export_sensitive_report_roles: List[str] = field(
        default_factory=lambda: _split_env_roles(
            os.getenv("VAP_RBAC_CAPABILITY_EXPORT_SENSITIVE_REPORT_ROLES", "admin")
        )
    )
    rbac_capability_override_policy_roles: List[str] = field(
        default_factory=lambda: _split_env_roles(
            os.getenv("VAP_RBAC_CAPABILITY_OVERRIDE_POLICY_ROLES", "admin")
        )
    )
    trusted_proxy_ip: str = os.getenv("VAP_TRUSTED_PROXY_IP", "")
    cors_allowed_origins: List[str] = field(
        default_factory=lambda: _split_env_list(os.getenv("VAP_CORS_ALLOWED_ORIGINS", ""))
    )
    cors_allowed_methods: List[str] = field(
        default_factory=lambda: _split_env_list(
            os.getenv("VAP_CORS_ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
        )
    )
    cors_allowed_headers: List[str] = field(
        default_factory=lambda: _split_env_list(
            os.getenv("VAP_CORS_ALLOWED_HEADERS", "Authorization,Content-Type,X-API-Key")
        )
    )
    cors_allow_credentials: bool = os.getenv("VAP_CORS_ALLOW_CREDENTIALS", "false").lower() == "true"
    target_allowlist: List[str] = field(
        default_factory=lambda: _split_env_list(os.getenv("VAP_TARGET_ALLOWLIST", ""))
    )
    rate_limit_default: str = os.getenv("VAP_RATE_LIMIT_DEFAULT", "120/minute")
    rate_limit_create_scan: str = os.getenv("VAP_RATE_LIMIT_CREATE_SCAN", "10/minute")
    rate_limit_auth: str = os.getenv("VAP_RATE_LIMIT_AUTH", "15/minute")
    rate_limit_read: str = os.getenv("VAP_RATE_LIMIT_READ", "120/minute")
    hsts_max_age: int = int(os.getenv("VAP_HSTS_MAX_AGE", "31536000"))
    csp_policy: str = os.getenv(
        "VAP_CSP_POLICY",
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; frame-src 'none'; "
        "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; "
        "manifest-src 'self'; block-all-mixed-content; upgrade-insecure-requests",
    )
    permissions_policy: str = os.getenv(
        "VAP_PERMISSIONS_POLICY",
        "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), "
        "display-capture=(), fullscreen=(self), geolocation=(), gyroscope=(), microphone=(), payment=(), "
        "publickey-credentials-get=(), usb=(), web-share=()",
    )
    security_headers_enabled: bool = os.getenv("VAP_SECURITY_HEADERS", "true").lower() == "true"
    audit_logging_enabled: bool = os.getenv("VAP_AUDIT_LOGGING", "true").lower() == "true"
    privacy_policy_version: str = os.getenv("VAP_PRIVACY_POLICY_VERSION", "2024-01")
    terms_of_service_version: str = os.getenv("VAP_TERMS_VERSION", "2024-01")
    consent_retention_days: int = int(os.getenv("VAP_CONSENT_RETENTION_DAYS", "365"))
    audit_retention_days: int = int(os.getenv("VAP_AUDIT_RETENTION_DAYS", "365"))
    tls_certfile: str = os.getenv("VAP_TLS_CERTFILE", "")
    tls_keyfile: str = os.getenv("VAP_TLS_KEYFILE", "")
    tls_ca_certs: str = os.getenv("VAP_TLS_CA_CERTS", "")
    nuclei_rate_limit: int = int(os.getenv("VAP_NUCLEI_RATE_LIMIT", "150"))
    nuclei_timeout_seconds: int = int(os.getenv("VAP_NUCLEI_TIMEOUT", "10"))
    nuclei_severities: str = os.getenv(
        "VAP_NUCLEI_SEVERITIES", "critical,high,medium,low,info"
    )
    nuclei_templates: str = os.getenv("VAP_NUCLEI_TEMPLATES", "")
    nuclei_update_templates: bool = (
        os.getenv("VAP_NUCLEI_UPDATE_TEMPLATES", "true").lower() == "true"
    )
    nuclei_additional_args: str = os.getenv("VAP_NUCLEI_ADDITIONAL_ARGS", "")
    nmap_profile: str = os.getenv("VAP_NMAP_PROFILE", "quick").lower()
    nmap_additional_args: str = os.getenv("VAP_NMAP_ADDITIONAL_ARGS", "")
    securitytrails_api_key: str = os.getenv("VAP_SECURITYTRAILS_API_KEY", "")
    virustotal_api_key: str = os.getenv("VAP_VIRUSTOTAL_API_KEY", "")
    shodan_api_key: str = os.getenv("VAP_SHODAN_API_KEY", "")
    subfinder_sources: str = os.getenv("VAP_SUBFINDER_SOURCES", "")
    subfinder_resolve_limit: int = int(os.getenv("VAP_SUBFINDER_RESOLVE_LIMIT", "200"))
    dirsearch_path: str = os.getenv("VAP_DIRSEARCH_PATH", "dirsearch")
    dirsearch_wordlist: str = os.getenv("VAP_DIRSEARCH_WORDLIST", "")
    dirsearch_extensions: str = os.getenv(
        "VAP_DIRSEARCH_EXTENSIONS", "php,asp,aspx,js,html,zip,tar.gz,bak,old,backup"
    )
    dirsearch_threads: int = int(os.getenv("VAP_DIRSEARCH_THREADS", "20"))
    sqlmap_path: str = os.getenv("VAP_SQLMAP_PATH", "sqlmap")
    sqlmap_level: int = int(os.getenv("VAP_SQLMAP_LEVEL", "2"))
    sqlmap_risk: int = int(os.getenv("VAP_SQLMAP_RISK", "1"))
    sqlmap_crawl_depth: int = int(os.getenv("VAP_SQLMAP_CRAWL_DEPTH", "1"))
    sqlmap_forms: bool = os.getenv("VAP_SQLMAP_FORMS", "true").lower() == "true"
    sqlmap_additional_args: str = os.getenv("VAP_SQLMAP_ADDITIONAL_ARGS", "")
    xsstrike_path: str = os.getenv("VAP_XSSTRIKE_PATH", "xsstrike")
    xsstrike_crawl: bool = os.getenv("VAP_XSSTRIKE_CRAWL", "true").lower() == "true"
    xsstrike_additional_args: str = os.getenv("VAP_XSSTRIKE_ADDITIONAL_ARGS", "")
    zap_api_base_url: str = os.getenv("VAP_ZAP_API_BASE_URL", "")
    zap_api_key: str = os.getenv("VAP_ZAP_API_KEY", "")
    zap_max_alerts: int = int(os.getenv("VAP_ZAP_MAX_ALERTS", "200"))
    zap_timeout_seconds: int = int(os.getenv("VAP_ZAP_TIMEOUT", "20"))
    burp_api_base_url: str = os.getenv("VAP_BURP_API_BASE_URL", "")
    burp_api_key: str = os.getenv("VAP_BURP_API_KEY", "")
    burp_api_scan_endpoint: str = os.getenv("VAP_BURP_API_SCAN_ENDPOINT", "/v0.1/scan")
    burp_api_issues_endpoint: str = os.getenv(
        "VAP_BURP_API_ISSUES_ENDPOINT", "/v0.1/scan/{scan_id}/issues"
    )
    burp_timeout_seconds: int = int(os.getenv("VAP_BURP_TIMEOUT", "20"))
    wapiti_path: str = os.getenv("VAP_WAPITI_PATH", "wapiti")
    commix_path: str = os.getenv("VAP_COMMIX_PATH", "commix")
    commix_additional_args: str = os.getenv("VAP_COMMIX_ADDITIONAL_ARGS", "")
    acunetix_api_base_url: str = os.getenv("VAP_ACUNETIX_API_BASE_URL", "")
    acunetix_api_key: str = os.getenv("VAP_ACUNETIX_API_KEY", "")
    acunetix_vulnerabilities_endpoint: str = os.getenv(
        "VAP_ACUNETIX_VULNERABILITIES_ENDPOINT", "/api/v1/vulnerabilities"
    )
    acunetix_timeout_seconds: int = int(os.getenv("VAP_ACUNETIX_TIMEOUT", "20"))
    nessus_api_base_url: str = os.getenv("VAP_NESSUS_API_BASE_URL", "")
    nessus_api_key: str = os.getenv("VAP_NESSUS_API_KEY", "")
    nessus_vulnerabilities_endpoint: str = os.getenv(
        "VAP_NESSUS_VULNERABILITIES_ENDPOINT", "/vulnerabilities"
    )
    nessus_timeout_seconds: int = int(os.getenv("VAP_NESSUS_TIMEOUT", "20"))
    # OpenVAS / Greenbone (GVM) — adapter opzionale verso un'istanza esistente.
    openvas_api_base_url: str = os.getenv("VAP_OPENVAS_API_BASE_URL", "")
    openvas_api_key: str = os.getenv("VAP_OPENVAS_API_KEY", "")
    openvas_vulnerabilities_endpoint: str = os.getenv(
        "VAP_OPENVAS_VULNERABILITIES_ENDPOINT", "/gmp/results"
    )
    openvas_timeout_seconds: int = int(os.getenv("VAP_OPENVAS_TIMEOUT", "30"))
    wpscan_api_token: str = os.getenv("VAP_WPSCAN_API_TOKEN", "")
    wpscan_enumerate: str = os.getenv(
        "VAP_WPSCAN_ENUMERATE", "plugins,themes,users,timthumbs,config_backups,db_exports"
    )
    nvd_api_base_url: str = os.getenv("VAP_NVD_API_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    nvd_api_key: str = os.getenv("VAP_NVD_API_KEY", "")
    nvd_timeout_seconds: int = int(os.getenv("VAP_NVD_TIMEOUT", "10"))
    nvd_max_cves: int = int(os.getenv("VAP_NVD_MAX_CVES", "20"))
    exploitdb_searchsploit_path: str = os.getenv("VAP_EXPLOITDB_SEARCHSPLOIT_PATH", "searchsploit")
    exploitdb_timeout_seconds: int = int(os.getenv("VAP_EXPLOITDB_TIMEOUT", "10"))
    exploitdb_max_cves: int = int(os.getenv("VAP_EXPLOITDB_MAX_CVES", "20"))
    # ── Threat intelligence feeds (fonti ufficiali, aggiornate all'avvio) ─────
    # Cache locale dei feed (CVE/CVSS NVD, CISA KEV, EPSS) interrogabile offline.
    feeds_dir: Path = Path(os.getenv("VAP_FEEDS_DIR", "feeds"))
    # Abilita/disabilita globalmente l'aggiornamento dei feed da fonti ufficiali.
    feed_update_enabled: bool = os.getenv("VAP_FEED_UPDATE_ENABLED", "true").lower() == "true"
    # Aggiorna i feed all'avvio dell'applicazione (in background, non bloccante).
    feed_update_on_startup: bool = os.getenv("VAP_FEED_UPDATE_ON_STARTUP", "true").lower() == "true"
    # Intervallo dell'aggiornamento periodico in background.
    feed_update_interval_hours: int = int(os.getenv("VAP_FEED_UPDATE_INTERVAL_HOURS", "12"))
    # Guardia anti-stale: intervallo minimo tra due refresh (evita download a ogni reload).
    feed_min_refresh_interval_minutes: int = int(os.getenv("VAP_FEED_MIN_REFRESH_MINUTES", "360"))
    # Timeout per ogni operazione di download/aggiornamento feed.
    feed_update_timeout_seconds: int = int(os.getenv("VAP_FEED_UPDATE_TIMEOUT", "60"))
    # Fonti da aggiornare (CSV). Vuoto = tutte: nvd,cisa_kev,epss,nuclei_templates,exploitdb.
    feed_sources: str = os.getenv("VAP_FEED_SOURCES", "")
    # Usa la cache locale dei feed nell'enrichment (KEV/NVD offline, più veloce).
    feed_cache_enabled: bool = os.getenv("VAP_FEED_CACHE_ENABLED", "true").lower() == "true"
    # Finestra (giorni) e dimensione pagina per il corpus NVD recente.
    nvd_recent_window_days: int = int(os.getenv("VAP_NVD_RECENT_WINDOW_DAYS", "7"))
    nvd_feed_max_results: int = int(os.getenv("VAP_NVD_FEED_MAX_RESULTS", "2000"))
    cisa_kev_feed_url: str = os.getenv(
        "VAP_CISA_KEV_FEED_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    epss_feed_url: str = os.getenv("VAP_EPSS_FEED_URL", "https://api.first.org/data/v1/epss")
    false_positive_medium_threshold: float = float(os.getenv("VAP_FP_MEDIUM_THRESHOLD", "0.4"))
    false_positive_high_threshold: float = float(os.getenv("VAP_FP_HIGH_THRESHOLD", "0.7"))
    celery_broker_url: str = os.getenv("VAP_CELERY_BROKER_URL", "redis://localhost:6379/0")
    celery_result_backend: str = os.getenv("VAP_CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
    celery_default_queue: str = os.getenv("VAP_CELERY_DEFAULT_QUEUE", "scans")
    celery_worker_concurrency: int = int(os.getenv("VAP_CELERY_WORKER_CONCURRENCY", "4"))
    celery_task_time_limit: int = int(os.getenv("VAP_CELERY_TASK_TIME_LIMIT", "900"))
    celery_task_soft_time_limit: int = int(os.getenv("VAP_CELERY_TASK_SOFT_TIME_LIMIT", "840"))
    celery_result_expires_seconds: int = int(os.getenv("VAP_CELERY_RESULT_EXPIRES", "3600"))
    api_cache_enabled: bool = os.getenv("VAP_API_CACHE_ENABLED", "true").lower() == "true"
    api_cache_redis_url: str = os.getenv("VAP_API_CACHE_REDIS_URL", "redis://localhost:6379/2")
    api_cache_ttl_seconds: int = int(os.getenv("VAP_API_CACHE_TTL", "30"))
    api_cache_prefix: str = os.getenv("VAP_API_CACHE_PREFIX", "vap:api")
    scan_retention_days: int = int(os.getenv("VAP_SCAN_RETENTION_DAYS", "30"))
    scan_archive_after_days: int = int(os.getenv("VAP_SCAN_ARCHIVE_AFTER_DAYS", "7"))
    scheduled_scans: str = os.getenv("VAP_SCHEDULED_SCANS", "[]")
    websocket_poll_seconds: float = float(os.getenv("VAP_WEBSOCKET_POLL_SECONDS", "2.0"))
    scan_kill_switch_enabled: bool = os.getenv("VAP_SCAN_KILL_SWITCH", "false").lower() == "true"
    scan_guardrails_max_duration_seconds: int = int(os.getenv("VAP_SCAN_GUARDRAILS_MAX_DURATION", "900"))
    scan_guardrails_max_requests_per_minute: int = int(os.getenv("VAP_SCAN_GUARDRAILS_MAX_RPM", "300"))
    scan_guardrails_max_concurrency: int = int(os.getenv("VAP_SCAN_GUARDRAILS_MAX_CONCURRENCY", "8"))
    scan_guardrails_max_tool_timeout_seconds: int = int(os.getenv("VAP_SCAN_GUARDRAILS_MAX_TOOL_TIMEOUT", "120"))
    scan_guardrails_safe_mode_max_depth: int = int(os.getenv("VAP_SCAN_GUARDRAILS_SAFE_MAX_DEPTH", "2"))
    scan_guardrails_safe_mode_max_payloads: int = int(os.getenv("VAP_SCAN_GUARDRAILS_SAFE_MAX_PAYLOADS", "80"))
    scan_guardrails_auto_abort_error_threshold: int = int(os.getenv("VAP_SCAN_GUARDRAILS_AUTO_ABORT_ERRORS", "3"))
    scan_runtime_sla_seconds: int = int(os.getenv("VAP_SCAN_RUNTIME_SLA_SECONDS", "900"))
    report_render_sla_seconds: int = int(os.getenv("VAP_REPORT_RENDER_SLA_SECONDS", "20"))
    ui_guided_scan_explorer_enabled: bool = os.getenv("VAP_UI_GUIDED_SCAN_EXPLORER_ENABLED", "true").lower() == "true"
    # ── Telemetria centralizzata ──────────────────────────────────────────────
    # Prometheus remote-write: esporta metriche a Prometheus/Thanos/Mimir.
    # Lasciare vuoto per disabilitare l'export (il /metrics locale è sempre attivo).
    metrics_remote_write_url: str = os.getenv("VAP_METRICS_REMOTE_WRITE_URL", "")
    metrics_remote_write_bearer: str = os.getenv("VAP_METRICS_REMOTE_WRITE_BEARER", "")
    metrics_push_interval_seconds: int = int(os.getenv("VAP_METRICS_PUSH_INTERVAL", "60"))
    # Pushgateway Prometheus (alternativa a remote-write per ambienti senza scraping)
    metrics_pushgateway_url: str = os.getenv("VAP_METRICS_PUSHGATEWAY_URL", "")
    metrics_pushgateway_job: str = os.getenv("VAP_METRICS_PUSHGATEWAY_JOB", "vap")
    # DataDog: esporta metriche via DogStatsD o HTTP API
    datadog_api_key: str = os.getenv("VAP_DATADOG_API_KEY", "")
    datadog_site: str = os.getenv("VAP_DATADOG_SITE", "datadoghq.eu")
    datadog_service: str = os.getenv("VAP_DATADOG_SERVICE", "vap")
    datadog_env: str = os.getenv("VAP_DATADOG_ENV", os.getenv("VAP_ENV", "development"))
    # Alerting: soglie per notifiche su spike di errori e latenza elevata
    alert_error_rate_threshold: float = float(os.getenv("VAP_ALERT_ERROR_RATE_THRESHOLD", "0.05"))
    alert_latency_p99_threshold_seconds: float = float(os.getenv("VAP_ALERT_LATENCY_P99_THRESHOLD", "2.0"))
    alertmanager_url: str = os.getenv("VAP_ALERTMANAGER_URL", "")
    alert_webhook_url: str = os.getenv("VAP_ALERT_WEBHOOK_URL", "")


settings = Settings()
settings.reports_dir.mkdir(parents=True, exist_ok=True)


def build_startup_security_checklist() -> List[Dict[str, str]]:
    """Return startup security checks with severity for production deployments."""
    checks: List[Dict[str, str]] = []
    if settings.app_env != "production":
        return checks

    if not settings.csrf_secret:
        checks.append(
            {
                "severity": "high",
                "code": "csrf_secret_missing",
                "message": (
                    "VAP_CSRF_SECRET non impostato: verrà generata una chiave random a ogni riavvio, "
                    "invalidando le sessioni attive."
                ),
                "remediation": "Impostare VAP_CSRF_SECRET in modo stabile tramite secret manager.",
            }
        )
    if not settings.jwt_secret:
        checks.append(
            {
                "severity": "critical",
                "code": "jwt_secret_missing",
                "message": (
                    "VAP_JWT_SECRET non impostato: autenticazione JWT non affidabile o non funzionante."
                ),
                "remediation": "Impostare VAP_JWT_SECRET con valore robusto (es. openssl rand -hex 32).",
            }
        )
    if not settings.api_key and not settings.api_key_hash:
        checks.append(
            {
                "severity": "high",
                "code": "api_key_missing",
                "message": "Nessuna API key configurata: endpoint API esposti senza autenticazione by-key.",
                "remediation": "Configurare VAP_API_KEY_HASH (preferibile) o VAP_API_KEY.",
            }
        )
    if not settings.require_https:
        checks.append(
            {
                "severity": "high",
                "code": "https_not_enforced",
                "message": "VAP_REQUIRE_HTTPS=false: traffico non forzato su HTTPS.",
                "remediation": "Impostare VAP_REQUIRE_HTTPS=true in produzione.",
            }
        )
    if settings.host == "0.0.0.0":
        checks.append(
            {
                "severity": "medium",
                "code": "host_exposed",
                "message": "VAP_HOST=0.0.0.0: servizio in ascolto su tutte le interfacce di rete.",
                "remediation": "Limitare VAP_HOST a interfacce autorizzate quando possibile.",
            }
        )
    if not settings.rbac_enabled:
        checks.append(
            {
                "severity": "high",
                "code": "rbac_disabled",
                "message": "VAP_RBAC_ENABLED=false: controllo ruolo disattivato su endpoint sensibili.",
                "remediation": "Impostare VAP_RBAC_ENABLED=true in produzione.",
            }
        )
    if not settings.target_allowlist:
        checks.append(
            {
                "severity": "medium",
                "code": "target_allowlist_missing",
                "message": (
                    "VAP_TARGET_ALLOWLIST vuota: possibile abuso scansioni verso target non autorizzati."
                ),
                "remediation": (
                    "Definire VAP_TARGET_ALLOWLIST con domini/IP consentiti per deployment production."
                ),
            }
        )

    today = date.today()

    jwt_last_rotated = _parse_iso_date(settings.jwt_last_rotated_at)
    if settings.jwt_secret and not jwt_last_rotated:
        checks.append(
            {
                "severity": "medium",
                "code": "jwt_rotation_date_missing",
                "message": "Manca VAP_JWT_LAST_ROTATED_AT: impossibile verificare la rotazione del secret JWT.",
                "remediation": (
                    "Impostare VAP_JWT_LAST_ROTATED_AT (YYYY-MM-DD) e ruotare VAP_JWT_SECRET "
                    f"al massimo ogni {settings.jwt_rotation_max_days} giorni."
                ),
            }
        )
    elif jwt_last_rotated and (today - jwt_last_rotated).days > settings.jwt_rotation_max_days:
        checks.append(
            {
                "severity": "high",
                "code": "jwt_rotation_overdue",
                "message": (
                    "VAP_JWT_SECRET oltre finestra di rotazione consigliata: "
                    f"{(today - jwt_last_rotated).days} giorni."
                ),
                "remediation": (
                    "Ruotare VAP_JWT_SECRET e aggiornare VAP_JWT_LAST_ROTATED_AT tramite secret manager."
                ),
            }
        )

    csrf_last_rotated = _parse_iso_date(settings.csrf_last_rotated_at)
    if settings.csrf_secret and not csrf_last_rotated:
        checks.append(
            {
                "severity": "low",
                "code": "csrf_rotation_date_missing",
                "message": "Manca VAP_CSRF_LAST_ROTATED_AT: impossibile verificare la rotazione del secret CSRF.",
                "remediation": (
                    "Impostare VAP_CSRF_LAST_ROTATED_AT (YYYY-MM-DD) e pianificare la rotazione periodica "
                    f"entro {settings.csrf_rotation_max_days} giorni."
                ),
            }
        )
    elif csrf_last_rotated and (today - csrf_last_rotated).days > settings.csrf_rotation_max_days:
        checks.append(
            {
                "severity": "medium",
                "code": "csrf_rotation_overdue",
                "message": (
                    "VAP_CSRF_SECRET oltre finestra di rotazione consigliata: "
                    f"{(today - csrf_last_rotated).days} giorni."
                ),
                "remediation": (
                    "Ruotare VAP_CSRF_SECRET, aggiornare VAP_CSRF_LAST_ROTATED_AT e invalidare "
                    "le sessioni legacy."
                ),
            }
        )

    api_key_last_rotated = _parse_iso_date(settings.api_key_last_rotated_at)
    if (settings.api_key or settings.api_key_hash) and not api_key_last_rotated:
        checks.append(
            {
                "severity": "medium",
                "code": "api_key_rotation_date_missing",
                "message": "Manca VAP_API_KEY_LAST_ROTATED_AT: impossibile verificare la rotazione API key.",
                "remediation": (
                    "Impostare VAP_API_KEY_LAST_ROTATED_AT (YYYY-MM-DD) e ruotare la chiave "
                    f"entro {settings.api_key_rotation_max_days} giorni."
                ),
            }
        )
    elif api_key_last_rotated and (today - api_key_last_rotated).days > settings.api_key_rotation_max_days:
        checks.append(
            {
                "severity": "high",
                "code": "api_key_rotation_overdue",
                "message": (
                    "API key oltre finestra di rotazione consigliata: "
                    f"{(today - api_key_last_rotated).days} giorni."
                ),
                "remediation": "Ruotare VAP_API_KEY/VAP_API_KEY_HASH e aggiornare VAP_API_KEY_LAST_ROTATED_AT.",
            }
        )

    return checks


def _warn_production_security() -> None:
    """Log warnings for insecure settings when running in production."""
    import logging
    _log = logging.getLogger("vap.config")

    checks = build_startup_security_checklist()
    for check in checks:
        _log.warning(
            "[VAP PRODUCTION SECURITY][%s][%s] %s Remediation: %s",
            check["severity"].upper(),
            check["code"],
            check["message"],
            check["remediation"],
        )


_warn_production_security()
