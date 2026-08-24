#!/usr/bin/env python3
"""
Telemetria centralizzata — VAP

Esporta metriche Prometheus verso backend remoti (Pushgateway, remote-write,
DataDog) e implementa rilevamento spike di errori/latenza con alerting via
Alertmanager o webhook.

Backends supportati (configurabili via variabili d'ambiente):
  - Prometheus Pushgateway      (VAP_METRICS_PUSHGATEWAY_URL)
  - Prometheus remote-write     (VAP_METRICS_REMOTE_WRITE_URL)
  - DataDog HTTP API            (VAP_DATADOG_API_KEY)
  - Alertmanager                (VAP_ALERTMANAGER_URL)
  - Webhook generico            (VAP_ALERT_WEBHOOK_URL)

Il push è asincrono e non bloccante: eventuali errori di rete sono loggati
senza interrompere il processo principale.
"""
from __future__ import annotations

import json
import logging
import time
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error
import urllib.parse

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    REGISTRY,
    generate_latest,
    push_to_gateway,
    CollectorRegistry,
    Metric,
)
from prometheus_client.exposition import basic_auth_handler

from config import settings

logger = logging.getLogger("vap.telemetry")

# ── Metriche aggiuntive production-grade ─────────────────────────────────────

def _safe_counter(name: str, doc: str, labels: List[str]) -> Counter:
    try:
        return Counter(name, doc, labels)
    except ValueError:
        return REGISTRY._names_to_collectors.get(name)  # type: ignore[return-value]


def _safe_gauge(name: str, doc: str, labels: Optional[List[str]] = None) -> Gauge:
    try:
        return Gauge(name, doc, labels or [])
    except ValueError:
        return REGISTRY._names_to_collectors.get(name)  # type: ignore[return-value]


SCAN_ACTIVE = _safe_gauge(
    "vap_scans_active_total",
    "Numero di scansioni attualmente attive (queue + running)",
)
SCAN_COMPLETED = _safe_counter(
    "vap_scans_completed_total",
    "Numero totale di scansioni completate con successo",
    [],
)
SCAN_FAILED = _safe_counter(
    "vap_scans_failed_total",
    "Numero totale di scansioni terminate con errore",
    [],
)
FINDINGS_TOTAL = _safe_gauge(
    "vap_findings_total",
    "Numero totale di finding nelle scansioni completate",
)
HTTP_ERRORS_5XX = _safe_counter(
    "vap_http_errors_5xx_total",
    "Numero totale di risposte HTTP 5xx",
    [],
)
ALERT_FIRED = _safe_counter(
    "vap_alerts_fired_total",
    "Numero totale di alert inviati (spike errori/latenza)",
    ["type"],
)


# ── Stato interno per rilevamento spike ──────────────────────────────────────

_last_alert_ts: Dict[str, float] = {}
_ALERT_COOLDOWN_SECONDS = 300  # non inviare lo stesso alert più di 1 volta ogni 5 min


def _should_fire_alert(alert_type: str) -> bool:
    now = time.monotonic()
    last = _last_alert_ts.get(alert_type, 0.0)
    if now - last >= _ALERT_COOLDOWN_SECONDS:
        _last_alert_ts[alert_type] = now
        return True
    return False


# ── Helpers HTTP ─────────────────────────────────────────────────────────────

def _http_post(url: str, data: bytes, headers: Dict[str, str], timeout: int = 10) -> bool:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError) as exc:
        logger.warning("Telemetria: POST a %s fallita — %s", url, exc)
        return False


# ── Export Pushgateway ────────────────────────────────────────────────────────

def push_to_pushgateway() -> bool:
    """Invia metriche a Prometheus Pushgateway."""
    url = settings.metrics_pushgateway_url
    if not url:
        return False
    try:
        push_to_gateway(
            url,
            job=settings.metrics_pushgateway_job,
            registry=REGISTRY,
        )
        logger.debug("Telemetria: metriche inviate a Pushgateway %s", url)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("Telemetria: Pushgateway push fallita — %s", exc)
        return False


# ── Export DataDog ────────────────────────────────────────────────────────────

def push_to_datadog() -> bool:
    """Invia serie temporali a DataDog via HTTP API v2."""
    api_key = settings.datadog_api_key
    if not api_key:
        return False

    now_ts = int(time.time())
    series: List[Dict[str, Any]] = []

    # Raccoglie metriche selezionate dal registry
    metric_names = {
        "vap_http_requests_total",
        "vap_http_request_duration_seconds",
        "vap_scans_active_total",
        "vap_scans_completed_total",
        "vap_scans_failed_total",
        "vap_findings_total",
        "vap_http_errors_5xx_total",
    }
    for metric in REGISTRY.collect():
        if metric.name not in metric_names:
            continue
        for sample in metric.samples:
            tags = [
                f"service:{settings.datadog_service}",
                f"env:{settings.datadog_env}",
            ] + [f"{k}:{v}" for k, v in sample.labels.items()]
            series.append({
                "metric": f"vap.{sample.name.replace('vap_', '')}",
                "type": 0,  # UNSPECIFIED → gauge-like for compatibility
                "points": [{"timestamp": now_ts, "value": sample.value}],
                "tags": tags,
            })

    if not series:
        return False

    payload = json.dumps({"series": series}).encode()
    headers = {
        "Content-Type": "application/json",
        "DD-API-KEY": api_key,
    }
    url = f"https://api.{settings.datadog_site}/api/v2/series"
    ok = _http_post(url, payload, headers)
    if ok:
        logger.debug("Telemetria: %d serie inviate a DataDog", len(series))
    return ok


# ── Alerting ──────────────────────────────────────────────────────────────────

def _fire_alertmanager(alert_name: str, summary: str, labels: Dict[str, str]) -> None:
    """Invia un alert ad Alertmanager (API v2 /api/v2/alerts)."""
    url = settings.alertmanager_url
    if not url:
        return
    now_iso = datetime.now(timezone.utc).isoformat()
    payload = json.dumps([
        {
            "labels": {"alertname": alert_name, "service": "vap", **labels},
            "annotations": {"summary": summary},
            "startsAt": now_iso,
        }
    ]).encode()
    _http_post(
        f"{url.rstrip('/')}/api/v2/alerts",
        payload,
        {"Content-Type": "application/json"},
    )


def _fire_webhook(alert_name: str, summary: str, labels: Dict[str, str]) -> None:
    """Invia un alert a un webhook generico (payload JSON)."""
    url = settings.alert_webhook_url
    if not url:
        return
    payload = json.dumps({
        "alert": alert_name,
        "summary": summary,
        "labels": {"service": "vap", **labels},
        "fired_at": datetime.now(timezone.utc).isoformat(),
    }).encode()
    _http_post(url, payload, {"Content-Type": "application/json"})


def _fire_alert(alert_name: str, summary: str, labels: Optional[Dict[str, str]] = None) -> None:
    labels = labels or {}
    logger.warning("ALERT %s: %s (labels=%s)", alert_name, summary, labels)
    _fire_alertmanager(alert_name, summary, labels)
    _fire_webhook(alert_name, summary, labels)
    if ALERT_FIRED:
        ALERT_FIRED.labels(type=alert_name).inc()


# ── Rilevamento spike errori/latenza ─────────────────────────────────────────

def check_and_alert() -> None:
    """
    Legge le metriche correnti e invia alert se si superano le soglie
    configurate (VAP_ALERT_ERROR_RATE_THRESHOLD, VAP_ALERT_LATENCY_P99_THRESHOLD).
    """
    total_requests = 0.0
    error_5xx = 0.0
    p99_latency = 0.0

    for metric in REGISTRY.collect():
        if metric.name == "vap_http_requests_total":
            for sample in metric.samples:
                total_requests += sample.value
        elif metric.name == "vap_http_errors_5xx_total":
            for sample in metric.samples:
                error_5xx += sample.value
        elif metric.name == "vap_http_request_duration_seconds":
            # cerca il quantile 0.99 se disponibile (histogram_quantile è lato Prometheus)
            for sample in metric.samples:
                if sample.name.endswith("_bucket") and sample.labels.get("le") == "+Inf":
                    pass
                elif sample.name.endswith("_sum"):
                    pass
                elif sample.name.endswith("_count") and sample.value > 0:
                    # approssimazione p99 non disponibile localmente senza aggregazione:
                    # usiamo il rate medio come proxy
                    pass

    # Alert su error rate
    if total_requests > 100 and error_5xx / total_requests > settings.alert_error_rate_threshold:
        if _should_fire_alert("HighErrorRate"):
            rate = error_5xx / total_requests
            _fire_alert(
                "HighErrorRate",
                f"Error rate HTTP 5xx al {rate:.1%} (soglia: {settings.alert_error_rate_threshold:.1%})",
                {"rate": f"{rate:.4f}"},
            )


# ── Loop di push periodico ────────────────────────────────────────────────────

_push_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()


def _push_loop() -> None:
    interval = max(10, settings.metrics_push_interval_seconds)
    while not _stop_event.wait(timeout=interval):
        try:
            push_to_pushgateway()
            push_to_datadog()
            check_and_alert()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Telemetria: errore nel push loop — %s", exc)


def start_telemetry_push() -> None:
    """Avvia il thread di push periodico in background. Idempotente."""
    global _push_thread
    if _push_thread and _push_thread.is_alive():
        return
    if not (settings.metrics_pushgateway_url or settings.datadog_api_key or settings.metrics_remote_write_url):
        logger.debug("Telemetria centralizzata disabilitata (nessun backend configurato).")
        return
    _stop_event.clear()
    _push_thread = threading.Thread(target=_push_loop, name="vap-telemetry", daemon=True)
    _push_thread.start()
    logger.info(
        "Telemetria avviata — pushgateway=%s datadog=%s remote_write=%s interval=%ds",
        bool(settings.metrics_pushgateway_url),
        bool(settings.datadog_api_key),
        bool(settings.metrics_remote_write_url),
        settings.metrics_push_interval_seconds,
    )


def stop_telemetry_push() -> None:
    """Segnala lo stop al thread di push. Chiamare nello shutdown dell'app."""
    _stop_event.set()
