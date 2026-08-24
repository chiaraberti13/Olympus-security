#!/usr/bin/env python3
"""Gestore dei feed di threat intelligence da fonti ufficiali.

Scarica e mantiene aggiornati i dati di vulnerabilità e le definizioni usate
dagli scanner, attingendo esclusivamente da fonti ufficiali:

* **NVD / NIST** — CVE recenti con punteggi CVSS (corpus locale interrogabile);
* **CISA KEV** — catalogo Known Exploited Vulnerabilities;
* **FIRST.org EPSS** — modello di probabilità di sfruttamento (CVSS-correlato);
* **Nuclei templates** — definizioni di vulnerabilità per lo scanner Nuclei;
* **ExploitDB** — database exploit locale (searchsploit).

Il modulo mantiene una cache locale (utilizzabile anche offline dall'enrichment
engine) e un *manifest* di stato che riporta, per ogni fonte, l'esito
dell'ultimo aggiornamento, il conteggio degli elementi e il timestamp. È
pensato per essere eseguito **all'avvio dell'applicazione** ("ad ogni avvio") e
periodicamente in background, senza mai bloccare il boot e degradando in modo
controllato in assenza di rete o di tool esterni.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
import shutil
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

import requests

from config import settings


logger = logging.getLogger("vap.feeds")

# Nomi dei file di cache all'interno della directory dei feed.
MANIFEST_FILENAME = "feed_status.json"
NVD_CACHE_FILENAME = "nvd_recent.json"
KEV_CACHE_FILENAME = "cisa_kev.json"
EPSS_CACHE_FILENAME = "epss_probe.json"

# Stati possibili per un singolo feed.
STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"
STATUS_DISABLED = "disabled"


# Descrittori statici dei feed, esposti a UI/API per spiegare ogni fonte.
FEED_DEFINITIONS: List[Dict[str, str]] = [
    {
        "key": "nvd",
        "label": "NVD / NIST (CVE + CVSS)",
        "kind": "network",
        "source": "https://nvd.nist.gov/",
        "description": "Vulnerabilità CVE recenti con punteggi e vettori CVSS ufficiali.",
    },
    {
        "key": "cisa_kev",
        "label": "CISA KEV",
        "kind": "network",
        "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "description": "Catalogo delle vulnerabilità note come attivamente sfruttate.",
    },
    {
        "key": "epss",
        "label": "FIRST.org EPSS",
        "kind": "network",
        "source": "https://www.first.org/epss/",
        "description": "Probabilità di sfruttamento (Exploit Prediction Scoring System).",
    },
    {
        "key": "nuclei_templates",
        "label": "Nuclei templates",
        "kind": "tool",
        "source": "https://github.com/projectdiscovery/nuclei-templates",
        "description": "Definizioni di vulnerabilità per lo scanner Nuclei.",
    },
    {
        "key": "exploitdb",
        "label": "Exploit-DB (searchsploit)",
        "kind": "tool",
        "source": "https://www.exploit-db.com/",
        "description": "Archivio exploit pubblici per correlazione ai findings.",
    },
]


@dataclass
class FeedResult:
    """Esito dell'aggiornamento di un singolo feed."""

    key: str
    label: str
    status: str = STATUS_SKIPPED
    count: Optional[int] = None
    message: str = ""
    source: str = ""
    updated_at: Optional[str] = None
    duration_ms: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "key": self.key,
            "label": self.label,
            "status": self.status,
            "message": self.message,
            "source": self.source,
            "updated_at": self.updated_at,
        }
        if self.count is not None:
            payload["count"] = self.count
        if self.duration_ms is not None:
            payload["duration_ms"] = self.duration_ms
        if self.details:
            payload["details"] = self.details
        return payload


# ── Helper di basso livello ────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def feeds_dir() -> Path:
    """Percorso della directory dei feed.

    Non crea la directory: la sua creazione avviene solo in fase di scrittura
    (``_write_json``), così le letture di stato/cache restano prive di effetti
    collaterali sul filesystem.
    """
    return settings.feeds_dir


def _http_get(url: str, **kwargs: Any) -> requests.Response:
    """Wrapper attorno a requests.get per centralizzare timeout e mocking nei test."""
    kwargs.setdefault("timeout", settings.feed_update_timeout_seconds)
    return requests.get(url, **kwargs)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


# ── Aggiornatori per singola fonte ─────────────────────────────────────────


def update_nvd_recent() -> FeedResult:
    """Scarica le CVE modificate di recente da NVD e ne costruisce un indice locale.

    L'indice ``nvd_recent.json`` mappa ``CVE-ID -> {descrizione, cvss, vettore,
    severità, ultima modifica}`` e viene usato dall'enrichment engine come
    sorgente offline prima di interrogare l'API NVD per singola CVE.
    """
    result = FeedResult(
        key="nvd",
        label="NVD / NIST (CVE + CVSS)",
        source=settings.nvd_api_base_url,
    )
    start = time.monotonic()

    end = _now()
    begin = end - timedelta(days=max(1, settings.nvd_recent_window_days))
    params = {
        "lastModStartDate": begin.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": max(1, min(settings.nvd_feed_max_results, 2000)),
    }
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}

    try:
        response = _http_get(settings.nvd_api_base_url, params=params, headers=headers)
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, json.JSONDecodeError, ValueError) as exc:
        result.status = STATUS_ERROR
        result.message = f"Aggiornamento NVD non riuscito: {exc}"
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    index = _parse_nvd_payload(payload)
    cache = {
        "updated_at": _iso(end),
        "window_days": settings.nvd_recent_window_days,
        "source": settings.nvd_api_base_url,
        "cves": index,
    }
    _write_json(feeds_dir() / NVD_CACHE_FILENAME, cache)

    result.status = STATUS_OK
    result.count = len(index)
    result.updated_at = _iso(end)
    result.message = (
        f"{len(index)} CVE indicizzate (ultimi {settings.nvd_recent_window_days} giorni)."
    )
    if not settings.nvd_api_key:
        result.message += " Senza API key NVD i rate limit sono ridotti."
    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result


def _parse_nvd_payload(payload: Any) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    for entry in vulnerabilities:
        cve_item = entry.get("cve", {}) if isinstance(entry, dict) else {}
        cve_id = str(cve_item.get("id", "")).strip()
        if not cve_id:
            continue

        descriptions = cve_item.get("descriptions", []) if isinstance(cve_item, dict) else []
        description = next(
            (d.get("value") for d in descriptions if isinstance(d, dict) and d.get("lang") == "en"),
            "",
        )

        cvss_score: Optional[float] = None
        cvss_vector: Optional[str] = None
        cvss_severity: Optional[str] = None
        metrics = cve_item.get("metrics", {}) if isinstance(cve_item, dict) else {}
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key) if isinstance(metrics, dict) else None
            if metric_list:
                metric = metric_list[0] if isinstance(metric_list, list) else {}
                data = metric.get("cvssData", {}) if isinstance(metric, dict) else {}
                cvss_score = data.get("baseScore")
                cvss_vector = data.get("vectorString")
                cvss_severity = data.get("baseSeverity") or metric.get("baseSeverity")
                break

        index[cve_id] = {
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cvss_severity": cvss_severity,
            "last_modified": cve_item.get("lastModified"),
            "source": "NVD",
        }
    return index


def update_cisa_kev() -> FeedResult:
    """Scarica il catalogo CISA KEV completo e lo memorizza localmente."""
    result = FeedResult(
        key="cisa_kev",
        label="CISA KEV",
        source=settings.cisa_kev_feed_url,
    )
    start = time.monotonic()

    try:
        response = _http_get(settings.cisa_kev_feed_url)
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, json.JSONDecodeError, ValueError) as exc:
        result.status = STATUS_ERROR
        result.message = f"Aggiornamento CISA KEV non riuscito: {exc}"
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    catalog: Dict[str, Dict[str, Any]] = {}
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID", "")).strip()
        if cve_id:
            catalog[cve_id] = item

    cache = {
        "updated_at": _iso(_now()),
        "catalog_version": payload.get("catalogVersion") if isinstance(payload, dict) else None,
        "date_released": payload.get("dateReleased") if isinstance(payload, dict) else None,
        "source": settings.cisa_kev_feed_url,
        "vulnerabilities": catalog,
    }
    _write_json(feeds_dir() / KEV_CACHE_FILENAME, cache)

    result.status = STATUS_OK
    result.count = len(catalog)
    result.updated_at = cache["updated_at"]
    version = cache.get("catalog_version")
    result.message = f"{len(catalog)} vulnerabilità sfruttate" + (
        f" (catalogo {version})." if version else "."
    )
    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result


def update_epss() -> FeedResult:
    """Verifica la disponibilità e la data del modello EPSS (FIRST.org).

    Il dataset EPSS completo è di grandi dimensioni e cambia ogni giorno: invece
    di scaricarlo per intero, il feed registra la data del modello corrente come
    indicatore di freschezza. I punteggi per singola CVE sono comunque recuperati
    on-demand dall'enrichment engine.
    """
    result = FeedResult(
        key="epss",
        label="FIRST.org EPSS",
        source=settings.epss_feed_url,
    )
    start = time.monotonic()

    try:
        response = _http_get(settings.epss_feed_url, params={"limit": 1})
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, json.JSONDecodeError, ValueError) as exc:
        result.status = STATUS_ERROR
        result.message = f"Verifica EPSS non riuscita: {exc}"
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    model_date = None
    if isinstance(payload, dict):
        data = payload.get("data", [])
        if isinstance(data, list) and data and isinstance(data[0], dict):
            model_date = data[0].get("date")
        total = payload.get("total")
    else:
        total = None

    cache = {
        "updated_at": _iso(_now()),
        "model_date": model_date,
        "total_scored_cves": total,
        "source": settings.epss_feed_url,
    }
    _write_json(feeds_dir() / EPSS_CACHE_FILENAME, cache)

    result.status = STATUS_OK
    result.count = total if isinstance(total, int) else None
    result.updated_at = cache["updated_at"]
    result.details = {"model_date": model_date}
    result.message = (
        f"Modello EPSS del {model_date} disponibile." if model_date else "Servizio EPSS raggiungibile."
    )
    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result


def update_nuclei_templates() -> FeedResult:
    """Aggiorna i template di Nuclei (definizioni di vulnerabilità dello scanner)."""
    result = FeedResult(
        key="nuclei_templates",
        label="Nuclei templates",
        source="https://github.com/projectdiscovery/nuclei-templates",
    )
    start = time.monotonic()

    if not shutil.which("nuclei"):
        result.status = STATUS_SKIPPED
        result.message = "Tool nuclei non installato: aggiornamento template saltato."
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    try:
        completed = subprocess.run(
            ["nuclei", "-update-templates"],
            capture_output=True,
            text=True,
            timeout=settings.feed_update_timeout_seconds,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        result.status = STATUS_ERROR
        result.message = f"Aggiornamento template nuclei non riuscito: {exc}"
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    if completed.returncode != 0:
        result.status = STATUS_ERROR
        result.message = (completed.stderr or "Errore aggiornamento template nuclei.").strip()[:500]
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    result.status = STATUS_OK
    result.updated_at = _iso(_now())
    result.message = "Template Nuclei aggiornati."
    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result


def update_exploitdb() -> FeedResult:
    """Aggiorna il database locale di Exploit-DB (searchsploit -u)."""
    result = FeedResult(
        key="exploitdb",
        label="Exploit-DB (searchsploit)",
        source="https://www.exploit-db.com/",
    )
    start = time.monotonic()

    searchsploit = settings.exploitdb_searchsploit_path
    if not shutil.which(searchsploit):
        result.status = STATUS_SKIPPED
        result.message = "searchsploit non installato: aggiornamento Exploit-DB saltato."
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    try:
        completed = subprocess.run(
            [searchsploit, "-u"],
            capture_output=True,
            text=True,
            timeout=settings.feed_update_timeout_seconds,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        result.status = STATUS_ERROR
        result.message = f"Aggiornamento Exploit-DB non riuscito: {exc}"
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    if completed.returncode != 0:
        result.status = STATUS_ERROR
        result.message = (completed.stderr or "Errore aggiornamento Exploit-DB.").strip()[:500]
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    result.status = STATUS_OK
    result.updated_at = _iso(_now())
    result.message = "Database Exploit-DB aggiornato."
    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result


# Registro degli aggiornatori: chiave -> (funzione, è_di_rete).
_UPDATERS = {
    "nvd": (update_nvd_recent, True),
    "cisa_kev": (update_cisa_kev, True),
    "epss": (update_epss, True),
    "nuclei_templates": (update_nuclei_templates, False),
    "exploitdb": (update_exploitdb, False),
}


# ── Orchestrazione e stato ──────────────────────────────────────────────────


def _selected_feed_keys() -> List[str]:
    configured = [item.strip() for item in settings.feed_sources.split(",") if item.strip()]
    if not configured:
        return list(_UPDATERS.keys())
    return [key for key in configured if key in _UPDATERS]


def refresh_all_feeds(force: bool = False) -> Dict[str, Any]:
    """Aggiorna tutte le fonti abilitate e scrive il manifest di stato.

    Args:
        force: ignora la guardia anti-stale ed esegue comunque l'aggiornamento.

    Returns:
        Il manifest di stato (lo stesso restituito da :func:`get_feed_status`).
    """
    if not settings.feed_update_enabled:
        manifest = {
            "last_run_at": _iso(_now()),
            "overall_status": STATUS_DISABLED,
            "message": "Aggiornamento feed disabilitato (VAP_FEED_UPDATE_ENABLED=false).",
            "feeds": {},
        }
        _save_manifest(manifest)
        return manifest

    if not force and not feeds_are_stale():
        existing = _load_manifest()
        if existing is not None:
            return existing

    started = _now()
    logger.info("Avvio aggiornamento feed di threat intelligence…")

    results: Dict[str, Dict[str, Any]] = {}
    network_keys: List[str] = []
    network_failures = 0

    for key in _selected_feed_keys():
        updater, is_network = _UPDATERS[key]
        try:
            outcome = updater()
        except Exception as exc:  # noqa: BLE001 - un feed non deve mai far cadere il boot
            logger.warning("Feed %s: errore inatteso: %s", key, exc)
            definition = next((d for d in FEED_DEFINITIONS if d["key"] == key), {})
            outcome = FeedResult(
                key=key,
                label=str(definition.get("label", key)),
                status=STATUS_ERROR,
                message=f"Errore inatteso: {exc}",
                source=str(definition.get("source", "")),
            )
        results[key] = outcome.to_dict()
        if is_network:
            network_keys.append(key)
            if outcome.status == STATUS_ERROR:
                network_failures += 1
        logger.info("Feed %s -> %s (%s)", key, outcome.status, outcome.message)

    overall = _derive_overall_status(results, network_keys, network_failures)
    manifest = {
        "last_run_at": _iso(started),
        "duration_ms": int((_now() - started).total_seconds() * 1000),
        "overall_status": overall,
        "feeds": results,
    }
    _save_manifest(manifest)
    logger.info("Aggiornamento feed completato: stato complessivo=%s", overall)
    return manifest


def trigger_startup_refresh() -> Optional[threading.Thread]:
    """Avvia l'aggiornamento dei feed all'avvio dell'app, senza bloccare il boot.

    L'aggiornamento gira in un thread daemon e rispetta sia i flag di
    configurazione (``feed_update_enabled`` / ``feed_update_on_startup``) sia la
    guardia anti-stale. Restituisce il thread avviato oppure ``None`` se
    l'aggiornamento all'avvio è disabilitato.
    """
    if not (settings.feed_update_enabled and settings.feed_update_on_startup):
        return None

    def _run() -> None:
        try:
            refresh_all_feeds(force=False)
        except Exception:  # noqa: BLE001 - il refresh all'avvio non deve mai far cadere il boot
            logger.exception("Refresh feed all'avvio non riuscito.")

    thread = threading.Thread(target=_run, name="vap-feed-startup-refresh", daemon=True)
    thread.start()
    return thread


def _derive_overall_status(
    results: Dict[str, Dict[str, Any]],
    network_keys: List[str],
    network_failures: int,
) -> str:
    if not results:
        return STATUS_DISABLED
    statuses = {item.get("status") for item in results.values()}
    if network_keys and network_failures == len(network_keys):
        # Tutte le fonti di rete hanno fallito: probabile assenza di connettività.
        return "offline"
    if STATUS_ERROR in statuses:
        return "degraded"
    if statuses <= {STATUS_SKIPPED, STATUS_DISABLED}:
        return STATUS_SKIPPED
    return STATUS_OK


def _manifest_path() -> Path:
    return feeds_dir() / MANIFEST_FILENAME


def _save_manifest(manifest: Dict[str, Any]) -> None:
    try:
        _write_json(_manifest_path(), manifest)
    except OSError as exc:
        logger.warning("Impossibile salvare il manifest dei feed: %s", exc)


def _load_manifest() -> Optional[Dict[str, Any]]:
    return _read_json(_manifest_path())


def get_feed_status() -> Dict[str, Any]:
    """Restituisce lo stato corrente dei feed per UI/API/report.

    Se non è ancora stato eseguito alcun aggiornamento, restituisce un manifest
    "neutro" con i descrittori delle fonti e stato ``unknown``.
    """
    manifest = _load_manifest()
    if manifest is None:
        return {
            "last_run_at": None,
            "overall_status": "unknown",
            "message": "Nessun aggiornamento feed ancora eseguito.",
            "feeds": {},
            "definitions": FEED_DEFINITIONS,
        }
    enriched = dict(manifest)
    enriched["definitions"] = FEED_DEFINITIONS
    enriched["stale"] = feeds_are_stale()
    return enriched


def feeds_are_stale() -> bool:
    """Indica se i feed vanno riaggiornati in base all'intervallo minimo."""
    manifest = _load_manifest()
    if manifest is None:
        return True
    last_run = manifest.get("last_run_at")
    if not last_run:
        return True
    try:
        last_dt = datetime.fromisoformat(last_run)
    except (TypeError, ValueError):
        return True
    if last_dt.tzinfo is None:
        last_dt = last_dt.replace(tzinfo=timezone.utc)
    threshold = timedelta(minutes=max(0, settings.feed_min_refresh_interval_minutes))
    return (_now() - last_dt) >= threshold


# ── Accessori per l'enrichment engine ───────────────────────────────────────


def load_local_kev_catalog() -> Dict[str, Dict[str, Any]]:
    """Restituisce il catalogo CISA KEV dalla cache locale (vuoto se assente)."""
    cache = _read_json(feeds_dir() / KEV_CACHE_FILENAME)
    if isinstance(cache, dict):
        vulnerabilities = cache.get("vulnerabilities")
        if isinstance(vulnerabilities, dict):
            return vulnerabilities
    return {}


def load_local_nvd_index() -> Dict[str, Dict[str, Any]]:
    """Restituisce l'indice NVD recente dalla cache locale (vuoto se assente)."""
    cache = _read_json(feeds_dir() / NVD_CACHE_FILENAME)
    if isinstance(cache, dict):
        cves = cache.get("cves")
        if isinstance(cves, dict):
            return cves
    return {}
