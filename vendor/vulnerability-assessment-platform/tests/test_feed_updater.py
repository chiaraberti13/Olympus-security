"""Test del gestore dei feed di threat intelligence (feed_updater).

Coprono: comportamento offline/degradato senza far cadere il boot, scrittura e
rilettura del manifest, logica di staleness, lettura della cache locale
(KEV/NVD) e percorso di successo con accessi di rete simulati.
"""
from pathlib import Path
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import feed_updater


def _fake_settings(tmp_path: Path, **overrides):
    base = dict(
        feeds_dir=tmp_path,
        feed_update_enabled=True,
        feed_update_on_startup=True,
        feed_update_interval_hours=12,
        feed_min_refresh_interval_minutes=360,
        feed_update_timeout_seconds=5,
        feed_sources="",
        feed_cache_enabled=True,
        nvd_api_base_url="https://nvd.local/cves",
        nvd_api_key="",
        nvd_recent_window_days=7,
        nvd_feed_max_results=2000,
        cisa_kev_feed_url="https://cisa.local/kev.json",
        epss_feed_url="https://first.local/epss",
        exploitdb_searchsploit_path="searchsploit",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _network_ok(url, **kwargs):
    if "nvd.local" in url:
        return _FakeResponse(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-1000",
                            "lastModified": "2026-06-09T10:00:00",
                            "descriptions": [{"lang": "en", "value": "Esempio"}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": 9.8,
                                            "vectorString": "CVSS:3.1/AV:N",
                                            "baseSeverity": "CRITICAL",
                                        }
                                    }
                                ]
                            },
                        }
                    }
                ]
            }
        )
    if "cisa.local" in url:
        return _FakeResponse(
            {
                "catalogVersion": "2026.06.09",
                "dateReleased": "2026-06-09",
                "vulnerabilities": [
                    {"cveID": "CVE-2026-1000", "dateAdded": "2026-06-01"},
                    {"cveID": "CVE-2025-0007", "dateAdded": "2025-12-01"},
                ],
            }
        )
    if "first.local" in url:
        return _FakeResponse({"total": 250000, "data": [{"cve": "CVE-2026-1000", "date": "2026-06-09"}]})
    raise AssertionError(f"URL inatteso: {url}")


def test_refresh_disabled_writes_disabled_manifest(monkeypatch, tmp_path):
    monkeypatch.setattr(feed_updater, "settings", _fake_settings(tmp_path, feed_update_enabled=False))

    manifest = feed_updater.refresh_all_feeds(force=True)

    assert manifest["overall_status"] == feed_updater.STATUS_DISABLED
    assert (tmp_path / feed_updater.MANIFEST_FILENAME).exists()


def test_refresh_offline_is_degraded_without_crashing(monkeypatch, tmp_path):
    monkeypatch.setattr(feed_updater, "settings", _fake_settings(tmp_path))

    def _boom(url, **kwargs):
        raise feed_updater.requests.RequestException("no network")

    monkeypatch.setattr(feed_updater, "_http_get", _boom)
    # Nessun tool esterno installato: i feed "tool" risultano saltati.
    monkeypatch.setattr(feed_updater.shutil, "which", lambda _: None)

    manifest = feed_updater.refresh_all_feeds(force=True)

    assert manifest["overall_status"] == "offline"
    assert manifest["feeds"]["nvd"]["status"] == feed_updater.STATUS_ERROR
    assert manifest["feeds"]["nuclei_templates"]["status"] == feed_updater.STATUS_SKIPPED
    assert manifest["feeds"]["exploitdb"]["status"] == feed_updater.STATUS_SKIPPED


def test_refresh_success_populates_caches_and_manifest(monkeypatch, tmp_path):
    monkeypatch.setattr(feed_updater, "settings", _fake_settings(tmp_path))
    monkeypatch.setattr(feed_updater, "_http_get", _network_ok)
    monkeypatch.setattr(feed_updater.shutil, "which", lambda _: None)

    manifest = feed_updater.refresh_all_feeds(force=True)

    # Le fonti di rete sono OK; i tool non installati non degradano lo stato.
    assert manifest["overall_status"] == feed_updater.STATUS_OK
    assert manifest["feeds"]["nvd"]["status"] == feed_updater.STATUS_OK
    assert manifest["feeds"]["nvd"]["count"] == 1
    assert manifest["feeds"]["cisa_kev"]["count"] == 2

    # Le cache locali sono interrogabili dall'enrichment engine.
    kev = feed_updater.load_local_kev_catalog()
    assert "CVE-2026-1000" in kev
    nvd_index = feed_updater.load_local_nvd_index()
    assert nvd_index["CVE-2026-1000"]["cvss_score"] == 9.8


def test_get_feed_status_includes_definitions(monkeypatch, tmp_path):
    monkeypatch.setattr(feed_updater, "settings", _fake_settings(tmp_path))

    status = feed_updater.get_feed_status()
    assert status["overall_status"] == "unknown"
    assert any(d["key"] == "nvd" for d in status["definitions"])


def test_feeds_are_stale_respects_interval(monkeypatch, tmp_path):
    monkeypatch.setattr(feed_updater, "settings", _fake_settings(tmp_path))
    monkeypatch.setattr(feed_updater, "_http_get", _network_ok)
    monkeypatch.setattr(feed_updater.shutil, "which", lambda _: None)

    assert feed_updater.feeds_are_stale() is True  # nessun manifest ancora
    feed_updater.refresh_all_feeds(force=True)
    assert feed_updater.feeds_are_stale() is False  # appena aggiornato, intervallo ampio


def test_refresh_skips_when_not_stale(monkeypatch, tmp_path):
    monkeypatch.setattr(feed_updater, "settings", _fake_settings(tmp_path))
    monkeypatch.setattr(feed_updater, "_http_get", _network_ok)
    monkeypatch.setattr(feed_updater.shutil, "which", lambda _: None)

    first = feed_updater.refresh_all_feeds(force=True)
    # Senza force e con feed freschi, deve restituire il manifest esistente intatto.
    second = feed_updater.refresh_all_feeds(force=False)
    assert second["last_run_at"] == first["last_run_at"]


def test_startup_refresh_disabled_returns_none(monkeypatch, tmp_path):
    monkeypatch.setattr(
        feed_updater, "settings", _fake_settings(tmp_path, feed_update_on_startup=False)
    )
    assert feed_updater.trigger_startup_refresh() is None
