# Threat Intelligence Feeds

VAP mantiene **sempre aggiornati** i dati di vulnerabilità e le definizioni
usate dagli scanner attingendo esclusivamente da **fonti ufficiali**. Gli
aggiornamenti vengono scaricati **all'avvio dell'applicazione** e poi
periodicamente in background, così l'analisi e i report riflettono lo stato
dell'arte della minaccia.

## Fonti ufficiali

| Fonte | Cosa fornisce | Tipo |
| --- | --- | --- |
| **NVD / NIST** | CVE recenti con punteggi e vettori **CVSS** ufficiali | Rete |
| **CISA KEV** | Catalogo delle vulnerabilità note come attivamente sfruttate | Rete |
| **FIRST.org EPSS** | Probabilità di sfruttamento (Exploit Prediction Scoring System) | Rete |
| **Nuclei templates** | Definizioni di vulnerabilità per lo scanner Nuclei | Tool |
| **Exploit-DB** | Archivio exploit pubblici (via `searchsploit`) | Tool |

I feed di tipo *Tool* vengono aggiornati solo se il binario corrispondente
(`nuclei`, `searchsploit`) è installato; in caso contrario sono marcati come
`skipped` senza generare errori.

## Funzionamento

1. **All'avvio** (`VAP_FEED_UPDATE_ON_STARTUP=true`) viene avviato un refresh in
   un thread in background: il boot dell'app non viene mai bloccato.
2. Una **guardia anti-stale** (`VAP_FEED_MIN_REFRESH_MINUTES`) evita download
   ripetuti a ogni reload in sviluppo.
3. Un **job periodico** (`VAP_FEED_UPDATE_INTERVAL_HOURS`) mantiene la cache
   fresca durante l'esecuzione.
4. I dati scaricati finiscono in una **cache locale** (`VAP_FEEDS_DIR`, default
   `feeds/`) interrogabile **anche offline**:
   - `nvd_recent.json` — indice CVE→CVSS delle vulnerabilità recenti;
   - `cisa_kev.json` — catalogo KEV completo;
   - `epss_probe.json` — freschezza del modello EPSS;
   - `feed_status.json` — manifest di stato (esito, conteggi, timestamp).

> La directory `feeds/` è rigenerabile e **non** viene versionata (è in
> `.gitignore`).

## Integrazione con l'enrichment

Quando `VAP_FEED_CACHE_ENABLED=true`, l'enrichment dei findings usa la cache
locale come prima sorgente:

- il **catalogo KEV** locale è completo e funziona offline;
- l'**indice NVD recente** risolve le CVE degli ultimi giorni senza interrogare
  l'API per ogni CVE (utile anche in assenza di API key NVD).

In assenza di dati in cache, il sistema ricade sulle chiamate live esistenti
(NVD, EPSS, KEV) quando `VAP_ENABLE_LIVE_SCANS=true`.

## API

| Metodo | Endpoint | Ruolo | Descrizione |
| --- | --- | --- | --- |
| `GET` | `/api/v1/feeds/status` | viewer | Stato dei feed: esito, conteggi, timestamp, staleness. |
| `POST` | `/api/v1/feeds/refresh` | admin | Forza l'aggiornamento immediato da tutte le fonti. |

Esempio di risposta di `GET /api/v1/feeds/status`:

```json
{
  "last_run_at": "2026-06-10T12:28:00+00:00",
  "overall_status": "ok",
  "feeds": {
    "nvd": {"status": "ok", "count": 2000, "updated_at": "..."},
    "cisa_kev": {"status": "ok", "count": 1617, "updated_at": "..."},
    "epss": {"status": "ok", "count": 338871, "updated_at": "..."},
    "nuclei_templates": {"status": "skipped"},
    "exploitdb": {"status": "skipped"}
  },
  "stale": false
}
```

Lo stato complessivo può essere: `ok`, `degraded` (alcune fonti fallite),
`offline` (tutte le fonti di rete irraggiungibili), `skipped` (solo feed
saltati), `disabled` o `unknown` (nessun aggiornamento ancora eseguito).

## Report

Ogni report PDF riporta in copertina una riga sintetica con le **fonti di
threat intelligence** attive e la data dell'ultimo aggiornamento, a supporto
della tracciabilità delle fonti.

## Note operative

- **Senza API key NVD** (`VAP_NVD_API_KEY`) i rate limit sono ridotti: per
  ambienti professionali è consigliato richiedere una API key gratuita a NIST.
- Tutte le operazioni hanno timeout (`VAP_FEED_UPDATE_TIMEOUT`) e degradano in
  modo controllato: un feed non disponibile non blocca mai l'avvio né le
  scansioni.
