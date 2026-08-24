# Configurazione completa (.env ↔ config.py)

Questa pagina mappa **tutte** le variabili disponibili nel file `.env` con la configurazione letta da `config.py`.
Usa `.env.example` come base e compila solo le variabili che ti servono.

> Suggerimento: in produzione imposta **almeno** le variabili di sicurezza nella sezione “Hardening minimo”.

## Hardening minimo (produzione)

| Variabile | Scopo | Note |
| --- | --- | --- |
| `VAP_API_KEY` / `VAP_API_KEY_HASH` | Protegge le API con API key | Obbligatorio in produzione. |
| `VAP_JWT_REQUIRED` | Forza l’autenticazione JWT | Imposta `true` in produzione. |
| `VAP_JWT_SECRET` | Firma i token JWT | Genera un secret robusto. |
| `VAP_CSRF_SECRET` | Protezione CSRF | Impostalo a un valore ruotabile. |
| `VAP_REQUIRE_HTTPS` | Richiede HTTPS | Imposta `true` + certificati TLS. |
| `VAP_TLS_CERTFILE` / `VAP_TLS_KEYFILE` | Certificati TLS | Obbligatori se `VAP_REQUIRE_HTTPS=true`. |
| `VAP_CORS_ALLOWED_ORIGINS` | Limita le origini CORS | Usa una lista di domini consentiti. |
| `VAP_RATE_LIMIT_*` | Rate limiting | Stringhe tipo `120/minute`. |
| `VAP_SECURITY_HEADERS` | Header di sicurezza | Lascia `true` e valida `VAP_CSP_POLICY`. |
| `VAP_AUDIT_LOGGING` | Audit log | Consigliato `true` in produzione. |

## Server

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_ENV` | `development` | Ambiente applicativo (`development`, `staging`, `production`). |
| `VAP_HOST` | `0.0.0.0` | Bind host. |
| `VAP_PORT` | `8000` | Porta del server. |
| `VAP_REQUIRE_HTTPS` | `false` | Richiede HTTPS. |
| `VAP_TLS_CERTFILE` | `""` | Percorso certificato TLS. |
| `VAP_TLS_KEYFILE` | `""` | Percorso chiave TLS. |
| `VAP_TLS_CA_CERTS` | `""` | CA bundle. |

## Database

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_DATABASE_URL` | `sqlite:///./vap.db` | Stringa di connessione. |
| `VAP_SQLCIPHER_KEY` | `""` | Chiave per SQLCipher (se usato). |

## Migrazioni database (Alembic)

Lo schema DB è versionato con **Alembic**. In ambienti reali applica sempre le migrazioni prima di avviare worker/API:

```bash
python -m alembic upgrade head
```

Per creare una nuova revisione:

```bash
python -m alembic revision -m "descrizione_migrazione"
```

> `init_db()` applica automaticamente `upgrade head` quando trova `alembic.ini`; il fallback `create_all` resta disponibile solo come rete di sicurezza per ambienti legacy senza asset Alembic.

## Reports & retention

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_REPORTS_DIR` | `reports` | Directory report PDF. |
| `VAP_SCAN_RETENTION_DAYS` | `30` | Giorni retention scansioni. |
| `VAP_SCAN_ARCHIVE_AFTER_DAYS` | `7` | Archiviazione scansioni. |

## Scansioni & concorrenza

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_SCAN_TIMEOUT` | `300` | Timeout scansioni (sec). |
| `VAP_ENABLE_LIVE_SCANS` | `false` | Abilita scansioni live. |
| `VAP_MAX_FINDINGS` | `200` | Massimo findings per scan. |
| `VAP_MAX_CONCURRENT_SCANNERS` | `5` | Concorrenza tool scanner. |

## Performance budget (SLA operativi)

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_SCAN_RUNTIME_SLA_SECONDS` | `900` | Soglia SLA massima per la durata end-to-end della scansione (queue/running/finalize). Se superata, viene emesso warning nei log della scansione. |
| `VAP_REPORT_RENDER_SLA_SECONDS` | `20` | Soglia SLA massima per il tempo di rendering PDF. Se superata, viene emesso warning nei log della scansione. |

## Autenticazione & API security

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_API_KEY` | `""` | API key in chiaro. |
| `VAP_API_KEY_HASH` | `""` | Hash API key (preferibile). |
| `VAP_API_KEY_LAST_ROTATED_AT` | `""` | Data ultima rotazione API key (`YYYY-MM-DD`) usata dalla startup security checklist. |
| `VAP_API_KEY_ROTATION_MAX_DAYS` | `90` | Finestra massima consigliata (giorni) tra rotazioni API key. |
| `VAP_CSRF_SECRET` | `""` → autogenerato | Secret CSRF. |
| `VAP_CSRF_LAST_ROTATED_AT` | `""` | Data ultima rotazione secret CSRF (`YYYY-MM-DD`) per checklist hardening. |
| `VAP_CSRF_ROTATION_MAX_DAYS` | `180` | Finestra consigliata (giorni) per rotazione secret CSRF. |
| `VAP_CSRF_COOKIE` | `vap_csrf` | Nome cookie CSRF. |
| `VAP_CSRF_TTL` | `3600` | TTL CSRF (sec). |
| `VAP_JWT_SECRET` | `""` | Secret JWT. |
| `VAP_JWT_LAST_ROTATED_AT` | `""` | Data ultima rotazione secret JWT (`YYYY-MM-DD`) per controlli startup. |
| `VAP_JWT_ROTATION_MAX_DAYS` | `90` | Finestra massima consigliata (giorni) per rotazione JWT secret. |
| `VAP_JWT_ALGORITHM` | `HS256` | Algoritmo JWT. |
| `VAP_JWT_ISSUER` | `vap` | Issuer JWT. |
| `VAP_JWT_AUDIENCE` | `vap-users` | Audience JWT. |
| `VAP_JWT_EXP_MINUTES` | `60` | Expiration JWT (min). |
| `VAP_JWT_REQUIRED` | `false` | Richiede JWT. |
| `VAP_JWT_DEMO_USER` | `` | Username opzionale per endpoint demo `/auth/token`. In produzione lasciarlo vuoto o disabilitare endpoint. |
| `VAP_JWT_DEMO_PASSWORD` | `` | Password opzionale per endpoint demo `/auth/token`. Deve essere impostata esplicitamente. |
| `VAP_TRUSTED_PROXY_IP` | `` | IP del reverse proxy fidato da cui accettare `X-Forwarded-For`. |
| `VAP_TARGET_ALLOWLIST` | `""` | Lista target consentiti in produzione (domini, wildcard `*.example.com`, IP/CIDR). |

## CORS

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_CORS_ALLOWED_ORIGINS` | `""` | Origini consentite (lista). |
| `VAP_CORS_ALLOWED_METHODS` | `GET,POST,PUT,PATCH,DELETE,OPTIONS` | Metodi permessi. |
| `VAP_CORS_ALLOWED_HEADERS` | `Authorization,Content-Type,X-API-Key` | Header permessi. |
| `VAP_CORS_ALLOW_CREDENTIALS` | `false` | Consenti credentials. |

## Rate limiting

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_RATE_LIMIT_DEFAULT` | `120/minute` | Limite default. |
| `VAP_RATE_LIMIT_CREATE_SCAN` | `10/minute` | Limite creazione scan. |
| `VAP_RATE_LIMIT_AUTH` | `15/minute` | Limite auth. |
| `VAP_RATE_LIMIT_READ` | `120/minute` | Limite read. |

## Security headers

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_HSTS_MAX_AGE` | `31536000` | HSTS max-age. |
| `VAP_CSP_POLICY` | *(policy di default)* | Content Security Policy. |
| `VAP_SECURITY_HEADERS` | `true` | Abilita header di sicurezza. |

## Compliance & audit

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_AUDIT_LOGGING` | `true` | Audit logging. |
| `VAP_PRIVACY_POLICY_VERSION` | `2024-01` | Versione privacy policy. |
| `VAP_TERMS_VERSION` | `2024-01` | Versione ToS. |
| `VAP_CONSENT_RETENTION_DAYS` | `365` | Retention consensi. |
| `VAP_AUDIT_RETENTION_DAYS` | `365` | Retention audit. |

## Nuclei

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_NUCLEI_RATE_LIMIT` | `150` | Rate limit Nuclei. |
| `VAP_NUCLEI_TIMEOUT` | `10` | Timeout Nuclei (sec). |
| `VAP_NUCLEI_SEVERITIES` | `critical,high,medium,low,info` | Severità incluse. |
| `VAP_NUCLEI_TEMPLATES` | `""` | Path template custom. |
| `VAP_NUCLEI_UPDATE_TEMPLATES` | `true` | Aggiorna templates. |
| `VAP_NUCLEI_ADDITIONAL_ARGS` | `""` | Argomenti extra. |

## Nmap

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_NMAP_PROFILE` | `quick` | Profilo Nmap. |
| `VAP_NMAP_ADDITIONAL_ARGS` | `""` | Argomenti extra. |

## Enrichment APIs

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_SECURITYTRAILS_API_KEY` | `""` | API key SecurityTrails. |
| `VAP_VIRUSTOTAL_API_KEY` | `""` | API key VirusTotal. |
| `VAP_SHODAN_API_KEY` | `""` | API key Shodan. |

## Subfinder

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_SUBFINDER_SOURCES` | `""` | Sorgenti Subfinder. |
| `VAP_SUBFINDER_RESOLVE_LIMIT` | `200` | Limit risoluzione. |

## Dirsearch

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_DIRSEARCH_PATH` | `dirsearch` | Binario Dirsearch. |
| `VAP_DIRSEARCH_WORDLIST` | `""` | Wordlist. |
| `VAP_DIRSEARCH_EXTENSIONS` | `php,asp,aspx,js,html,zip,tar.gz,bak,old,backup` | Estensioni. |
| `VAP_DIRSEARCH_THREADS` | `20` | Thread Dirsearch. |

## SQLMap

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_SQLMAP_PATH` | `sqlmap` | Binario SQLMap. |
| `VAP_SQLMAP_LEVEL` | `2` | Level SQLMap. |
| `VAP_SQLMAP_RISK` | `1` | Risk SQLMap. |
| `VAP_SQLMAP_CRAWL_DEPTH` | `1` | Crawl depth. |
| `VAP_SQLMAP_FORMS` | `true` | Analizza form. |
| `VAP_SQLMAP_ADDITIONAL_ARGS` | `""` | Argomenti extra. |

## XSStrike

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_XSSTRIKE_PATH` | `xsstrike` | Binario XSStrike. |
| `VAP_XSSTRIKE_CRAWL` | `true` | Crawling. |
| `VAP_XSSTRIKE_ADDITIONAL_ARGS` | `""` | Argomenti extra. |

## OWASP ZAP

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_ZAP_API_BASE_URL` | `""` | Base URL ZAP API. |
| `VAP_ZAP_API_KEY` | `""` | API key ZAP. |
| `VAP_ZAP_MAX_ALERTS` | `200` | Max alert. |
| `VAP_ZAP_TIMEOUT` | `20` | Timeout (sec). |

## Burp Suite

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_BURP_API_BASE_URL` | `""` | Base URL Burp API. |
| `VAP_BURP_API_KEY` | `""` | API key Burp. |
| `VAP_BURP_API_SCAN_ENDPOINT` | `/v0.1/scan` | Endpoint scan. |
| `VAP_BURP_API_ISSUES_ENDPOINT` | `/v0.1/scan/{scan_id}/issues` | Endpoint issues. |
| `VAP_BURP_TIMEOUT` | `20` | Timeout (sec). |

## Wapiti & Commix

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_WAPITI_PATH` | `wapiti` | Binario Wapiti. |
| `VAP_COMMIX_PATH` | `commix` | Binario Commix. |
| `VAP_COMMIX_ADDITIONAL_ARGS` | `""` | Argomenti extra. |

## Acunetix

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_ACUNETIX_API_BASE_URL` | `""` | Base URL Acunetix. |
| `VAP_ACUNETIX_API_KEY` | `""` | API key Acunetix. |
| `VAP_ACUNETIX_VULNERABILITIES_ENDPOINT` | `/api/v1/vulnerabilities` | Endpoint vulnerabilità. |
| `VAP_ACUNETIX_TIMEOUT` | `20` | Timeout (sec). |

## Nessus

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_NESSUS_API_BASE_URL` | `""` | Base URL Nessus. |
| `VAP_NESSUS_API_KEY` | `""` | API key Nessus. |
| `VAP_NESSUS_VULNERABILITIES_ENDPOINT` | `/vulnerabilities` | Endpoint vulnerabilità. |
| `VAP_NESSUS_TIMEOUT` | `20` | Timeout (sec). |

## OpenVAS / Greenbone (GVM)

Adapter opzionale verso un'istanza Greenbone/GVM esistente (legge i risultati,
non avvia il task). Vedi il [playbook OpenVAS](scan-playbooks/openvas.md).

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_OPENVAS_API_BASE_URL` | `""` | Base URL dell'istanza Greenbone/GVM. |
| `VAP_OPENVAS_API_KEY` | `""` | API key (header `X-API-KEY`). |
| `VAP_OPENVAS_VULNERABILITIES_ENDPOINT` | `/gmp/results` | Endpoint dei risultati. |
| `VAP_OPENVAS_TIMEOUT` | `30` | Timeout (sec). |

## NVD

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_NVD_API_BASE_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Base URL NVD. |
| `VAP_NVD_API_KEY` | `""` | API key NVD. |
| `VAP_NVD_TIMEOUT` | `10` | Timeout (sec). |
| `VAP_NVD_MAX_CVES` | `20` | Max CVE per query. |

## ExploitDB

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_EXPLOITDB_SEARCHSPLOIT_PATH` | `searchsploit` | Binario searchsploit. |
| `VAP_EXPLOITDB_TIMEOUT` | `10` | Timeout (sec). |
| `VAP_EXPLOITDB_MAX_CVES` | `20` | Max CVE per query. |

## Threat intelligence feeds (aggiornamento all'avvio)

Aggiornamento automatico di vulnerabilità e definizioni scanner da **fonti
ufficiali** (NVD/NIST, CISA KEV, FIRST.org EPSS, template Nuclei, Exploit-DB).
Vedi la pagina [Threat Intelligence Feeds](threat-intelligence-feeds.md) per i
dettagli sul funzionamento e sulla cache locale.

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_FEED_UPDATE_ENABLED` | `true` | Abilita/disabilita l'intero sottosistema feed. |
| `VAP_FEED_UPDATE_ON_STARTUP` | `true` | Aggiorna i feed all'avvio (in background, non bloccante). |
| `VAP_FEED_UPDATE_INTERVAL_HOURS` | `12` | Intervallo dell'aggiornamento periodico. |
| `VAP_FEED_MIN_REFRESH_MINUTES` | `360` | Intervallo minimo tra due refresh (anti-stale). |
| `VAP_FEED_UPDATE_TIMEOUT` | `60` | Timeout per ogni download/aggiornamento (sec). |
| `VAP_FEEDS_DIR` | `feeds` | Directory della cache locale dei feed. |
| `VAP_FEED_SOURCES` | `""` | Fonti da aggiornare (CSV). Vuoto = tutte. |
| `VAP_FEED_CACHE_ENABLED` | `true` | Usa la cache locale (KEV/NVD) nell'enrichment. |
| `VAP_NVD_RECENT_WINDOW_DAYS` | `7` | Finestra (giorni) per il corpus NVD recente. |
| `VAP_NVD_FEED_MAX_RESULTS` | `2000` | Dimensione pagina del corpus NVD. |
| `VAP_CISA_KEV_FEED_URL` | URL ufficiale CISA | Sorgente del catalogo KEV. |
| `VAP_EPSS_FEED_URL` | `https://api.first.org/data/v1/epss` | Sorgente EPSS. |

## False Positive Model

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_FP_MEDIUM_THRESHOLD` | `0.4` | Soglia medio. |
| `VAP_FP_HIGH_THRESHOLD` | `0.7` | Soglia alto. |

## Celery & Redis

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_CELERY_BROKER_URL` | `redis://localhost:6379/0` | Broker Celery. |
| `VAP_CELERY_RESULT_BACKEND` | `redis://localhost:6379/1` | Result backend. |
| `VAP_CELERY_DEFAULT_QUEUE` | `scans` | Coda di default. |
| `VAP_CELERY_WORKER_CONCURRENCY` | `4` | Concorrenza worker. |
| `VAP_CELERY_TASK_TIME_LIMIT` | `900` | Hard limit task (sec). |
| `VAP_CELERY_TASK_SOFT_TIME_LIMIT` | `840` | Soft limit task (sec). |
| `VAP_CELERY_RESULT_EXPIRES` | `3600` | TTL result (sec). |

## API cache

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_API_CACHE_ENABLED` | `true` | Abilita cache API. |
| `VAP_API_CACHE_REDIS_URL` | `redis://localhost:6379/2` | Redis per cache. |
| `VAP_API_CACHE_TTL` | `30` | TTL cache (sec). |
| `VAP_API_CACHE_PREFIX` | `vap:api` | Prefix chiavi. |

## Scheduler & WebSocket

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `VAP_SCHEDULED_SCANS` | `[]` | Scansioni schedulate. |
| `VAP_WEBSOCKET_POLL_SECONDS` | `2.0` | Polling WebSocket. |

## Riferimenti ufficiali

- dotenv: https://pypi.org/project/python-dotenv/
- FastAPI: https://fastapi.tiangolo.com/
- Celery: https://docs.celeryq.dev/
- Redis: https://redis.io/docs/
