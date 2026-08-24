# 🛡️ Vulnerability Assessment Platform (VAP)

> **English** | [Italiano](#-vulnerability-assessment-platform-vap--italiano)

**Learn web security hands-on _and_ run professional assessments — from a single web dashboard.**

VAP is two tools in one: a **didactic platform** that explains every choice and finding step‑by‑step, and a **professional scanner** that orchestrates 25+ industry tools, correlates findings and generates audit‑ready reports.

---

> ⚠️ **Legal Disclaimer:** Use this platform only on systems you own or for which you have explicit written authorization. Unauthorized scanning is illegal in most jurisdictions.

---

## ✨ Two ways to use it

VAP adapts to your experience level. You pick the mode in **Step 1** of the guided wizard (field *"Livello di esperienza"*). Server‑side safety guardrails stay active in every mode.

| | 🎓 **Didactic mode** | 🛠️ **Professional mode** |
|---|---|---|
| **For** | Students, juniors, anyone learning | Analysts, pentesters, security teams |
| **Level** | `Beginner` | `Analyst` / `Expert` |
| **Risk** | High‑risk modules disabled, conservative limits | Full module control, extended limits |
| **Help** | Per‑parameter explanations, glossary, learning blocks | Concise, automation‑oriented |
| **Output** | Guided interpretation of every finding | PDF reports, remediation roadmap, REST API, audit trail |

➡️ The in‑app **Guida** (`/guida`) is a full learning hub: scan catalog, learning paths, glossary and safe‑usage rules.

---

## 🚀 Quick start

```bash
# 1) Clone
git clone <repository-url> VAP && cd VAP

# 2) Install (see per-OS instructions below)
#    Linux/macOS:  ./installer.sh        Windows:  .\installer.ps1

# 3) Configure
cp .env.example .env        # then edit secrets (see "Configuration")

# 4) Run
source venv/bin/activate
python3 app.py
```

Then open **http://localhost:8000** and use the top navigation: **Nuova scansione · Storico · Guida**.

---

## 🔰 New here? Beginner walkthrough (from zero)

> Never used terminal tools before? Follow these in order:
>
> 1. **Prerequisites** — install **Python 3.10–3.12** and **Git** (check with `python3 --version` and `git --version`).
> 2. **Get the code** — `git clone <repository-url> VAP && cd VAP` (or *Code → Download ZIP* on GitHub).
> 3. **Install once** — `./installer.sh` (Linux/macOS) or `.\installer.ps1` (Windows). This creates an isolated `venv/` and installs dependencies.
> 4. **Configure** — `cp .env.example .env`; generate strong secrets with `openssl rand -hex 32` (defaults are fine for a local trial).
> 5. **Run** — `source venv/bin/activate && python3 app.py`, then open **http://localhost:8000**. VAP auto‑downloads vulnerability updates from official sources on first start (see **Guida → Fonti**).
> 6. **First scan** — *Nuova scansione* → level **Beginner** → an **authorized** target → follow the wizard → download the PDF report.
>
> **External tools are optional to start:** without Nmap/Nuclei/ZAP/etc. coverage is reduced, but the app, official‑source updates and finding enrichment still work. Missing tools are skipped without errors (many ship preinstalled on **Kali Linux**).

---

## ✅ Installation (all 3 operating systems)

This project is **not** a single‑file app: it installs once, then everyday use is straightforward.
The guided installers create a Python virtual environment and install dependencies.

### 🐧 Linux / 🍎 macOS

```bash
git clone <repository-url> VAP
cd VAP
chmod +x installer.sh
./installer.sh                 # creates venv + installs dependencies
source venv/bin/activate
cp .env.example .env
```

Supported: Ubuntu/Debian/Kali/Fedora/RHEL‑like/Arch/openSUSE and macOS 11+.

### 🪟 Windows 10/11 (PowerShell)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1                # creates venv + installs dependencies
.\venv\Scripts\Activate.ps1
copy .env.example .env
```

WSL2 is also fully supported — follow the Linux instructions inside your WSL distro.

> **Optional frontend build:** the dashboard CSS ships pre‑built. To rebuild Tailwind after editing the UI: `npm install && npm run build:css`.

---

## ⚙️ Configuration

Edit `.env` and set at least:

```env
VAP_ENV=production
VAP_CSRF_SECRET=<hex-32-bytes>
VAP_JWT_SECRET=<hex-32-bytes>
VAP_API_KEY=<strong-random-key>
VAP_REQUIRE_HTTPS=true
```

Generate strong secrets with:

```bash
openssl rand -hex 32
```

---

## ▶️ Running the app

### Minimal local mode (no queue)

```bash
source venv/bin/activate
python3 app.py
```

### Full async mode (Redis + Celery)

```bash
# Terminal A
redis-server

# Terminal B
source venv/bin/activate
celery -A celery_app worker --loglevel=info

# Terminal C
source venv/bin/activate
python3 app.py
```

Open **http://localhost:8000**.

---

## 🧭 Your first scan

1. Open the dashboard and read the **Guida** (`/guida`) if it's your first time.
2. In **Step 1**, choose your **experience level** (Beginner / Analyst / Expert) and enter an **authorized** target.
3. In **Step 2**, pick the scan type (`light`, `full`, `wordpress`, or a tool‑specific scan) and the scanner modules.
4. Review impact, risk and the compliance checklist (Steps 3–5), then start the scan.
5. Watch real‑time progress, then review findings — with **learning blocks**, **remediation roadmap** and **trend** — and download the **PDF report**.

---

## 🧩 Features

- ✅ **Guided 5‑step scan wizard** with real‑time validation and accessibility (keyboard, skip links, ARIA live regions)
- ✅ **Didactic modes** (Beginner / Analyst / Expert) with per‑parameter explanations and a built‑in glossary
- ✅ **In‑app learning hub** (`/guida`): scan catalog, learning paths, glossary, safe‑usage rules
- ✅ **Multi‑scanner orchestration** from one interface (Nmap, Nuclei, ZAP, SQLMap, WPScan, and 20+ more)
- ✅ **Scan profiles** (`light`, `full`, `wordpress`, `network`) and tool‑specific scans, organized by category (**Web · Web App · Network**)
- ✅ **Network & infrastructure scanning** (Nmap service/version detection + NSE `vulners`/`vuln`): exposed services are correlated to CVEs and enriched with CVSS/CISA KEV/EPSS
- ✅ **Always‑updated threat‑intel feeds** from official sources (NVD/NIST, CISA KEV, FIRST.org EPSS, Nuclei templates, Exploit‑DB) — refreshed **at every startup** into a local, offline‑queryable cache
- ✅ **Finding enrichment** (CVE/CWE/CVSS, NVD, ExploitDB, OWASP & MITRE ATT&CK mapping)
- ✅ **Learning blocks** on every finding (junior explanation, business risk, manual verification, next skill)
- ✅ **Remediation roadmap** ordered by impact × effort, plus **historical trend** per target
- ✅ **False‑positive scoring** and confidence rubric
- ✅ **PDF report generation** and scan history
- ✅ **REST API** for automation
- ✅ **Security controls**: CSRF, JWT/API key, hardened headers, rate limiting, audit logging
- ✅ **Extensible plugin architecture** for new scanner adapters

---

## 🗂️ Project structure

| Path | Description |
|---|---|
| `app.py` | FastAPI app — dashboard UI + REST API |
| `scanner_engine.py` | Scan orchestration and target validation |
| `scanners/` | Tool‑specific scanner plugins |
| `templates/` + `static/` | Dashboard UI (shared nav, guided wizard, scan detail, **Guida**) |
| `report_generator.py` | PDF reporting pipeline (Inter font, page-safe layout) |
| `enrichment_engine.py` | CVE/NVD/ExploitDB correlation |
| `feed_updater.py` | Threat‑intel feed manager (NVD/CISA KEV/EPSS + scanner defs), startup + scheduled refresh |
| `assets/fonts/` | Bundled Inter font used by the PDF reports |
| `tests/` | Regression and security‑focused tests |
| `installer.sh` / `installer.ps1` | Guided installers (Linux/macOS, Windows) |
| `docker-compose.yml` | Redis helper service for async workers |
| `docs/` | Architecture, security, operations, scan playbooks, learning paths |

---

## 💻 System requirements

**Runtime:** Python 3.10–3.12 · Redis 6/7 (async workers) · Go ≥ 1.19 (selected tools) · Node.js/npm (frontend build/tests only)

**Supported OS:** ✅ Linux · ✅ macOS 11+ · ✅ Windows 10/11 (native PowerShell or WSL2)

**Recommended resources:** CPU 2 cores (4+ for concurrent scans) · RAM 4 GB min (8+ GB for heavy scans) · Disk 2 GB + scan/report artifacts

> Results depend on installed tools and permissions. Some scanners need external binaries (e.g., Nmap, Nuclei, WhatWeb); enterprise scanners (Acunetix/Nessus) need valid API credentials. Without optional tools, VAP runs reduced‑coverage flows.

---

## 🛠️ Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ModuleNotFoundError` | venv not active / deps missing | `source venv/bin/activate && pip install -r requirements.txt` |
| Celery jobs don't start | Redis down / bad broker URL | start `redis-server`, verify `.env`, restart the worker |
| Empty/partial findings | tool missing / target unreachable | check scanner binary, verify reachability, try the `light` profile |
| UI loads but styling is broken | wrong working dir / static mapping | run from the repo root; verify `static/` is served |

---

## 🔐 Security & privacy

- ✅ Secrets via environment variables (`.env`)
- ✅ Security middleware and hardened response headers
- ✅ Input validation and target sanitation
- ✅ Optional JWT / API‑key protections for the API
- ✅ Audit logging for security‑relevant actions

⚠️ Scan data may include sensitive infrastructure details. Protect reports, DB files and backups with strict access controls.

---

## 📚 Documentation

- `docs/user-manual.md` — detailed user manual
- `docs/learning-paths/` — beginner / analyst / professional paths
- `docs/scan-playbooks/` — per‑scanner playbooks
- `docs/glossary-faq.md` — glossary and FAQ
- `docs/architecture.md`, `docs/security.md`, `docs/deployment.md` — operations

---

## 📄 License

Distributed under the terms of the license in [`LICENSE`](LICENSE).

---
---

# 🛡️ Vulnerability Assessment Platform (VAP) — Italiano

> [English](#-vulnerability-assessment-platform-vap) | **Italiano**

**Impara la sicurezza web sul campo _e_ conduci assessment professionali — da un'unica dashboard web.**

VAP è due strumenti in uno: una **piattaforma didattica** che spiega passo‑passo ogni scelta e ogni risultato, e uno **scanner professionale** che orchestra oltre 25 tool, correla i findings e genera report pronti per l'audit.

---

> ⚠️ **Disclaimer legale:** usa la piattaforma solo su sistemi di tua proprietà o con autorizzazione scritta esplicita. Le scansioni non autorizzate sono illegali.

---

## ✨ Due modi di usarlo

VAP si adatta al tuo livello. La modalità si sceglie nello **Step 1** del wizard guidato (campo *"Livello di esperienza"*). I guardrail di sicurezza lato server restano sempre attivi.

| | 🎓 **Modalità didattica** | 🛠️ **Modalità professionale** |
|---|---|---|
| **Per chi** | Studenti, junior, chi sta imparando | Analyst, pentester, team di sicurezza |
| **Livello** | `Beginner` | `Analyst` / `Expert` |
| **Rischio** | Moduli ad alto rischio disabilitati, limiti conservativi | Controllo completo dei moduli, limiti estesi |
| **Aiuto** | Spiegazione di ogni parametro, glossario, learning blocks | Conciso, orientato all'automazione |
| **Output** | Interpretazione guidata di ogni finding | Report PDF, remediation roadmap, API REST, audit trail |

➡️ La **Guida** integrata (`/guida`) è un hub didattico completo: catalogo scansioni, percorsi di apprendimento, glossario e regole d'uso legale.

---

## 🚀 Avvio rapido

```bash
# 1) Clona
git clone <repository-url> VAP && cd VAP

# 2) Installa (istruzioni per OS qui sotto)
#    Linux/macOS:  ./installer.sh        Windows:  .\installer.ps1

# 3) Configura
cp .env.example .env        # poi modifica i segreti (vedi "Configurazione")

# 4) Avvia
source venv/bin/activate
python3 app.py
```

Apri **http://localhost:8000** e usa la barra di navigazione in alto: **Nuova scansione · Storico · Guida**.

---

## 🔰 Primo avvio per principianti (da zero)

> Non hai mai usato strumenti da terminale? Segui questi passi nell'ordine. Ogni comando è spiegato.

### 0) Cosa ti serve prima (prerequisiti)

| Strumento | A cosa serve | Come verificarlo |
|---|---|---|
| **Python 3.10–3.12** | Esegue l'applicazione | `python3 --version` |
| **Git** | Scarica il progetto | `git --version` |
| **Connessione internet** | Scarica dipendenze e aggiornamenti delle fonti ufficiali | — |

Se Python o Git non sono installati: su **Windows** scaricali da [python.org](https://www.python.org/downloads/) e [git-scm.com](https://git-scm.com/); su **macOS** usa `brew install python git`; su **Linux Debian/Ubuntu/Kali** usa `sudo apt install python3 python3-venv git`.

### 1) Scarica il progetto

```bash
git clone <repository-url> VAP
cd VAP
```

> In alternativa puoi scaricare lo ZIP da GitHub (pulsante **Code → Download ZIP**), estrarlo e aprire un terminale dentro la cartella.

### 2) Installa (crea l'ambiente e le dipendenze)

```bash
# Linux / macOS
chmod +x installer.sh
./installer.sh
```

```powershell
# Windows (PowerShell)
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1
```

L'installer crea un **ambiente virtuale** (`venv/`, una "scatola" isolata per le librerie) e installa tutto il necessario. Lo fai **una sola volta**.

### 3) Configura i segreti (file `.env`)

```bash
cp .env.example .env          # Windows: copy .env.example .env
```

Apri `.env` con un editor di testo e imposta almeno le chiavi di sicurezza. Per generarne di robuste:

```bash
openssl rand -hex 32          # esegui una volta per ogni segreto (CSRF, JWT, API key)
```

> Per **provare in locale** puoi anche lasciare i valori di default: l'app parte comunque. I segreti robusti servono soprattutto in produzione.

### 4) Avvia l'applicazione

```bash
# Linux / macOS
source venv/bin/activate
python3 app.py
```

```powershell
# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
python app.py
```

Apri il browser su **http://localhost:8000**. Al primo avvio VAP scarica automaticamente gli aggiornamenti delle vulnerabilità dalle **fonti ufficiali** (vedi la scheda **Guida → Fonti**).

### 5) La tua prima scansione

1. Clicca **Nuova scansione**.
2. **Step 1**: scegli livello **Beginner** e inserisci un target **che sei autorizzato a testare** (es. un tuo sito di prova).
3. Segui il wizard (tipo di scansione, moduli, conferme) e avvia.
4. A fine scansione consulta i findings spiegati e scarica il **report PDF**.

### ℹ️ Nota sui tool esterni (opzionali)

VAP orchestra strumenti professionali (Nmap, Nuclei, ZAP, SQLMap, …). **Non sono obbligatori per partire**: senza di essi la copertura è ridotta, ma l'app, l'aggiornamento delle fonti ufficiali e l'enrichment dei findings funzionano comunque. Installa i singoli tool quando ti servono (su **Kali Linux** molti sono già presenti). Se un tool non è installato, il relativo modulo viene semplicemente saltato senza errori.

> Qualcosa non funziona? Vai alla sezione [Risoluzione problemi](#%EF%B8%8F-risoluzione-problemi).

---

## ✅ Installazione (tutti e 3 i sistemi operativi)

L'applicazione **richiede un'installazione iniziale** (non è un file standalone).
Gli installer guidati creano un ambiente virtuale Python e installano le dipendenze.

### 🐧 Linux / 🍎 macOS

```bash
git clone <repository-url> VAP
cd VAP
chmod +x installer.sh
./installer.sh                 # crea venv + installa dipendenze
source venv/bin/activate
cp .env.example .env
```

Supportati: Ubuntu/Debian/Kali/Fedora/RHEL‑like/Arch/openSUSE e macOS 11+.

### 🪟 Windows 10/11 (PowerShell)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1                # crea venv + installa dipendenze
.\venv\Scripts\Activate.ps1
copy .env.example .env
```

WSL2 è pienamente supportato — segui le istruzioni Linux dentro la tua distro WSL.

> **Build frontend opzionale:** la CSS della dashboard è già pre‑compilata. Per ricompilare Tailwind dopo modifiche all'UI: `npm install && npm run build:css`.

---

## ⚙️ Configurazione

Nel file `.env` imposta almeno:

```env
VAP_ENV=production
VAP_CSRF_SECRET=<hex-32-byte>
VAP_JWT_SECRET=<hex-32-byte>
VAP_API_KEY=<chiave-random-forte>
VAP_REQUIRE_HTTPS=true
```

Genera segreti robusti con:

```bash
openssl rand -hex 32
```

---

## ▶️ Avvio dell'applicazione

### Modalità locale minima (senza coda)

```bash
source venv/bin/activate
python3 app.py
```

### Modalità completa asincrona (Redis + Celery)

```bash
# Terminale A
redis-server

# Terminale B
source venv/bin/activate
celery -A celery_app worker --loglevel=info

# Terminale C
source venv/bin/activate
python3 app.py
```

Apri **http://localhost:8000**.

---

## 🧭 La tua prima scansione

1. Apri la dashboard e, se è la prima volta, leggi la **Guida** (`/guida`).
2. Nello **Step 1** scegli il **livello di esperienza** (Beginner / Analyst / Expert) e inserisci un target **autorizzato**.
3. Nello **Step 2** scegli il tipo di scansione (`light`, `full`, `wordpress` o uno scan mirato) e i moduli scanner.
4. Verifica impatto, rischio e checklist compliance (Step 3–5), poi avvia.
5. Monitora il progresso realtime, poi analizza i findings — con **learning blocks**, **remediation roadmap** e **trend** — e scarica il **report PDF**.

---

## 🧩 Caratteristiche

- ✅ **Wizard guidato in 5 step** con validazione realtime e accessibilità (tastiera, skip link, ARIA live region)
- ✅ **Modalità didattiche** (Beginner / Analyst / Expert) con spiegazione di ogni parametro e glossario integrato
- ✅ **Hub didattico integrato** (`/guida`): catalogo scansioni, percorsi, glossario, regole d'uso legale
- ✅ **Orchestrazione multi‑scanner** da un'unica interfaccia (Nmap, Nuclei, ZAP, SQLMap, WPScan e oltre 20 altri)
- ✅ **Profili di scansione** (`light`, `full`, `wordpress`, `network`) e scan mirati per singolo tool, organizzati per categoria (**Web · Web App · Rete**)
- ✅ **Scansione di rete e infrastruttura** (Nmap service/version + script NSE `vulners`/`vuln`): i servizi esposti vengono correlati a CVE e arricchiti con CVSS/CISA KEV/EPSS
- ✅ **Feed di threat intelligence sempre aggiornati** da fonti ufficiali (NVD/NIST, CISA KEV, FIRST.org EPSS, template Nuclei, Exploit‑DB) — aggiornati **a ogni avvio** in una cache locale interrogabile anche offline
- ✅ **Enrichment dei findings** (CVE/CWE/CVSS, NVD, ExploitDB, mapping OWASP e MITRE ATT&CK)
- ✅ **Learning blocks** su ogni finding (spiegazione junior, rischio business, verifica manuale, skill successiva)
- ✅ **Remediation roadmap** ordinata per impatto × effort e **trend storico** per target
- ✅ **Scoring falsi positivi** e rubrica di affidabilità
- ✅ **Generazione report PDF** e storico scansioni
- ✅ **API REST** per automazione
- ✅ **Controlli di sicurezza**: CSRF, JWT/API key, header hardenizzati, rate limiting, audit log
- ✅ **Architettura a plugin** estendibile a nuovi scanner

---

## 🗂️ Struttura del progetto

| Percorso | Descrizione |
|---|---|
| `app.py` | App FastAPI — UI dashboard + API REST |
| `scanner_engine.py` | Orchestrazione scansioni e validazione target |
| `scanners/` | Plugin scanner per singolo strumento |
| `templates/` + `static/` | Interfaccia (nav condivisa, wizard guidato, dettaglio scan, **Guida**) |
| `report_generator.py` | Pipeline report PDF (font Inter, layout page-safe) |
| `enrichment_engine.py` | Correlazione CVE/NVD/ExploitDB |
| `feed_updater.py` | Gestore feed threat‑intel (NVD/CISA KEV/EPSS + definizioni scanner), refresh all'avvio e periodico |
| `assets/fonts/` | Font Inter bundlato usato dai report PDF |
| `tests/` | Test di regressione e sicurezza |
| `installer.sh` / `installer.ps1` | Installer guidati (Linux/macOS, Windows) |
| `docker-compose.yml` | Servizio Redis per worker async |
| `docs/` | Architettura, sicurezza, operations, playbook, percorsi |

---

## 💻 Requisiti di sistema

**Runtime:** Python 3.10–3.12 · Redis 6/7 (worker async) · Go ≥ 1.19 (tool specifici) · Node.js/npm (solo build/test frontend)

**Sistemi operativi:** ✅ Linux · ✅ macOS 11+ · ✅ Windows 10/11 (PowerShell nativo o WSL2)

**Risorse consigliate:** CPU 2 core (4+ per scansioni concorrenti) · RAM 4 GB min (8+ GB per carichi pesanti) · Disco 2 GB + artefatti scansione/report

> La copertura dipende dai tool installati e dai permessi. Alcuni scanner richiedono binari esterni (Nmap, Nuclei, WhatWeb…); gli scanner enterprise (Acunetix/Nessus) richiedono API key valide. Senza i componenti opzionali, VAP opera con copertura ridotta.

---

## 🛠️ Risoluzione problemi

| Sintomo | Causa probabile | Soluzione |
|---|---|---|
| `ModuleNotFoundError` | venv non attivo / dipendenze mancanti | `source venv/bin/activate && pip install -r requirements.txt` |
| Job Celery non partono | Redis spento / broker URL errato | avvia `redis-server`, verifica `.env`, riavvia il worker |
| Findings vuoti/parziali | tool mancante / target irraggiungibile | controlla il binario, verifica raggiungibilità, prova il profilo `light` |
| UI senza stile | working dir errata / mapping static | esegui dalla root del repo; verifica che `static/` sia servito |

---

## 🔐 Privacy e sicurezza

- ✅ Segreti in variabili d'ambiente (`.env`)
- ✅ Middleware e security header hardenizzati
- ✅ Validazione input e sanitizzazione target
- ✅ Protezioni API opzionali (JWT/API key)
- ✅ Audit logging per azioni sensibili

⚠️ I dati di scansione possono essere sensibili: proteggi report, DB e backup con controlli d'accesso rigorosi.

---

## 📚 Documentazione

- `docs/user-manual.md` — manuale utente dettagliato
- `docs/learning-paths/` — percorsi beginner / analyst / professional
- `docs/scan-playbooks/` — playbook per singolo scanner
- `docs/glossary-faq.md` — glossario e FAQ
- `docs/architecture.md`, `docs/security.md`, `docs/deployment.md` — operations

---

## 📄 Licenza

Distribuito secondo la licenza indicata in [`LICENSE`](LICENSE).


© Chiara Berti 13 - 2026
