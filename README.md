# ⛰️ Olympus Security

> **🇮🇹 Italiano** · [🇬🇧 English below](#-english)
>
> Una piattaforma di **offensive security** (Red + Blue) costruita come **monorepo**: un solo
> CLI, un contratto dati condiviso e un ciclo di sviluppo che **si testa e si corregge da
> solo**. Allineata a **CompTIA Security+ (SY0-701)**, con un profilo orientato a
> **Penetration Testing e Red Team**.

![CI](https://img.shields.io/badge/CI-ruff%20%7C%20mypy%20%7C%20pytest-informational)
![Coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

## 🇮🇹 In una frase
Olympus scopre, verifica, sfrutta (in laboratorio), rileva, risponde e **produce il report**:
lo stesso asset (`AST-2026-00001`) attraversa tutti i moduli mantenendo lo stesso ID.

## Perché esiste
Il lavoro reale di un pentester non è solo "trovare bug": è **recon metodica, rispetto delle
regole d'ingaggio, evidenze tracciabili e report scritti bene**. Olympus automatizza proprio
le parti che fanno perdere ore, dimostrando metodologia — non solo comandi.

## I moduli

| Modulo | Team | Cosa fa |
|---|---|---|
| **core** | ⚙️ | Contratto dati condiviso: modelli, ID tracciabili, schemi, validazione |
| **Argus** | 🔴 Red | OSINT e recon passiva (DNS, CT logs, metadati, change monitoring) |
| **Helios** | 🔴 Red | Attack surface mapper di rete **con scope enforcement** |
| **Artemis** | 🔴 Red | Web recon: content discovery, parametri, file esposti, header, CORS |
| **Proteus** | 🔴 Red | Simulazione phishing autorizzata (**mai credenziali reali**, solo training) |
| **Hermes** | 🔵 Blue | Secret & config scanner (regex + entropia), output SARIF, pre-commit/CI |
| **Apollo** | 🔵 Blue | Detection engineering: regole YAML mappate su MITRE ATT&CK + testing |
| **Minerva** | 🔵 Blue | Incident response & triage DFIR con chain of custody |
| **Vulcan** | 🟣 | Aggrega e deduplica i finding, CVSS, **genera il report di pentest** |
| **Mars** | 🟣 | Cyber range (Docker) + scenari purple end-to-end |

Bilanciamento: **4 Red / 3 Blue / 2 Reporting-Range**.

## Avvio rapido
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

olympus --version
olympus --help
olympus core export-schemas ./examples/output    # esporta i JSON Schema
olympus argus scan --domain example.com --scope examples/input/argus-scope.json
```

## Usabilità & configurazione
- **Formato output**: i comandi tabellari accettano `--format table|json` (es. `olympus vulcan
  rank --findings ...`): tabella leggibile o JSON da pipe.
- **Concorrenza & cortesia**: le enumerazioni di massa supportano `--concurrency` e `--rate`
  (secondi minimi tra richieste). Il client HTTP fa retry con backoff su errori transitori
  (rete, 429/5xx).
- **Config file** (opzionale): `olympus.toml` (via `$OLYMPUS_CONFIG`, `./olympus.toml` o
  `~/.olympus.toml`) per non ripetere i flag, es. `[http] timeout = 15 \n retries = 3 \n rate = 0.25`.
- **Exit code canonici**: `0` ok · `1` finding rilevati · `2` errore d'uso/input · `3` fuori
  scope (bloccato+loggato) · `4` autorizzazione mancante (`--i-am-authorized`).

## Qualità: "Verde o non fatto"
Ogni modifica passa da tre gate prima di essere considerata fatta:
```bash
make check      # ruff + mypy --strict + pytest con gate coverage portabile (≥90%)
```
Lo sviluppo segue un **loop auto-correttivo**: ogni fallimento viene registrato in
`ERRORS.md` e diventa un nuovo task in `TASKS.md`. Dettagli in [PLAN.md](PLAN.md).

## Etica e legalità
I moduli offensivi (Argus, Helios, Artemis, Proteus, Mars) servono **solo per uso
autorizzato, difensivo e formativo**. Richiedono un file di scope, bloccano e registrano
ciò che è fuori perimetro, e restano **non distruttivi**. Proteus non raccoglie mai
credenziali reali. Vedi [SECURITY.md](SECURITY.md).

## Struttura
```text
src/olympus/{core,argus,helios,artemis,proteus,hermes,apollo,minerva,vulcan}
labs/mars/            # cyber range (docker compose)
tests/{unit,integration,e2e,fixtures}
examples/             # dataset "Olympus Demo Corp" + report d'esempio
PLAN.md  TASKS.md  ERRORS.md   # il motore auto-correttivo
```

---

## 🇬🇧 English

> An **offensive-security** platform (Red + Blue) built as a **monorepo**: one CLI, a shared
> data contract, and a development loop that **tests and fixes itself**. Aligned with
> **CompTIA Security+ (SY0-701)**, with a **Penetration Testing / Red Team** focus.

### In one sentence
Olympus discovers, verifies, exploits (in a lab), detects, responds and **writes the
report**: the same asset (`AST-2026-00001`) travels across every module keeping one ID.

### Why it exists
Real pentest work isn't just "finding bugs": it's **methodical recon, respecting the rules
of engagement, traceable evidence and well-written reports**. Olympus automates the
time-consuming parts, demonstrating methodology — not just commands.

### Modules

| Module | Team | What it does |
|---|---|---|
| **core** | ⚙️ | Shared data contract: models, traceable IDs, schemas, validation |
| **Argus** | 🔴 Red | OSINT & passive recon (DNS, CT logs, metadata, change monitoring) |
| **Helios** | 🔴 Red | Network attack-surface mapper **with scope enforcement** |
| **Artemis** | 🔴 Red | Web recon: content discovery, parameters, exposed files, headers, CORS |
| **Proteus** | 🔴 Red | Authorized phishing simulation (**never real credentials**, training only) |
| **Hermes** | 🔵 Blue | Secret & config scanner (regex + entropy), SARIF output, pre-commit/CI |
| **Apollo** | 🔵 Blue | Detection engineering: YAML rules mapped to MITRE ATT&CK + testing |
| **Minerva** | 🔵 Blue | Incident response & DFIR triage with chain of custody |
| **Vulcan** | 🟣 | Aggregates & deduplicates findings, CVSS, **generates the pentest report** |
| **Mars** | 🟣 | Cyber range (Docker) + end-to-end purple scenarios |

Balance: **4 Red / 3 Blue / 2 Reporting-Range**.

### Quick start
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

olympus --version
olympus --help
olympus core export-schemas ./examples/output
olympus argus scan --domain example.com --scope examples/input/argus-scope.json
```

### Quality: "Green or not done"
Every change passes three gates before it counts as done:
```bash
make check      # ruff + mypy --strict + pytest with portable coverage gate (≥90%)
```
Development follows a **self-correcting loop**: every failure is logged in `ERRORS.md` and
becomes a new task in `TASKS.md`. See [PLAN.md](PLAN.md).

### Ethics & legality
Offensive modules (Argus, Helios, Artemis, Proteus, Mars) are for **authorized, defensive,
educational use only**. They require a scope file, block and log out-of-scope targets, and
stay **non-destructive**. Proteus never collects real credentials. See [SECURITY.md](SECURITY.md).

### License
MIT — see [LICENSE](LICENSE). All demo data is synthetic ("Olympus Demo Corp").
