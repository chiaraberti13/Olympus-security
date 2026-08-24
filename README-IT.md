<div align="center">

```
  ___  _  _   _ __  __ ___ _   _ ___
 / _ \| || | | |  \/  | _ \ | | / __|
| (_) | || |_| | |\/| |  _/ |_| \__ \
 \___/|____\__, |_|  |_|_|  \___/|___/
           |___/
```

# 🏛️ Olympus Security

**Una sola CLI per l'intero ingaggio — recon, assessment, supporto all'exploitation, detection e reporting.**
*Un unico binario, un contratto dati condiviso, offline-first e sicuro-per-scope per progettazione.*

<p align="center">
  <a href="README.md">🇬🇧 English</a> | <a href="README-IT.md">🇮🇹 Italiano</a>
</p>

<p align="center">
  <a href="https://github.com/chiaraberti13/olympus-security/actions"><img src="https://img.shields.io/badge/CI-GitHub%20Actions-blue?style=for-the-badge" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?style=for-the-badge" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/moduli-10-blue?style=for-the-badge" alt="10 moduli">
</p>

</div>

> [!IMPORTANT]
> **Solo per test di sicurezza autorizzati, ricerca e formazione.**
> Ogni comando che opera in rete valida il proprio bersaglio contro uno scope
> di ingaggio esplicito e blocca (registrandolo) tutto ciò che è fuori scope.
> Sei l'unico responsabile di un uso **lecito e con autorizzazione documentata**
> di Olympus. Leggi la **[nota legale](#-uso-legale-ed-etico)** prima dell'uso.

---

## Navigazione rapida

- **[Cos'è Olympus?](#cosè-olympus)** — cosa fa, e a chi si rivolge.
- **[Moduli](#-moduli)** — ogni tool, cosa fa e il suo punto d'ingresso.
- **[Installazione](#-installazione)** — un solo comando, Python 3.11+.
- **[Avvio rapido](#-avvio-rapido)** — un percorso verificato recon → assessment → report.
- **[Configurazione](#-configurazione)** — file di scope, config e segreti.
- **[Struttura del progetto](#-struttura-del-progetto)** — com'è organizzato il repository.
- **[Sviluppo](#-sviluppo)** — strumenti di qualità opzionali (mai un gate).
- **[Modello di sicurezza](#-modello-di-sicurezza)** — scope, autorizzazione, SSRF, audit.
- **[Migrazione](#-migrazione)** — ARGUS e la Vulnerability Assessment Platform.
- **[Licenza](#-licenza)** — MIT, per l'intero repository.
- **[Uso legale ed etico](#-uso-legale-ed-etico)** — solo autorizzato, in pratica.

---

## Cos'è Olympus?

Olympus è una piattaforma di sicurezza offensiva-e-difensiva pilotata da un
unico binario. Invece di un cassetto di script scollegati, ogni capacità è un
sotto-comando di una sola CLI e parla lo **stesso contratto dati** — lo stesso
`Asset`, `Finding`, `Event`, `Evidence`, `Alert` e `Incident` prodotto da un
modulo può essere consumato da qualsiasi altro senza conversioni.

Due regole di progettazione attraversano l'intero progetto:

- **Offline-first, I/O iniettato.** La logica di dominio non parla mai
  direttamente con la rete; dipende da piccole porte tipizzate (client HTTP,
  resolver DNS, tool runner) così i test sono deterministici e offline, mentre
  in produzione si inietta il trasporto reale.
- **Sicuro-per-scope per costruzione.** Ogni comando che tocca un bersaglio
  reale lo verifica prima contro uno scope autorizzato esplicito, blocca i
  bersagli fuori scope e scrive un record di audit — mai uno scarto silenzioso.

```console
$ olympus --help
$ olympus argus dns --domain example.com --scope scope.json
$ olympus athena run plan.json --storage ./.athena
```

## 🧰 Moduli

| Modulo | Punto d'ingresso | Cosa fa |
| --- | --- | --- |
| **Argus** | `olympus argus` | OSINT & recon passivo: DNS, WHOIS/RDAP, header web, IP, telefono, email, MAC, account, CDN fronting, grafi di investigazione. |
| **Athena** | `olympus athena` | **Orchestrazione e ciclo di vita** dell'assessment: piani validati, esecuzione job limitata, storage SQLite durevole, audit trail, reporting. |
| **Helios** | `olympus helios` | Scansione della superficie in scope ed export dei finding. |
| **Artemis** | `olympus artemis` | Probing di applicazioni web (fingerprint, contenuti, XSS) in scope. |
| **Proteus** | `olympus proteus` | Modellazione di campagne di social engineering (autorizzate, simulate). |
| **Hermes** | `olympus hermes` | Scansione di segreti e dati sensibili con output SARIF. |
| **Apollo** | `olympus apollo` | Motore di regole di detection (red/blue) su eventi normalizzati. |
| **Minerva** | `olympus minerva` | Triage degli incidenti e catena di custodia. |
| **Vulcan** | `olympus vulcan` | Aggregazione, deduplica, ranking e rendering dei report. |
| **core** | `olympus core` | Utility del contratto dati condiviso (es. `export-schemas`). |
| **ARGUS (completo)** | `olympus argus-native` | La CLI OSINT ARGUS standalone completa, importata verbatim in `vendor/` — tutti i sottocomandi originali più il menu interattivo. |
| **VAP (completo)** | `olympus vap` | La Vulnerability Assessment Platform completa, importata verbatim — web app FastAPI, tutti i **24 scanner**, database + migrazioni, report. |

> [!TIP]
> Esegui qualsiasi modulo con `--help` per vederne i comandi, oppure
> `olympus <modulo> <comando> --help` per le opzioni di un comando.

## 🚀 Installazione

Olympus richiede **Python 3.11+**.

```bash
git clone https://github.com/chiaraberti13/olympus-security
cd olympus-security
python -m pip install -e ".[dev]"      # oppure: make install
olympus --version
```

## 🎯 Avvio rapido

Ogni comando attivo in rete richiede un file di scope che nomina i domini che
sei autorizzato a toccare:

```bash
cat > scope.json <<'JSON'
{ "engagement": "demo-2026", "allowed_domains": ["example.com"] }
JSON
```

Recon passivo con Argus (scrive un bundle `core.Asset`/`core.Finding`):

```bash
olympus argus dns   --domain example.com --scope scope.json
olympus argus whois --domain example.com --scope scope.json
olympus argus web   --url https://example.com --scope scope.json --output web.json
```

Orchestra un intero assessment con Athena, poi leggi i risultati:

```bash
olympus athena plan validate examples/input/athena-plan.json
olympus athena run examples/input/athena-plan.json --storage ./.athena --report
olympus athena status <ASSESSMENT_ID> --storage ./.athena
```

Athena esce con `0` (pulito), `1` (finding/parziale), `2` (input non valido),
`3` (negazione di scope) o `4` (errore d'esecuzione), quindi si integra bene in
CI e negli script.

## ⚙️ Configurazione

- **File di scope** (JSON) autorizzano i bersagli per ingaggio:
  `{"engagement": "...", "allowed_domains": [...], "excluded_domains": [...]}`.
  Gli scope IP/telefono/account di Argus usano chiavi proprie — vedi
  [`examples/input/`](examples/input).
- **`olympus.toml`** (opzionale) imposta i default HTTP condivisi; l'ordine di
  risoluzione è `OLYMPUS_CONFIG` → `./olympus.toml` → `~/.olympus.toml`.
- **I segreti** sono letti solo da variabili d'ambiente (es.
  `OLYMPUS_NUMVERIFY_KEY`) e **non** vengono mai loggati, esportati o inseriti
  nei report.

## 🗂️ Struttura del progetto

```text
src/olympus/
├── cli.py            # punto d'ingresso unificato `olympus`
├── core/             # contratto dati condiviso: modelli, enum, http, config, ids
├── argus/            # OSINT & recon passivo (incl. integrazione ARGUS)
├── athena/           # orchestrazione degli assessment (integrazione VAP)
│   ├── domain/       # piani, job, macchine a stati, audit immutabili
│   ├── application/  # coordinator, registry, use case di planning
│   ├── adapters/     # sqlite, audit, reporting e adapter dei tool
│   └── cli.py
├── helios/ artemis/ proteus/ hermes/ apollo/ minerva/ vulcan/
docs/                 # architettura (ADR), manifest di parità, reference
examples/             # file di scope, piani, input/output di esempio
tests/                # test unitari e di contratto, offline e deterministici
```

## 🧪 Sviluppo

Gli strumenti di qualità sono **opzionali** e non bloccano mai il lavoro: lint,
type checking, test e copertura sono aiuti, non un gate di completamento. Un
tool è "completo" quando ha parità funzionale al 100% — non quando passa un gate.

```bash
make lint      # ruff (opzionale)
make type      # mypy   (opzionale)
make test      # pytest (opzionale)
make check     # esegue tutti e tre, non bloccante — solo informativo
```

Vedi [`docs/architecture/`](docs/architecture) per le decisioni di progetto
accettate, [`docs/parity/`](docs/parity) per i manifest di capacità upstream e
[`vendor/`](vendor) per i tool upstream completi, dentro il repository.

## 🔐 Modello di sicurezza

- **Enforcement dello scope** prima di ogni lookup reale; i bersagli bloccati
  vengono registrati in audit.
- **Autorizzazione esplicita** (`--i-am-authorized`) per l'OSINT sensibile alla
  privacy (es. enrichment di telefono/email su una persona reale).
- **Guardia SSRF**: gli adapter di Athena rifiutano i bersagli che risolvono a
  IP non globali e ri-validano lo scope prima di ogni richiesta.
- **Esecuzione limitata**: timeout/retry/rate limit HTTP condivisi, e in Athena
  concorrenza, timeout per-job e deadline complessive con massimi sicuri.
- **Audit trail con redazione**: eventi append-only con soli metadati in
  allowlist — mai credenziali, corpi di risposta o finding grezzi.

## 🔁 Migrazione & tool importati

Il toolkit OSINT **ARGUS** e la **Vulnerability Assessment Platform** standalone
sono implementati **dentro questo repository** — nessun submodule, wrapper o CLI
esterna a runtime. Il **codice sorgente upstream completo e non modificato** di
ciascuno è importato sotto [`vendor/`](vendor) e collegato a `olympus` come
comandi di prima classe, così i repository originali possono essere cancellati
senza perdere nulla:

```bash
bash scripts/setup-vendored-tools.sh      # installa le dipendenze di entrambi

olympus argus-native --help               # la CLI ARGUS completa (verbatim)
olympus argus-native ip 8.8.8.8

olympus vap scanners                      # tutti i 24 scanner
olympus vap migrate                       # applica le migrazioni DB di VAP
olympus vap serve --host 127.0.0.1 --port 8000   # avvia la web app VAP completa
```

I **binari** degli scanner esterni (nmap, nuclei, sqlmap, wpscan, …) e il
runtime completo (Redis/Celery) sono forniti in modo riproducibile dai file
`installer.sh` e `docker-compose.yml` importati; uno scanner senza binario
presente segnala uno stato chiaro "tool non installato" invece di fallire in
silenzio.

Olympus offre anche re-implementazioni **native**: `olympus argus …` (OSINT
scope-first) e `olympus athena …` (orchestrazione degli assessment). I loro
contratti di capacità e la provenienza sono in [`docs/parity/`](docs/parity) e
[`docs/provenance.md`](docs/provenance.md); l'architettura di Athena è
[ADR-002](docs/architecture/adr-002-athena-target-architecture.md). Le procedure
esaustive sono in [`docs/reference.md`](docs/reference.md).

## 📄 Licenza

MIT — vedi [LICENSE](LICENSE). La stessa licenza copre l'intero repository,
incluse le integrazioni in-repository di ARGUS e della Vulnerability Assessment
Platform.

## ⚠️ Uso legale ed etico

Olympus effettua test di sicurezza **autorizzati**. I moduli passivi
interrogano solo informazioni pubblicamente disponibili; i moduli attivi si
connettono solo a bersagli dentro uno scope dichiarato. Usalo esclusivamente
dove hai **permesso documentato** (i tuoi sistemi, un ingaggio firmato o un lab
che controlli). L'uso improprio è responsabilità esclusivamente tua.
