# PLAN — Olympus Security (auto-correcting build plan)

> 🇮🇹/🇬🇧 Backlog di potenziamento per modulo. Il motore resta il loop auto-correttivo:
> `PLAN → BUILD → VERIFY → TEST → CHECK → LOG → RESOLVE → GATE`. Regola d'oro:
> **"Verde o non fatto" / "Green or not done"**.

## 🇮🇹 Come funziona il motore
Lo stato vive nei file, non nel prompt: `PLAN.md` (rotta), `TASKS.md` (backlog), `ERRORS.md`
(fallimenti). Due regole chiudono il ciclo:
1. Ogni fallimento diventa una voce in `ERRORS.md`.
2. Ogni voce **APERTA** in `ERRORS.md` diventa un nuovo task in `TASKS.md`.
Il loop termina quando `TASKS.md` non ha task aperti, `ERRORS.md` non ha voci APERTE e i tre
gate sono verdi (`make check`).

## 🇬🇧 How the engine works
State lives in files, not in the prompt: `PLAN.md` (route), `TASKS.md` (backlog), `ERRORS.md`
(failures). Two rules close the loop:
1. Every failure becomes an entry in `ERRORS.md`.
2. Every **OPEN** entry in `ERRORS.md` becomes a new task in `TASKS.md`.
The loop ends when `TASKS.md` has no open tasks, `ERRORS.md` has no OPEN entries and the three
gates are green (`make check`).

## Gate / Quality gates
`ruff check .` · `mypy .` (strict) · `pytest` (coverage ≥ 90%). Nessun secret nel repo.

## 📦 Release 1.0.0 (storico / history)
Le ondate fondative W0–W4 (9 moduli, scenario purple cross-modulo, build riproducibile) sono
chiuse e non sono più tracciate qui: la cronologia completa resta in
[CHANGELOG.md](CHANGELOG.md). Da qui in avanti `PLAN.md`/`TASKS.md` tracciano solo il
**backlog di potenziamento**, organizzato per modulo invece che per ondata cronologica.

The foundational waves W0–W4 (9 modules, cross-module purple scenario, reproducible build)
are closed and no longer tracked here: the full history lives in
[CHANGELOG.md](CHANGELOG.md). From here on `PLAN.md`/`TASKS.md` track only the
**enhancement backlog**, organized per module instead of by chronological wave.

## 🔌 Fonti esterne integrate / External sources integrated
Concetti da progetti esterni reimplementati (non copiati) nella disciplina Olympus — vedi
`TASKS.md` (T-230..T-235) e il modello di sicurezza in [SECURITY.md](SECURITY.md): phone
OSINT + account enumeration in Argus, regola Apollo e check Artemis per la CVE Metabase
(CVE-2026-72898). `hackingtool` è **escluso per design** (DDoS/RAT/payload/evasion).

External-project concepts reimplemented (not copied) under Olympus's discipline — see
`TASKS.md` (T-230..T-235) and the security model in [SECURITY.md](SECURITY.md): phone OSINT +
account enumeration in Argus, an Apollo rule and an Artemis check for the Metabase CVE
(CVE-2026-72898). `hackingtool` is **excluded by design** (DDoS/RAT/payload/evasion).

## 🔧 Backlog di potenziamento per modulo / Per-module enhancement backlog

Ogni direttrice qui sotto ha i task puntuali corrispondenti in `TASKS.md` (`T-2xx`, non
spuntati). Nessun task è iniziato: sono proposte da validare una alla volta seguendo lo
stesso ciclo PLAN→BUILD→VERIFY→TEST→CHECK→LOG→RESOLVE→GATE già usato per W0–W4.

Each item below has corresponding itemized tasks in `TASKS.md` (`T-2xx`, unchecked). None
are started: they are proposals to validate one at a time, following the same
PLAN→BUILD→VERIFY→TEST→CHECK→LOG→RESOLVE→GATE cycle already used for W0–W4.

### Argus (🔴 OSINT)
- WHOIS/ASN passivo (ownership IP/dominio) come fonte OSINT aggiuntiva, best-effort come CT
- Fingerprint tecnologico passivo via header HTTP (server, framework) senza probing attivo

### Hermes (🔵 Secret scanner)
- Nuovi pattern/prefissi di secret provider (es. Slack, Stripe, GCP service account)
- Confronto/merge dell'output SARIF con altri tool di scansione per un report unificato

### Helios (🔴 Network attack-surface mapper)
- Banner/service fingerprinting opzionale sulle porte aperte (best-effort, non intrusivo)

### Apollo (🔵 Detection engineering)
- Rule-pack MITRE ATT&CK ampliato oltre a T1110 (Brute Force): T1110.003 (Password
  Spraying), T1595 (Active Scanning), T1071 (C2 su porte comuni), T1078 (Valid Accounts
  anomaly)

### Artemis (🔴 Web recon)
- Ulteriori controlli header di sicurezza (Permissions-Policy, Referrer-Policy)
- Lista path di content discovery estesa (backup, config di framework comuni)

### Minerva (🔵 IR/DFIR)
- Export report incidente in formati aggiuntivi oltre al JSON conforme a core

### Proteus (🔴 Phishing sim, mai credenziali reali)
- Più varianti di template campagna/training page (oggi una sola), sempre senza raccolta
  credenziali reale

### Vulcan (🟣 Aggregazione + report pentest)
- Export HTML del pentest report, riusando i dati già aggregati in `aggregate.py`/`risk.py`
- Filtro severità minima configurabile da CLI per il report

### Mars (🟣 Cyber range + scenari purple)
- Verifica opzionale in CI quando un daemon Docker è disponibile (self-hosted runner), oltre
  alla sola validazione strutturale attuale (`docker compose config`)
- Segmentazione di rete aggiuntiva nel range (oltre alla singola rete `dmz` attuale)

### Cross-cutting / DevEx
- CI: matrix su più versioni Python (3.11/3.12) in `.github/workflows/ci.yml`
- Badge di stato CI nel `README.md`
- Packaging: pubblicazione del pacchetto (build già riproducibile, manca solo il publish)
- Timeout e rate-limit configurabili da CLI per i client di rete (CT lookup di Argus,
  `HttpClient` di Artemis), utile con proxy/egress restrittivi

## ⏸️ Esplicitamente rinviato / Explicitly deferred
Dashboard web, database persistente, layer API/autenticazione: nessuno di questi risolve un
problema reale del progetto oggi (CLI + JSON restano sufficienti). Rinviati per disciplina
anti-over-engineering, non dimenticati — vedi sezione sotto.

Web dashboard, persistent database, API/auth layer: none solve a real problem for this
project today (CLI + JSON remain sufficient). Deferred on anti-over-engineering grounds, not
forgotten — see the section below.

## Definition of Done (per direttrice di potenziamento / per enhancement item)
- [ ] Funzione operativa · comando `demo` reale su dati sintetici (se applicabile)
- [ ] `make check` verde (ruff + mypy strict + pytest ≥90%)
- [ ] Output conforme agli schemi di `core`, se il potenziamento produce dati
- [ ] README di modulo aggiornato (bilingue) · commenti nel codice **solo in inglese**
- [ ] (Red) scope file, blocco+log fuori scope, non distruttivo — se il potenziamento tocca
      un modulo offensivo mandatorio (Helios, Artemis, Proteus/Mars)
- [ ] `ERRORS.md` senza voci APERTE per il modulo

## Anti-over-engineering
Prima di aggiungere DB/API/broker/dashboard, rispondi: (1) quale problema risolve? (2) serve
per la prima versione? (3) basta un file JSON? (4) come lo dimostro a un recruiter? Se non
migliora utilità/affidabilità/sicurezza/chiarezza/integrazione → rinviato.
