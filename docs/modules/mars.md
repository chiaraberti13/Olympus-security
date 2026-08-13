# Mars — Cyber range & purple lab

> **🇮🇹 Italiano** · [🇬🇧 English below](#-english)

## 🇮🇹 Italiano

### Cosa fa
Mars è il capstone Purple di Olympus: un **ambiente bersaglio Docker segmentato** su cui
puntare gli strumenti reali della suite, più uno **scenario purple end-to-end** che li
attraversa tutti mantenendo gli ID tracciabili — la prova che il contratto dati condiviso
(`olympus.core`) funziona davvero, non solo sulla carta.

A differenza degli altri moduli, Mars non è un pacchetto `src/olympus/mars` con un comando
`olympus mars ...`: è un ambiente (`labs/mars/`) più una suite di test di integrazione
(`tests/integration/`).

- **Range Docker segmentato** — un target nginx sintetico "Olympus Demo Corp",
  deliberatamente configurato male (header di sicurezza mancanti, CORS permissivo,
  `.env` esposto) su una rete `internal: true` (nessun accesso Internet in uscita),
  raggiungibile solo dall'host dell'operatore tramite la porta pubblicata.
- **Scenario purple offline** — `tests/integration/test_purple_scenario.py` fa attraversare
  a un'unica identità target sintetica Argus → Helios → Artemis → Apollo → Vulcan →
  Minerva, usando i doppi offline che ogni modulo già usa per il proprio `demo` (nessuna
  rete reale, nessun daemon Docker richiesto) — eseguito da `make check`.
- **Comandi Makefile sicuri** — `make mars-up`/`mars-down`/`mars-status`, ciascuno
  applicato esclusivamente al progetto Compose `mars`.

### Comandi
```bash
# Range Docker reale (richiede un daemon Docker in esecuzione)
make mars-up
make mars-status
olympus artemis scan --url http://localhost:8080 --scope labs/mars/scope-artemis.json
olympus helios scan --target 127.0.0.1 --scope labs/mars/scope-helios.json
make mars-down

# Scenario purple offline, sempre eseguito dal gate
make check   # include tests/integration/test_purple_scenario.py
```

### Perché non un daemon Docker nel gate
`make check` non richiede né avvia mai un daemon Docker: gli ambienti CI non sempre ne
hanno uno disponibile, e la disciplina del progetto è che `make check` deve restare
deterministico e offline. La validazione del compose file usa `docker compose config`
(analisi statica, non richiede il daemon); la logica di integrazione reale è invece
verificata offline nello scenario purple, riusando gli stessi doppi (`DemoResolver`,
`DemoScanner`, `DemoClient`...) di ogni modulo.

### Esempi
`labs/mars/scope-helios.json` e `labs/mars/scope-artemis.json` sono i file di scope da
usare puntando Helios/Artemis al range reale una volta avviato.

### Etica
Solo dati sintetici ("Olympus Demo Corp"). Il range è isolato (rete `internal`, nessun
accesso a Internet), non distruttivo (contenuto statico, nessuna logica applicativa), e
riproducibile da zero in qualunque momento con `make mars-down && make mars-up`.

---

## 🇬🇧 English

### What it does
Mars is Olympus's Purple capstone: a **segmented Docker target environment** to point the
suite's real tools at, plus an **end-to-end purple scenario** that walks through every one
of them while keeping traceable ids — proof the shared data contract (`olympus.core`)
actually works, not just on paper.

Unlike other modules, Mars isn't a `src/olympus/mars` package with an `olympus mars ...`
command: it's an environment (`labs/mars/`) plus an integration test suite
(`tests/integration/`).

- **Segmented Docker range** — a synthetic "Olympus Demo Corp" nginx target, deliberately
  misconfigured (missing security headers, permissive CORS, exposed `.env`) on an
  `internal: true` network (no outbound internet access), reachable only from the
  operator's own host via the published port.
- **Offline purple scenario** — `tests/integration/test_purple_scenario.py` walks a single
  synthetic target identity through Argus -> Helios -> Artemis -> Apollo -> Vulcan ->
  Minerva, using the same offline doubles each module already uses for its own `demo` (no
  real network, no Docker daemon required) — run by `make check`.
- **Safe Makefile commands** — `make mars-up`/`mars-down`/`mars-status`, each scoped
  exclusively to the `mars` Compose project.

### Commands
```bash
# Real Docker range (requires a running Docker daemon)
make mars-up
make mars-status
olympus artemis scan --url http://localhost:8080 --scope labs/mars/scope-artemis.json
olympus helios scan --target 127.0.0.1 --scope labs/mars/scope-helios.json
make mars-down

# Offline purple scenario, always run by the gate
make check   # includes tests/integration/test_purple_scenario.py
```

### Why no Docker daemon in the gate
`make check` never requires or starts a Docker daemon: CI environments don't always have
one available, and the project's discipline is that `make check` must stay deterministic
and offline. Compose file validation uses `docker compose config` (static analysis, no
daemon needed); the real integration logic is instead verified offline in the purple
scenario, reusing every module's own doubles (`DemoResolver`, `DemoScanner`,
`DemoClient`...).

### Examples
`labs/mars/scope-helios.json` and `labs/mars/scope-artemis.json` are the scope files to use
when pointing Helios/Artemis at the real range once it's running.

### Ethics
Synthetic data only ("Olympus Demo Corp"). The range is isolated (`internal` network, no
internet access), non-destructive (static content, no application logic), and can be torn
down and rebuilt from scratch at any time with `make mars-down && make mars-up`.
