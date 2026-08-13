# Apollo — Detection engineering (SIEM-lite)

> **🇮🇹 Italiano** · [🇬🇧 English below](#-english)

## 🇮🇹 Italiano

### Cosa fa
Apollo è il modulo Blue di Olympus per il **detection engineering**: regole dichiarative in
YAML, mappate a **MITRE ATT&CK**, valutate contro un flusso di `core.Event` — e, cosa che
distingue un vero programma di detection engineering da una lista di regex, un **harness di
detection testing** che tiene le regole oneste nel tempo.

- **Regole YAML** — `rule_id`, `event_type`, `mitre_technique_id` (validato nel formato
  `T1234[.001]`), condizioni `field`/`equals`/`contains` in AND, severità.
- **Motore di match** — semantica esplicita e semplice: stesso `event_type` + tutte le
  condizioni soddisfatte. Niente wildcard, niente scoring: la complessità deve crescere nelle
  regole, non nel motore.
- **Generazione Alert con evidence linking** — ogni evento che soddisfa una regola produce
  un `core.Alert` che referenzia l'`event_id` scatenante tramite un `core.Evidence`, così un
  alert è sempre tracciabile fino all'evento esatto che lo ha generato.
- **Detection testing** — ogni regola può portare con sé una manciata di eventi sintetici
  etichettati "deve scattare" / "non deve scattare"; l'harness segnala ogni scostamento
  invece di fidarsi ciecamente della regola.

### Comandi
```bash
# Demo reale, offline, su un log di autenticazione sintetico "Olympus Demo Corp"
olympus apollo demo
```
*(Non c'è ancora un comando `apollo scan` interattivo: il motore è pensato per essere
integrato come libreria da altri moduli/pipeline; il comando `demo` ne mostra il flusso
completo end-to-end.)*

### File di regola
```yaml
rule_id: APOLLO-BRUTE-FORCE-001
name: Repeated authentication failure
event_type: authentication
mitre_technique_id: T1110
severity: high
conditions:
  - field: outcome
    equals: failure
```
Vedi `examples/input/apollo-rules/brute-force.yaml`.

### Output
Il demo scrive gli eventi sintetici in `examples/output/apollo-events.json` e gli alert
generati (con evidence linking) in `examples/output/apollo-alerts.json`, entrambi conformi
agli schemi `olympus.core` (`Event`, `Alert`).

### Esempi
`examples/input/apollo-rules/` contiene la regola reale usata dal demo;
`examples/output/apollo-events.json` e `examples/output/apollo-alerts.json` sono l'output
reale prodotto da `apollo demo`.

### Etica
Nessun dato reale: il log di autenticazione è interamente sintetico
(`olympus.apollo.demo_data`), nessun utente o sistema reale coinvolto.

---

## 🇬🇧 English

### What it does
Apollo is Olympus's Blue module for **detection engineering**: declarative YAML rules
mapped to **MITRE ATT&CK**, evaluated against a `core.Event` stream — and, what actually
separates a real detection-engineering program from a pile of regexes, a **detection
testing harness** that keeps rules honest over time.

- **YAML rules** — `rule_id`, `event_type`, `mitre_technique_id` (validated against the
  `T1234[.001]` shape), `field`/`equals`/`contains` conditions in AND, a severity.
- **Matching engine** — explicit, simple semantics: same `event_type` + every condition
  satisfied. No wildcards, no scoring: complexity is expected to grow in the rules, not the
  engine.
- **Alert generation with evidence linking** — every event that satisfies a rule produces a
  `core.Alert` referencing the triggering `event_id` through a `core.Evidence`, so an alert
  can always be traced back to the exact event that raised it.
- **Detection testing** — each rule can ship with a small set of synthetic events labeled
  "should fire" / "should not fire"; the harness reports any mismatch instead of trusting
  the rule blindly.

### Commands
```bash
# Real, offline demo on a synthetic "Olympus Demo Corp" authentication log
olympus apollo demo
```
*(There is no interactive `apollo scan` command yet: the engine is meant to be consumed as
a library by other modules/pipelines; `demo` shows its full end-to-end flow.)*

### Rule file
```yaml
rule_id: APOLLO-BRUTE-FORCE-001
name: Repeated authentication failure
event_type: authentication
mitre_technique_id: T1110
severity: high
conditions:
  - field: outcome
    equals: failure
```
See `examples/input/apollo-rules/brute-force.yaml`.

### Output
The demo writes the synthetic events to `examples/output/apollo-events.json` and the
generated alerts (with evidence linking) to `examples/output/apollo-alerts.json`, both
conforming to the `olympus.core` schemas (`Event`, `Alert`).

### Examples
`examples/input/apollo-rules/` holds the real rule the demo uses;
`examples/output/apollo-events.json` and `examples/output/apollo-alerts.json` are the real
output produced by `apollo demo`.

### Ethics
No real data: the authentication log is entirely synthetic
(`olympus.apollo.demo_data`), no real user or system involved.
