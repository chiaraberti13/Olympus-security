# Minerva — Incident response & triage (DFIR)

> **🇮🇹 Italiano** · [🇬🇧 English below](#-english)

## 🇮🇹 Italiano

### Cosa fa
Minerva è il modulo Blue di Olympus per la **risposta agli incidenti**: aggrega Alert e
Finding da altri moduli in un `core.Incident`, lo porta lungo un ciclo di vita di risposta
formale, e mantiene una **chain of custody** delle evidenze a prova di manomissione — la
disciplina che distingue un vero processo DFIR dal semplice "chiudere il ticket".

- **Apertura incidente** — `open_incident()` aggrega Alert/Finding correlati in un
  `core.Incident`, con severità pari alla più alta tra tutti gli oggetti collegati.
- **Chain of custody hash-chained** — ogni voce del log include l'hash SHA-256 del proprio
  contenuto più l'hash della voce precedente; `verify()` rileva qualunque manomissione
  (contenuto alterato, voci riordinate, hash falsificato) — la stessa tecnica delle
  blockchain, applicata a un log append-only senza bisogno di consenso distribuito.
- **Macchina a stati** — `NEW → TRIAGED → CONTAINED → RESOLVED → CLOSED`, un passo alla
  volta; la chiusura diretta da qualunque stato non chiuso è permessa (falso positivo), ma
  saltare uno stato attivo o tornare indietro viene rifiutato.

### Comandi
```bash
# Demo reale, offline, su un incidente sintetico "Olympus Demo Corp"
olympus minerva demo
```

### Output
Il demo apre un incidente da un alert Apollo (brute force) e un finding Helios (RDP
esposto), lo porta attraverso l'intero ciclo di vita registrando ogni passo nella chain of
custody, verifica l'integrità della catena, ed esporta il report completo in
`examples/output/minerva-incident.json` — un oggetto JSON con `incident` (conforme a
`olympus.core.Incident`) e `chain_of_custody`.

### Esempi
`examples/output/minerva-incident.json` è l'output reale prodotto da `minerva demo`.

### Etica
Nessun dato reale: l'incidente demo è interamente sintetico
(`olympus.minerva.demo_data`), nessun sistema o utente reale coinvolto.

---

## 🇬🇧 English

### What it does
Minerva is Olympus's Blue module for **incident response**: it aggregates Alerts and
Findings from other modules into a `core.Incident`, walks it through a formal response
lifecycle, and maintains a tamper-evident **chain of custody** for evidence — the
discipline that separates a real DFIR process from just "closing the ticket."

- **Incident opening** — `open_incident()` aggregates related alerts/findings into a
  `core.Incident`, with severity set to the highest among all linked objects.
- **Hash-chained chain of custody** — each log entry includes the SHA-256 hash of its own
  content plus the previous entry's hash; `verify()` detects any tampering (altered
  content, reordered entries, forged hash) — the same technique blockchains use, applied to
  a plain append-only log with no distributed consensus needed.
- **State machine** — `NEW → TRIAGED → CONTAINED → RESOLVED → CLOSED`, one step at a time;
  closing directly from any non-closed state is allowed (false positive), but skipping an
  active step or moving backward is rejected.

### Commands
```bash
# Real, offline demo on a synthetic "Olympus Demo Corp" incident
olympus minerva demo
```

### Output
The demo opens an incident from an Apollo alert (brute force) and a Helios finding
(exposed RDP), walks it through the full lifecycle recording each step in the chain of
custody, verifies the chain's integrity, and exports the full report to
`examples/output/minerva-incident.json` — a JSON object with `incident` (conforming to
`olympus.core.Incident`) and `chain_of_custody`.

### Examples
`examples/output/minerva-incident.json` is the real output produced by `minerva demo`.

### Ethics
No real data: the demo incident is entirely synthetic
(`olympus.minerva.demo_data`), no real system or user involved.
