# Proteus — Authorized phishing simulation

> **🇮🇹 Italiano** · [🇬🇧 English below](#-english)

## 🇮🇹 Italiano

### Cosa fa
Proteus è il modulo Red di Olympus per la **simulazione di phishing autorizzata**, a scopo
esclusivamente formativo. Regola non negoziabile: **Proteus non invia mai email reali e non
raccoglie mai credenziali reali** — l'intera "campagna" è una simulazione locale.

- **Campagna simulata** — `simulate_campaign()` genera un esito clic/non-clic per
  destinatario da un modello casuale seedabile; nessuna email parte mai, nessuna chiamata di
  rete viene fatta.
- **Pagina di training statica** — chi "clicca" un link simulato vede una pagina che
  dichiara subito l'esercitazione. Nessun `<form>`, nessun `<input>`: per costruzione non
  può mai raccogliere una credenziale (garanzia imposta da test automatici dedicati).
- **Allowlist destinatari obbligatoria** — ogni destinatario viene verificato contro un file
  di scope basato su dominio prima della simulazione; chi è fuori perimetro viene
  **bloccato e registrato**, non semplicemente escluso in silenzio.
- **Report conforme al core** — un `Asset` per destinatario, un `Finding` (severità LOW,
  segnale di consapevolezza, non una vulnerabilità) per ogni clic.

### Comandi
```bash
# Demo reale, offline e deterministica su una campagna sintetica "Olympus Demo Corp"
olympus proteus demo
```

### File di scope
```json
{
  "engagement": "olympus-demo-corp-2026",
  "allowed_domains": ["olympusdemocorp.example"],
  "excluded_recipients": []
}
```
Il match è sul dominio dell'indirizzo email; `excluded_recipients` permette di escludere
indirizzi specifici anche dentro un dominio autorizzato. I tentativi fuori perimetro
vengono appesi come riga JSON al log (default `examples/output/proteus-blocked.log`).

### Output
Il demo simula una campagna su 5 destinatari sintetici (uno intenzionalmente fuori scope,
per mostrare il blocco), scrive la pagina di training in
`examples/output/proteus-training-page.html`, ed esporta il report in
`examples/output/proteus-report.json`.

### Etica
Nessuna email reale viene mai inviata. Nessuna credenziale, reale o simulata, viene mai
richiesta o raccolta — vincolo verificato da test automatici che falliscono se la pagina di
training dovesse mai includere un form. Tutti i destinatari demo sono indirizzi sintetici su
`olympusdemocorp.example` (TLD riservato alla documentazione, RFC 2606).

---

## 🇬🇧 English

### What it does
Proteus is Olympus's Red module for **authorized phishing simulation**, training purposes
only. Non-negotiable rule: **Proteus never sends a real email and never collects a real
credential** — the entire "campaign" is a local simulation.

- **Simulated campaign** — `simulate_campaign()` generates a clicked/not-clicked outcome
  per recipient from a seedable random model; no email ever goes out, no network call is
  ever made.
- **Static training page** — whoever "clicks" a simulated link sees a page that
  immediately discloses the exercise. No `<form>`, no `<input>`: by construction it can
  never collect a credential (a guarantee enforced by dedicated automated tests).
- **Mandatory recipient allowlist** — every recipient is checked against a domain-based
  scope file before simulation; anyone out of scope is **blocked and logged**, never just
  silently dropped.
- **Report conforming to core** — one `Asset` per recipient, one `Finding` (LOW severity,
  an awareness signal, not a vulnerability) per click.

### Commands
```bash
# Real, offline, deterministic demo on a synthetic "Olympus Demo Corp" campaign
olympus proteus demo
```

### Scope file
```json
{
  "engagement": "olympus-demo-corp-2026",
  "allowed_domains": ["olympusdemocorp.example"],
  "excluded_recipients": []
}
```
Matching is on the email's domain; `excluded_recipients` lets you carve out specific
addresses even within an authorized domain. Out-of-scope attempts are appended as a JSON
line to the log (default `examples/output/proteus-blocked.log`).

### Output
The demo simulates a campaign over 5 synthetic recipients (one intentionally out of scope,
to demonstrate blocking), writes the training page to
`examples/output/proteus-training-page.html`, and exports the report to
`examples/output/proteus-report.json`.

### Ethics
No real email is ever sent. No credential, real or simulated, is ever requested or
collected — a constraint verified by automated tests that fail if the training page were
ever to include a form. All demo recipients are synthetic addresses at
`olympusdemocorp.example` (TLD reserved for documentation, RFC 2606).
