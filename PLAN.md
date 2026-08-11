# PLAN — Olympus Security (auto-correcting build plan)

> 🇮🇹/🇬🇧 Piano d'ondate del monorepo. Il motore è il loop auto-correttivo:
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

## Ondate / Waves

**W0 — Foundations (fatto / done).** `core`: enum, ID generator, modelli Asset/Finding,
errori strutturati, CLI unico, export JSON Schema, CI, gate verdi.

**W1 — First value.** `Argus` (OSINT passivo → `argus-assets.json`) + `Hermes` (secret scan
→ SARIF, pre-commit). *Esito:* primo scambio dati reale + tool DevSecOps spendibile.

**W2 — Surface & detection.** `Helios` (scope enforcement → `helios-findings.json`) +
`Apollo` (regole YAML + MITRE ATT&CK + detection testing). Core aggiunge Alert/Event/Evidence.

**W3 — Web, response, reporting.** `Artemis` (web recon) + `Minerva` (IR/DFIR); poi `Proteus`
(phishing sim) + `Vulcan` (aggregazione finding + **report di pentest**). Core aggiunge Incident.

**W4 — Range & capstone.** `Mars`: cyber range Docker segmentato + scenari purple end-to-end
che attraversano tutta la suite. Test cross-module, release riproducibile.

## Definition of Done (per modulo / per module)
- [ ] Funzione core dello scope operativa · comando `demo` reale su dati sintetici
- [ ] `make check` verde (ruff + mypy strict + pytest ≥90%)
- [ ] Output conforme agli schemi di `core` · `examples/` con I/O reali
- [ ] README di modulo bilingue · commenti nel codice **solo in inglese**
- [ ] (Red) scope file, blocco+log fuori scope, non distruttivo
- [ ] `ERRORS.md` senza voci APERTE per il modulo

## Anti-over-engineering
Prima di aggiungere DB/API/broker/dashboard, rispondi: (1) quale problema risolve? (2) serve
per la prima versione? (3) basta un file JSON? (4) come lo dimostro a un recruiter? Se non
migliora utilità/affidabilità/sicurezza/chiarezza/integrazione → rinviato.
