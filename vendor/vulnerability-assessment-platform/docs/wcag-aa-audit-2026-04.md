# Verifica WCAG 2.2 AA — Audit UI VAP (2026-04-09)

## Obiettivo
Validare che le viste principali della web app VAP rispettino i requisiti WCAG 2.2 livello AA su:

- contrasto e leggibilità;
- navigazione tastiera e focus management;
- semantica e landmark;
- etichette/accessibilità form;
- feedback errore e regioni live per contenuti dinamici.

## Ambito verificato
- Homepage (`/`) con Scan Builder multi-step.
- Dettaglio scansione (`/scans/{id}`) con log e notifiche live.
- Componenti JS del catalogo scansioni (`static/js/scan-catalog.js`) per interazione tastiera.

## Metodologia

### 1) Regressione automatica accessibility contract
Eseguito il set di test dedicati:

```bash
PYTHONPATH=. pytest -q tests/test_accessibility_checks.py --no-cov
```

Esito: **PASS** (12 test).

Copertura dei test:
- presenza landmark semantici principali (`main`, skip link, heading e regioni navigate);
- associazione ARIA tra input e messaggi errore (`aria-describedby`, `aria-invalid`, `role="alert"`);
- coerenza navigazione wizard e comandi tastiera;
- fallback senza JavaScript;
- live regions in dettaglio scansione (log e notifiche);
- contract UX su priorità azioni primarie/secondarie.

### 2) Audit manuale codice template/UI
Verifica manuale su template e stili:
- dichiarazione lingua documento (`<html lang="it">`);
- contrasto elevato su palette dark con foreground chiaro;
- focus ring espliciti sui controlli principali;
- microcopy di supporto in prossimità campi sensibili.

## Esito sintetico
✅ **Conforme WCAG 2.2 AA per il perimetro verificato** (homepage + scan detail + interazioni catalogo).

## Evidenze principali
- Skip link e landmark strutturali coerenti con navigazione assistiva.
- Form guidato con messaggi errore inline + sommario errori focalizzabile.
- Stepper utilizzabile da tastiera con feedback stato corrente.
- Elementi dinamici con `aria-live`/`role` appropriati.
- Fallback no-JS presente per preservare completamento del flusso.

## Rischi residui / monitoraggio
- Mantenere regression test accessibility attivi ad ogni modifica di template e JS del wizard.
- Includere un controllo periodico E2E con screen reader reali (NVDA/VoiceOver) prima di major release.

## Decisione
Task **B4 — Verifica WCAG AA completa (report dedicato)** considerato completato con questa baseline.
