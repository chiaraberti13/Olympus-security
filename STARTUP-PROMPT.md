# ⭐ Prompt di avvio / Startup prompt — Olympus Security

> 🇮🇹 Incolla il blocco qui sotto in Claude Code, aperto nella cartella del monorepo. È
> l'unico prompt che serve: lo stato vive nei file (PLAN/TASKS/ERRORS), quindi lo stesso
> prompt vale per ogni ondata e ogni modulo.
> 🇬🇧 Paste the block below into Claude Code, opened in the monorepo folder. It's the only
> prompt you need: state lives in the files (PLAN/TASKS/ERRORS), so the same prompt works for
> every wave and module.

```text
Sei l'agente di sviluppo del monorepo "Olympus Security" (piattaforma offensive security,
Red + Blue). Obiettivo: far avanzare il progetto in modo auto-correttivo e auto-testante,
con cura e precisione maniacale.

REGOLE FISSE
- README di ogni modulo in DOPPIA LINGUA (italiano + inglese).
- Commenti nel codice SOLO in inglese.
- "Verde o non fatto": un task è completo solo se `make check` è verde
  (ruff + mypy --strict + pytest con coverage >= 90%).
- Un task alla volta. Niente scope creep: il nuovo scope va in TASKS.md o ERRORS.md.
- Moduli offensivi: scope file obbligatorio, blocco+log fuori scope, non distruttivo.
  Proteus non raccoglie mai credenziali reali.

CICLO DA SEGUIRE
1. Leggi PLAN.md, TASKS.md, ERRORS.md. Riassumi in 3 righe: dove siamo, cosa manca,
   qual è il PROSSIMO task (parti dal primo non spuntato in TASKS.md).
2. PLAN → BUILD (porzione minima) → VERIFY (ruff + mypy) → TEST (pytest, verde davvero)
   → CHECK (vs criterio del task) → LOG (fallimenti in ERRORS.md, formato ERR-YYYY-MM-DD-nn)
   → RESOLVE (ogni ERRORS APERTO → nuovo task in TASKS.md) → GATE (spunta solo se `make check` verde).
3. Ripeti dal punto 2 finché: TASKS.md senza task aperti nell'ondata corrente, ERRORS.md
   senza voci APERTE, `make check` verde.
4. Aggiorna TASKS.md ed ERRORS.md. Scrivi un riepilogo: task chiusi, gate superati,
   prossimo passo consigliato.

Ogni nuovo modulo che crei deve avere: package sotto src/olympus/<modulo>, comando `demo`
reale su dati sintetici "Olympus Demo Corp", output conforme agli schemi di olympus.core,
esempi in examples/, README di modulo bilingue in docs/modules/<modulo>.md.

Comincia ora dal punto 1.
```

## Continuazione / Continuation (giri successivi)
```text
Continua il loop Olympus: prossimo task da TASKS.md, ciclo completo, `make check` verde,
aggiorna i file. Fermati quando l'ondata è chiusa e tutto è verde.
```

## In automatico (facoltativo) / Unattended (optional)
Per esecuzioni notturne non presidiate usa un branch `nightly/AAAA-MM-GG`, **mai `main`**,
e apri una **Pull Request** per la review ("propose, don't push"). Vedi il workflow CI in
`.github/workflows/`.
