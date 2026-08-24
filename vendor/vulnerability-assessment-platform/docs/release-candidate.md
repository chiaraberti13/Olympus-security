# Release Candidate Readiness Checklist

Questa checklist formalizza la preparazione della release candidate (RC) per VAP dopo l'upgrade didattico/professionale. L'obiettivo è garantire che UX guidata, sicurezza applicativa e qualità software siano verificate in modo ripetibile prima del go-live.

## 1) Gate funzionali (must-pass)

- Verificare creazione scansione via UI guidata (stepper completo, consenso obbligatorio).
- Verificare creazione scansione via API (`POST /api/v1/scan`).
- Verificare dettaglio scansione con:
  - learning sidebar,
  - confidence rubric,
  - remediation roadmap ordinata.
- Verificare download report PDF e audit event associato.

## 2) Gate sicurezza (must-pass)

- Confermare policy CSP hardenizzata in ambiente target (assenza `unsafe-inline` in `script-src`).
- Verificare enforcement RBAC su endpoint critici (viewer/operator/admin).
- Verificare validazioni anti-tampering su `scan_type` e target.
- Verificare input hardening per endpoint didattici (`learning-feedback`, `learning-progress`).
- Verificare rate limiting su endpoint autenticazione/token.

## 3) Gate qualità e stabilità (must-pass)

- Eseguire suite test completa con coverage >= soglia minima definita.
- Eseguire quality gate Lighthouse CI con punteggi >= 90 sui flussi principali.
- Verificare assenza errori console sui principali percorsi UX.
- Verificare assenza regressioni nei fixture/golden dataset.

## 4) Gate UX e accessibilità (must-pass)

- Verificare keyboard traversal completo nei flussi di avvio scansione.
- Verificare presenza e correttezza skip-link.
- Verificare annunci ARIA per errori bloccanti e stato stepper.
- Verificare leggibilità mobile del catalogo scansioni e dei pannelli didattici.

## 5) Evidenze minime da allegare alla RC

Per ogni RC salvare:

1. hash commit candidato;
2. output sintetico dei test (`pytest -q`);
3. risultato quality/security gate CI;
4. nota rischi residui (se presenti) con owner e piano di rientro;
5. conferma finale "go/no-go" con data.

## 6) Comando operativo consigliato (pre-flight locale)

```bash
PYTHONPATH=. pytest -q
```

Se il comando fallisce, la RC è automaticamente **bloccata** finché i test non tornano verdi.
