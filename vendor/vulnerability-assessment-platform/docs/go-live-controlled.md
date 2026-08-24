# Go-live Controllato — Runbook Operativo

Questo runbook definisce i passaggi obbligatori per eseguire un go-live controllato di VAP dopo il completamento della release candidate.

Obiettivo: rilasciare in produzione in modo **sicuro, osservabile e reversibile**, minimizzando impatti su utenti e dati.

## 1) Prerequisiti (go/no-go)

Il go-live può iniziare solo se:

- tutti i gate della [Release Candidate Checklist](release-candidate.md) sono soddisfatti;
- la suite test è verde con coverage sopra la soglia minima;
- non esistono vulnerabilità critiche aperte senza mitigazione approvata;
- è disponibile un piano di rollback validato;
- sono stati nominati owner tecnici per finestra di rilascio e monitoraggio post-release.

## 2) Strategia di rilascio consigliata

Adottare un rollout progressivo:

1. **Canary interno** (team tecnico + security reviewer);
2. **Rollout parziale** (quota ridotta di traffico/utenze);
3. **Rollout completo** solo dopo conferma dei KPI di stabilità e sicurezza.

Per ogni step deve esistere una finestra di osservazione minima (es. 30–60 minuti) con decisione esplicita go/no-go.

## 3) Checklist operativa pre-deploy

- Congelare merge non urgenti sul branch di release.
- Verificare configurazione ambiente:
  - chiavi API/JWT presenti e ruotate;
  - policy CSP e header sicurezza attivi;
  - allowlist target (se prevista) coerente con ambiente.
- Verificare servizi dipendenti:
  - database raggiungibile e backup recente disponibile;
  - queue worker (Celery/Redis) operativi;
  - storage report PDF accessibile.
- Preparare dashboard osservabilità:
  - error rate API e HTTP 5xx,
  - latenza endpoint principali,
  - job scansione falliti,
  - eventi audit sensibili (download report, modifiche learning progress).

## 4) Esecuzione rilascio

1. Deploy della versione candidata in ambiente target.
2. Esecuzione smoke test immediati:
   - creazione scansione guidata da homepage;
   - creazione scansione via API;
   - apertura dettaglio scansione con learning sidebar;
   - download report PDF autorizzato.
3. Validazione sicurezza rapida:
   - RBAC su endpoint critici;
   - assenza regressioni CSP evidenti;
   - rate limiting attivo su endpoint autenticazione.
4. Se gli smoke test passano, procedere con step successivo di rollout.

## 5) Criteri di rollback immediato

Eseguire rollback senza attese in caso di:

- aumento sostenuto errori 5xx oltre soglia concordata;
- regressione di sicurezza (auth bypass, IDOR, policy CSP non applicata);
- perdita di funzionalità core (creazione scansione, dettaglio, download report);
- incidenti dati (corruzione, inconsistenza critica, leak).

Il rollback deve ripristinare:

- versione applicativa precedente;
- configurazione stabile precedente;
- eventuali migrazioni incompatibili (tramite piano testato).

## 6) Verifica post go-live (prime 24 ore)

- Monitoraggio continuo con checkpoint periodici (es. T+30m, T+2h, T+24h).
- Revisione dei log audit su azioni sensibili.
- Raccolta feedback utenti interni su UX guided flow.
- Apertura issue immediata per ogni anomalia rilevata con priorità e owner.

## 7) Evidenze da archiviare

Per compliance e tracciabilità conservare:

1. commit/tag rilasciato;
2. timestamp inizio/fine go-live;
3. output smoke test;
4. metriche osservabilità della finestra di rilascio;
5. decisione finale (go-live confermato o rollback) con responsabile.

