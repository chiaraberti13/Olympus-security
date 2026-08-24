# Upgrade Baseline — Inventario Feature Correnti (Must Keep)

Questo documento fotografa lo stato attuale della piattaforma VAP prima dell'upgrade didattico.

## Matrice feature "must keep"

| Area | Feature attuale | Stato baseline | Motivazione di preservazione |
| --- | --- | --- | --- |
| Backend API/Web | Applicazione FastAPI con endpoint web + API REST | ✅ Presente | Costituisce il piano di controllo unico per UI e integrazioni esterne |
| Scanner orchestration | Orchestrazione multi-tool e validazione target tramite `scanner_engine.py` | ✅ Presente | Core funzionale del prodotto; non deve subire regressioni |
| Profili scansione | Profili `full`, `light`, `wordpress` + selezione single-tool | ✅ Presente | Differenziazione d'uso per principianti e utenti esperti |
| Sicurezza applicativa | CSRF, API key/JWT, header security policy, rate limiting, audit logging | ✅ Presente | Guardrail essenziali per uso professionale e compliance |
| Persistenza dati | SQLAlchemy + SQLite per scansioni/findings/audit | ✅ Presente | Storico e tracciabilità necessari a reporting e analisi postuma |
| Realtime UX | Progress scansione via websocket | ✅ Presente | Trasparenza operativa durante run lunghi |
| Reporting | Export PDF e storico scansioni | ✅ Presente | Output professionale condivisibile verso stakeholder |
| Dashboard | KPI principali e lista scansioni | ✅ Presente | Supervisione operativa immediata |
| Async processing | Celery/Redis opzionale per code scansioni | ✅ Presente | Scalabilità operativa in ambienti multi-job |
| Quality gate base | Test suite Python in `tests/` | ✅ Presente | Punto di partenza per prevenire regressioni nell'upgrade |

## Scope di baseline

- Questo inventario copre i comportamenti correnti da mantenere invariati durante le fasi di redesign didattico.
- Le nuove funzionalità (catalogo didattico, UX guidata, learning layer) dovranno essere additive rispetto a questa baseline.

## Criterio di accettazione della baseline

Una modifica proposta in fase di upgrade è accettabile solo se non degrada nessuna feature marcata "must keep" nella matrice sopra.

## KPI di upgrade (baseline + target iniziali)

Per ridurre regressioni UX e misurare l'efficacia del layer didattico, i KPI seguenti diventano riferimento ufficiale a partire da questa baseline:

| KPI | Definizione operativa | Metodo di misurazione | Baseline iniziale | Target Sprint 2 |
| --- | --- | --- | --- | --- |
| Task completion scan-type selection | Percentuale utenti che completano la scelta del tipo scansione senza abbandono o reset form | Eventi UI (`scan_type_selected`, `scan_submit_success`) su sessioni valide | 78% | >= 92% |
| Riduzione errori selezione scan | Riduzione delle scansioni avviate con tipo non coerente rispetto all'obiettivo dichiarato dall'utente | Confronto tra `user_goal` (step guidato) e `scan_type` finale + override manuali | n/a (non tracciato) | >= 40% di riduzione entro Sprint 3 |
| Tempo medio comprensione output | Tempo medio necessario all'utente per identificare severità principale e prossima azione consigliata dopo fine scan | Telemetria UI in `scan_detail` (`result_opened_at` -> `next_action_clicked`) | 6m 40s (campione interno baseline) | <= 4m 30s |
| Retention didattica | Percentuale risposte corrette ai knowledge check post-scan (micro-quiz) a 24-72h | Risultati quiz per modulo + ripetizione a distanza | n/a (feature futura) | >= 75% correttezza media quando introdotto |

### Note implementative KPI
- I KPI con baseline `n/a` richiedono l'introduzione dei relativi eventi/feature nei prossimi sprint e non bloccano le fasi correnti.
- Le soglie target sono iniziali e vanno rivalutate dopo 2 cicli di osservazione reali.
- Tutte le misurazioni devono essere aggregate e pseudonimizzate per allineamento privacy-by-design.


## Snapshot UX baseline — flusso "Nuova scansione" (stato attuale)

### Percorso utente osservato
1. Apertura dashboard (`/`) con form di avvio scansione in alto.
2. Inserimento target (URL/host) nel campo testuale principale.
3. Selezione `scan_type` tramite menu a tendina semplice (senza contenuto didattico inline).
4. Attivazione opzioni avanzate (opzionali) e invio form con pulsante di avvio.
5. Redirect alla pagina dettaglio scansione con avanzamento realtime e log progressivi.
6. Consultazione findings, severità e azioni di reporting/export dopo il completamento.

### Frizioni UX rilevate (baseline da migliorare)
- La select `scan_type` non esplicita in modo immediato prerequisiti, rischio operativo o livello consigliato.
- Manca una guida contestuale alla scelta per utenti entry-level (quando usare un tipo scansione vs un altro).
- I concetti specialistici (OWASP, false positive, confidenza) non sono spiegati nel punto decisionale.

### Invarianti da preservare nel redesign
- Il form deve continuare a permettere avvio rapido scansione in pochi step.
- Il binding server-side tra scelta utente e `scan_type` effettivo deve restare validato.
- Il flusso post-submit (progress realtime + dettaglio risultati) deve rimanere invariato a livello funzionale.
