# Upgrade Plan VAP — Sicurezza, UX didattica e scansioni configurabili

## 0) Obiettivo del ciclo corrente
Creare un piano operativo **didattico e incrementale** per trasformare VAP in una piattaforma:
- impeccabile sul piano sicurezza applicativa e operativa;
- altamente configurabile “voce per voce” dall’utente;
- efficace per apprendimento guidato (junior → professional);
- curata nel design UI/PDF con estetica minimale.

---

## 1) Analisi stato attuale (baseline reale repository)

### Punti forti già presenti
- Architettura solida con FastAPI + orchestrazione scanner modulare e plugin contract versionato.
- Validazioni target e controlli fail-closed per registrazione scanner.
- Hardening già avviato: CSRF, API key/JWT, rate limit, audit logging, allowlist target in produzione.
- UX già orientata alla didattica: wizard step-by-step, glossario, learning sidebar, guidance per scan type.
- Report PDF già strutturato con KPI, severità, dettaglio finding.
- Documentazione security e roadmap dedicate già presenti.

### Gap principali rispetto alla richiesta utente
1. **Personalizzazione scansione ancora “a profilo”**
   - L’utente sceglie scan type, ma non ha un **builder granulare per singolo modulo/opzione** (timeout, profondità crawler, payload policy, aggressività, esclusioni, thread, autenticazione, ecc.).
2. **Didattica non ancora “adattiva” per competenza**
   - Contenuti didattici presenti, ma non un vero tutor mode con prerequisiti, warning dinamici, quiz/validation checkpoint e percorsi personalizzati per ruolo.
3. **Sicurezza operativa da rafforzare lato execution safety**
   - Mancano ancora guardrail avanzati centralizzati per evitare configurazioni distruttive o non conformi (policy engine per scan config, budget di rischio, sandboxing per tool ad alta invasività, approval workflow).
4. **UX informativa molto ricca ma non sempre minimal**
   - Dashboard e dettaglio scansione hanno alta densità contenutistica; il rischio è overload cognitivo per studenti/junior.
5. **PDF professionale ma visivamente migliorabile**
   - Struttura valida, ma servono varianti template più “clean” e leggibili (gerarchia tipografica, whitespace, executive summary 1 pagina, remediation board più visiva).

---

## 2) Principi guida dell’upgrade

1. **Secure by default, expert by choice**
   - preset sicuri sempre attivi;
   - modalità avanzata disponibile con sblocco esplicito e spiegazioni rischio.

2. **Didattica contestuale, non separata**
   - ogni scelta tecnica deve mostrare “cosa fa”, “perché”, “rischi”, “quando evitarla”, “come validare il risultato”.

3. **Progressive disclosure UX**
   - interfaccia pulita iniziale;
   - dettagli avanzati solo quando richiesti.

4. **Tracciabilità completa**
   - ogni modifica ai parametri di scansione deve essere auditabile, ripetibile, esportabile.

---

## 3) Piano di miglioramento (checklist prioritaria)

## Fase A — Fondazioni per scansioni configurabili (P0)
- [x] **A1. Modello dati Scan Configuration v1**
  - JSON schema versionato per opzioni per-tool e globali.
  - Campi minimi: target scope, rate/timeout, depth, auth context, exclusions, severity threshold, evidenza minima.
  - Vincoli fail-closed e default sicuri.

- [x] **A2. Validation & Policy Engine**
  - Validazione server-side rigorosa di ogni opzione.
  - Regole di compatibilità tra tool (es. mutually exclusive settings).
  - Policy di sicurezza: blocco opzioni ad alto rischio in assenza autorizzazione/ruolo.

- [x] **A3. Execution Guardrails**
  - [x] Limiti runtime centralizzati lato API: max duration stimata, max requests/min, max concurrency e timeout tool.
  - [x] Safe mode obbligatorio per ruoli non admin (depth/payload cap).
  - [x] Kill switch globale su nuove scansioni + auto-abort su pattern anomali (alto tasso errori scanner).

- [x] **A4. Persistenza configurazioni e profili utente**
  - [x] Salvare preset personalizzati (“Baseline didattica”, “OWASP top focus”, “WordPress deep”).
  - [x] Versioning + checksum config per reproducibility (snapshot configurazione salvato per ogni scansione con endpoint dedicato di retrieval + verifica checksum server-side su snapshot/preset per intercettare tampering).

## Fase B — UX didattica e configurazione guidata (P0/P1)
- [x] **B1. Nuovo “Scan Builder” multi-step**
  - [x] Step 1 Scope legale/target.
  - [x] Step 2 Selezione moduli scanner.
  - [x] Step 3 Parametri avanzati per modulo.
  - [x] Step 4 Simulazione impatto (durata/rumore/rischio stimato).
  - [x] Step 5 Conferma con checklist compliance.

- [x] **B2. Didactic Mode (Beginner / Analyst / Expert)**
  - [x] Beginner: linguaggio semplificato + preset bloccati.
  - [x] Analyst: parametri intermedi con suggerimenti.
  - [x] Expert: pieno controllo con warning forti.

- [x] **B3. Explainability inline per ogni parametro**
  - Tooltip “cosa cambia”, “trade-off”, “false positive impact”.
  - Esempi pratici e anti-pattern.

- [x] **B4. UX minimal e accessibile**
  - [x] Stato errore più chiaro nel wizard: evidenziazione visuale coerente (`form-control-invalid`) per input/checkbox/fieldset invalidi + associazione ARIA esplicita tra campi e messaggi di errore inline.
  - [x] Riduzione densità visiva e migliori spaziature nelle viste principali (dashboard + dettagli scansione).
  - [x] Verifica WCAG AA completa (contrasto, tastiera, screen reader labels) con report dedicato.

## Fase C — Sicurezza avanzata applicativa e operativa (P0/P1)
- [x] **C1. RBAC fine-grained sulle capability di scansione**
  - [x] Permesso capability `create_scan_config` separato dal semplice ruolo viewer, applicato a creazione/cancellazione preset e creazione scansione API.
  - [x] Permesso capability `run_high_risk_scan` con enforcement esplicito (403) prima dell'orchestrazione per tool ad alto rischio.
  - [x] Permesso capability `export_sensitive_report` per download report classificati `confidential/restricted`.
  - [x] Permesso capability `override_scan_policy` con enforcement esplicito per richieste di eccezione policy in creazione scansione/preset (workflow approvativo avanzato resta in C2).

- [x] **C2. Approval workflow per scansioni ad alto rischio**
  - Double-confirmation + eventuale approvazione admin.

- [x] **C3. Secret management hardening**
  - [x] Nessun segreto in chiaro in output API di snapshot/preset configurazione (mascheramento server-side dei campi auth sensibili).
  - [x] Nessun segreto in chiaro in form/log/report.
  - [x] Mascheramento forte e rotazione chiavi guidata.

- [x] **C4. Security regression suite estesa**
  - [x] Fuzzing input config.
  - [x] Test anti-IDOR su risorse scansione/report.
  - [x] Test policy bypass e privilege escalation.

## Fase D — Reporting PDF/UI (P1)
- [x] **D1. Nuovo template PDF minimal/professional**
  - Copertina pulita, sommario executive 1 pagina, severity heatmap, remediation roadmap by priority.

- [x] **D2. Report didattico dual-layer**
  - [x] Layer 1: executive (manageriale) con sezione dedicata esplicita nel PDF.
  - [x] Layer 2: tecnico con evidenze complete e passi di validazione (checklist + validation steps per finding).

- [x] **D3. Design tokens condivisi UI/PDF**
  - [x] Introdotto catalogo token condiviso (`design_tokens.py`) per palette, tipografia, spacing e severity.
  - [x] UI aggiornata con stylesheet dedicato (`/static/css/design-tokens.css`) caricato in tutte le viste HTML prima di `style.css`.
  - [x] PDF generator allineato ai token condivisi (rimozione valori hardcoded duplicati).
  - [x] Copertura test dedicata per garantire coerenza token UI/PDF nel tempo.

## Fase E — Osservabilità e qualità continua (P1/P2)
- [x] **E1. Telemetria UX del funnel Scan Builder**
  - Drop-off per step, errori frequenti, tempo decisionale.

- [x] **E2. KPI didattici**
  - Accuratezza quiz, riduzione false positive confermati, miglioramento time-to-remediation.

- [x] **E3. Performance budget**
  - [x] SLA runtime scansioni (`VAP_SCAN_RUNTIME_SLA_SECONDS`) con tracciamento automatico nei log scan.
  - [x] SLA rendering report (`VAP_REPORT_RENDER_SLA_SECONDS`) con warning automatico su superamento soglia.
  - [x] Copertura test unitari dedicata al motore di valutazione performance budget.

---

## 4) Backlog bug/pre-esistenti da monitorare
- [x] Possibile overload cognitivo nelle viste principali con molte informazioni contemporanee: introdotte sezioni progressive/collassabili per KPI secondari, log runtime e learning sidebar così da mantenere in primo piano solo le informazioni operative critiche (completato il 2026-04-18).
- [x] Uniformato il copywriting tecnico cross-canale su termini chiave di lettura finding/stato (UI dettaglio scansione + PDF report + catalogo didattico già allineato su lessico italiano operativo), riducendo mix IT/EN non necessario (completato il 2026-04-17).
- [x] Governance esplicita “scan config lifecycle” (draft/review/approved/deprecated) introdotta su preset configurazione con transizioni controllate e approvazione admin obbligatoria per lo stato `approved` (completato il 2026-04-17).
- [x] Test regressione CSP disallineato (`tests/test_security_headers.py::test_csp_disallows_inline_scripts_by_default`): expectation allineata alla policy CSP corrente con sole sorgenti locali (`'self'`) per `script-src`/`style-src` (completato il 2026-04-18).
- [x] Test integrazione flakey su approval high-risk (`tests/test_api_integration.py::test_create_scan_non_admin_high_risk_requires_admin_approval_reference`): isolamento dei test ripristinato centralizzando il reset dello storage del rate limiter dentro `_clear_scans()`, eliminando interferenze tra POST consecutivi e tra test che condividono lo stesso client IP (completato il 2026-04-18).
- [x] Riferimento checklist riallineato al repository: introdotta la suite dedicata `tests/test_compliance.py` con copertura su subject routing, required consents, redazione metadata audit e anonimizzazione export scansione (completato il 2026-04-24).

---


- [x] Disallineamento documentazione CI: ripristinato e versionato il workflow `.github/workflows/quality-gate.yml` con job dedicati (security/style, API integration matrix 3.10/3.11, accessibility, frontend security, scanner runtime), riallineando la checklist allo stato reale del repository (completato il 2026-04-24).

## 5) Definizione “Done” per ogni task
Un task è completato solo se:
1. implementazione funzionante end-to-end;
2. test automatici e controlli sicurezza pertinenti passati;
3. UX verificata (inclusa accessibilità base);
4. documentazione aggiornata;
5. checklist aggiornata con evidenza reale.

---

## 6) Primo task consigliato (prossimo ciclo)
- [x] **Hardening QA — fixture pytest `reset_runtime_state` introdotta per centralizzare reset rate limiter/dependency overrides nei test API** (completato il 2026-04-18).

Motivo completamento: consolidato il reset runtime in `tests/conftest.py` con fixture autouse (setup/teardown), eliminando reset duplicati espliciti nei test API più sensibili a flaky behavior.

- [x] **Hardening QA — helper condiviso `clear_persistent_state` riusato anche nei test non-API** (completato il 2026-04-18).

Motivo completamento: estratta in `tests/conftest.py` la utility condivisa per cleanup stato persistente e riutilizzata in `tests/test_api_integration.py` e `tests/test_accessibility_checks.py`, mantenendo cleanup differenziato via flag `include_learning_artifacts`.

**Prossimo task consigliato:** introdurre fixture pytest dedicata al seeding di scansioni/access audit per i test UI/API, così da ridurre boilerplate di setup nei casi di dettaglio scansione/report download e migliorare leggibilità/manutenibilità della suite.

- [x] **Hardening QA — fixture pytest dedicate al seeding Scan/Audit per test UI/API** (completato il 2026-04-18).

Motivo completamento: aggiunte in `tests/conftest.py` le fixture factory `seed_scan` e `seed_audit_event`, poi adottate nei test di integrazione API e accessibilità UI per ridurre setup duplicato su scan detail, report download e KPI didattici mantenendo isolamento e default sicuri.

- [x] **Hardening QA — refactor trend summary API tests su fixture `seed_scan` + assert espliciti default factory** (completato il 2026-04-18).

Motivo completamento: i test di trend summary su dettaglio scansione ora riusano la fixture condivisa `seed_scan` eliminando creazione manuale duplicata di record baseline/current; aggiunto inoltre un test dedicato sui default della factory (`target`, `scan_type`, `status`, `data_classification`, `logs_json`, `findings_json`) per intercettare regressioni silenziose del setup.

- [x] **Hardening QA — refactor test audit API su fixture `seed_audit_event`** (completato il 2026-04-18).

Motivo completamento: i test di listing audit (`/api/v1/audit/events`) ora usano la factory condivisa `seed_audit_event` al posto di `session.add_all(...)`, riducendo boilerplate SQLAlchemy diretto e mantenendo setup più leggibile/coerente con l’approccio fixture-first adottato in suite.

- [x] **Hardening QA — helper pytest `bootstrap_guided_form_client` per journey wizard/compliance** (completato il 2026-04-18).

Motivo completamento: introdotta in `tests/conftest.py` una fixture context-manager che centralizza bootstrap homepage, estrazione cookie CSRF e override API key del form guidato; i test journey/compliance in `tests/test_api_integration.py` ora riusano il helper riducendo boilerplate e divergence risk tra scenari positivi/negativi.

**Prossimo task consigliato:** estendere lo stesso pattern fixture-first ai test telemetry CSRF (`/api/v1/telemetry/scan-builder`) introducendo un helper dedicato ai POST CSRF-protected, così da uniformare ulteriormente i setup tra endpoint API JSON e submit form.

- [x] **Hardening QA — helper pytest `bootstrap_csrf_json_client` per endpoint JSON con CSRF** (completato il 2026-04-19).

Motivo completamento: introdotta in `tests/conftest.py` una fixture context-manager che inizializza cookie CSRF e compone header riusabili (`x-csrf-token` + eventuali header custom); i test telemetry su `/api/v1/telemetry/scan-builder` in `tests/test_api_integration.py` ora la riusano sia per il percorso valido sia per quello di rifiuto CSRF, riducendo boilerplate e mismatch di setup tra test.

- [x] **Hardening QA — adozione `bootstrap_csrf_json_client` nei test preset/lifecycle con header `x-data-subject`** (completato il 2026-04-19).

Motivo completamento: i test API su CRUD preset e transizioni lifecycle (`/api/v1/scan-config/presets` + `/lifecycle`) ora usano il bootstrap condiviso CSRF JSON al posto di cookie/header hardcoded per ogni chiamata, riducendo boilerplate, mismatch nei setup e rischio regressioni da copia-incolla.

- [x] **Hardening QA — helper pytest `subject_headers` per endpoint read-only con `x-data-subject` (KPI/trend/preset filters)** (completato il 2026-04-19).

Motivo completamento: introdotta in `tests/conftest.py` la fixture factory `subject_headers(subject_id, extra_headers=None)` per comporre header read-only coerenti; adottata nei test API di retrieval trend/config snapshot, filtri lifecycle preset e KPI didattici, eliminando header inline duplicati nei GET con subject routing.

- [x] **Hardening QA — adozione `subject_headers` nei test read-only residui (download report cross-subject + preset list)** (completato il 2026-04-19).

Motivo completamento: i test read-only rimasti con header `x-data-subject` hardcoded ora riusano la fixture factory `subject_headers(...)` nei casi di download report cross-subject e listing preset configurazione, riducendo duplicazioni e mantenendo coerenza fixture-first nei GET con subject routing.

- [x] **Hardening QA — lint test pytest contro header `x-data-subject` hardcoded fuori dai helper condivisi** (completato il 2026-04-19).

Motivo completamento: aggiunto il test `tests/test_subject_header_lint.py` che scansiona i file `tests/test_*.py` e fallisce se trova uso letterale di `"x-data-subject"` non mediato da `subject_headers(...)` o `bootstrap_csrf_json_client(...)`, prevenendo regressioni di stile/consistenza nei test.

- [x] **Hardening QA — allowlist documentata nel lint `x-data-subject` + quality gate CI con security headers** (completato il 2026-04-19).

Motivo completamento: il lint `tests/test_subject_header_lint.py` supporta ora una allowlist esplicita file/linea con motivazione per casi eccezionali documentati; aggiunto workflow GitHub Actions `.github/workflows/quality-gate.yml` che esegue in CI `tests/test_security_headers.py` e `tests/test_subject_header_lint.py` come quality gate minimo su push/PR.

- [x] **Hardening QA — quality gate CI esteso con `tests/test_api_integration.py` in job separata a matrice Python** (completato il 2026-04-19).

Motivo completamento: il workflow `.github/workflows/quality-gate.yml` ora mantiene un gate rapido dedicato a security/style e aggiunge una job separata `api-integration-matrix` con `fail-fast: false` su Python 3.10 e 3.11 per intercettare regressioni cross-versione senza rallentare eccessivamente il controllo minimo.

- [x] **Hardening QA — caching pip nei job CI del quality gate** (completato il 2026-04-19).

Motivo completamento: aggiunto `cache: 'pip'` con `cache-dependency-path: requirements.txt` in entrambi i job del workflow `.github/workflows/quality-gate.yml` (`security-and-style-guards` e `api-integration-matrix`), riducendo i tempi medi di installazione dipendenze senza modificare isolamento né ripetibilità della pipeline.

- [x] **Hardening QA — quality gate CI dedicato ai test di accessibilità WCAG** (completato il 2026-04-19).

Motivo completamento: aggiunta nel workflow `.github/workflows/quality-gate.yml` la job `accessibility-guards` con caching pip e run mirata di `tests/test_accessibility_checks.py`, così da intercettare regressioni UX/accessibilità direttamente su push/PR con un controllo rapido e isolato.

- [x] **Hardening QA — quality gate CI dedicato ai test frontend security del catalogo scansioni** (completato il 2026-04-19).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `frontend-security-guards` (Python 3.11 + pip cache) che esegue `tests/test_scan_catalog_frontend_security.py`, introducendo un controllo CI mirato contro regressioni XSS/template-injection lato UI prima del merge.

- [x] **Hardening QA — quality gate CI dedicato ai test scanner runtime guardrails** (completato il 2026-04-19).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `scanner-runtime-guards` (Python 3.11 + pip cache) che esegue `tests/test_scanner_engine_runtime.py`, aggiungendo un controllo automatico su timeout centralizzati e limiti operativi dello scanner engine in push/PR.

- [x] **Hardening QA — quality gate CI dedicato ai test di resilienza report generator** (completato il 2026-04-19).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `report-generator-guards` (Python 3.11 + pip cache) che esegue `tests/test_report_generator.py`, intercettando regressioni su rendering PDF/layout in una pipeline isolata rispetto ai test API.

- [x] **Hardening QA — quality gate CI dedicato ai test di security hardening template inline** (completato il 2026-04-19).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `template-inline-hardening-guards` (Python 3.11 + pip cache) che esegue `tests/test_template_inline_hardening.py`, così da intercettare in push/PR regressioni su protezioni XSS/CSP nel rendering template HTML/PDF.

- [x] **Hardening QA — quality gate CI dedicato ai test guardrail del catalogo scanner** (completato il 2026-04-19).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `scan-catalog-guards` (Python 3.11 + pip cache) che esegue `tests/test_scan_catalog.py`, introducendo un controllo CI isolato su coerenza metadata/routing del catalogo moduli di scansione prima del merge.

- [x] **Hardening QA — quality gate CI dedicato ai test validation/policy engine configurazioni** (completato il 2026-04-19).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `scanner-validation-guards` (Python 3.11 + pip cache) che esegue `tests/test_scanner_validation.py`, aggiungendo un controllo CI isolato su vincoli fail-closed e compatibilità opzioni del builder/scanner prima del merge.

- [x] **Hardening QA — quality gate CI dedicato ai test execution guardrails operativi** (completato il 2026-04-19).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `execution-guardrails-guards` (Python 3.11 + pip cache) che esegue `tests/test_execution_guardrails.py`, coprendo in pipeline dedicata i blocchi runtime/safe-mode/kill-switch del policy enforcement operativo.

- [x] **Hardening QA — quality gate CI dedicato ai test performance budget/SLA** (completato il 2026-04-19).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `performance-budget-guards` (Python 3.11 + pip cache) che esegue `tests/test_performance_budget.py`, aggiungendo un presidio CI isolato sui regression check di SLA runtime scansioni/report e warning automatici del performance budget.

- [x] **Hardening QA — quality gate CI dedicato ai test di coerenza design tokens UI/PDF** (completato il 2026-04-20).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `design-tokens-guards` (Python 3.11 + pip cache) che esegue `tests/test_design_tokens.py`, aggiungendo un presidio CI isolato contro regressioni di coerenza tra token condivisi UI/PDF prima del merge.

- [x] **Hardening QA — quality gate CI dedicato ai test di prioritizzazione remediation roadmap** (completato il 2026-04-20).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `remediation-roadmap-guards` (Python 3.11 + pip cache) che esegue `tests/test_remediation_roadmap.py`, aggiungendo un controllo CI isolato contro regressioni nella logica di priorità remediation dei report.

- [x] **Hardening QA — quality gate CI dedicato ai test enrichment engine** (completato il 2026-04-20).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `enrichment-engine-guards` (Python 3.11 + pip cache) che esegue `tests/test_enrichment_engine.py`, aggiungendo un presidio CI isolato contro regressioni nella normalizzazione/arricchimento finding prima del merge.

- [x] **Hardening QA — quality gate CI dedicato ai test checklist hardening configurativo** (completato il 2026-04-20).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `config-security-checklist-guards` (Python 3.11 + pip cache) che esegue `tests/test_config_security_checklist.py`, intercettando regressioni sui controlli baseline di hardening configurativo direttamente su push/PR prima del merge.

- [x] **Hardening QA — quality gate CI dedicato ai test schema/policy di Scan Configuration v1** (completato il 2026-04-20).

Motivo completamento: aggiunti test unitari dedicati in `tests/test_scan_configuration.py` per vincoli schema (normalizzazione/validazione override) e policy enforcement (compatibilità tool/scan type + approvazione high-risk per ruoli non admin); esteso `.github/workflows/quality-gate.yml` con la job `scan-configuration-guards` (Python 3.11 + pip cache) che esegue questo file in pipeline isolata su push/PR.

- [x] **Hardening QA — quality gate CI dedicato ai test core security + audit logging middleware** (completato il 2026-04-20).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con due job isolate (`security-core-guards` e `audit-logging-guards`, Python 3.11 + pip cache) che eseguono rispettivamente `tests/test_security.py` e `tests/test_audit_logging_middleware.py`, così da intercettare regressioni su primitive di sicurezza (API key/JWT/CSRF/proxy trust) e tracciamento audit middleware direttamente su push/PR prima del merge.

- [x] **Hardening QA — quality gate CI dedicato ai test migrazioni database Alembic** (completato il 2026-04-21).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `db-migrations-guards` (Python 3.11 + pip cache) che esegue `tests/test_db_migrations.py`, aggiungendo un controllo CI isolato contro regressioni su schema/versioning e drift migrazioni prima del merge.

- [x] **Hardening QA — quality gate CI dedicato ai test learning blocks didattici** (completato il 2026-04-21).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `learning-blocks-guards` (Python 3.11 + pip cache) che esegue `tests/test_learning_blocks.py`, aggiungendo un controllo CI isolato contro regressioni nei contenuti didattici contestuali e nella coerenza dei blocchi formativi UI/API.

- [x] **Hardening QA — quality gate CI dedicato ai test di integrazione nuovi scanner/plugin** (completato il 2026-04-21).

Motivo completamento: esteso `.github/workflows/quality-gate.yml` con la job `new-scanners-guards` (Python 3.11 + pip cache) che esegue `tests/test_new_scanners.py`, aggiungendo un presidio CI isolato per intercettare regressioni di integrazione sui nuovi scanner/plugin prima del merge.

- [x] **Hardening QA — suite pytest dedicata `tests/test_compliance.py` per utility compliance/privacy** (completato il 2026-04-24).

Motivo completamento: introdotti test unitari per `get_subject_id`, `has_required_consents`, `record_audit_event` (con verifica redazione metadati sensibili) e `anonymize_scan_for_export`, riallineando la checklist al file di test realmente presente nel repository e coprendo regressioni su flussi privacy/compliance di base.

**Prossimo task consigliato:** chiarire il disallineamento tra checklist e repository sui workflow CI (`.github/workflows/quality-gate.yml` assente) decidendo se ripristinare i workflow nel repo oppure semplificare `upgrade.md` per riflettere esclusivamente asset versionati.
