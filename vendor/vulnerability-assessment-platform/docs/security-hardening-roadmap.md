# Security Hardening Roadmap

## Obiettivo
Consolidare la sicurezza applicativa di VAP in produzione con un approccio progressivo, misurabile e verificabile, mantenendo compatibilità con l'architettura attuale (FastAPI + scanner orchestration + UI Jinja).

## Stato attuale (baseline)
Sono già operativi:
- RBAC applicativo (`viewer`, `operator`, `admin`) sugli endpoint sensibili.
- Policy opzionale di target allowlist in produzione.
- Audit logging esteso per azioni operative e download sensibili.
- CSP più restrittiva con rimozione di `unsafe-inline` da `script-src`.
- Refactor iniziale degli script inline (`scan_detail.html` -> `static/js/scan-detail.js`).
- Startup security checklist su configurazioni/segreti.

## Gap residui e priorità

### P0 — Hardening immediato (bloccante release)
1. **Eliminazione progressiva script/style inline residui**
   - Censire i template con inline script/style.
   - Estrarre in asset versionati (`static/js`, `static/css`).
   - Aggiornare CSP per ridurre eccezioni non necessarie.

2. **Cookie/session hardening completo**
   - Verificare `Secure`, `HttpOnly`, `SameSite` coerenti su tutti i cookie.
   - Uniformare lifetime e rotazione token JWT in base al ruolo.

3. **Copertura test sicurezza minima obbligatoria in CI**
   - CSRF regression suite.
   - JWT tampering e claim escalation checks.
   - Input tampering (`scan_type`, target, query params).
   - IDOR checks su risorse scansione/report.

### P1 — Riduzione superficie di attacco
1. **Tailwind CDN -> build locale**
   - Rimuovere dipendenza runtime da CDN per migliorare CSP e supply-chain posture.
   - Integrare pipeline build CSS con hashing e cache busting.

2. **Rate limit avanzato per endpoint ad alto rischio**
   - Policy differenziata per endpoint autenticati/non autenticati.
   - Telemetria su burst e tentativi abusivi.

3. **Download/report protection**
   - Tokenizzazione a scadenza breve per export sensibili.
   - Audit correlato a sessione/utente.

### P2 — Governance enterprise
1. **Dependency & container security gates**
   - SCA automatica su `requirements.txt`.
   - Container image scanning in pipeline.

2. **Threat modeling periodico**
   - Aggiornamento trimestrale con focus su nuovi scanner/endpoint.

3. **Incident readiness**
   - Esercitazioni tabletop su abuso API key/JWT e data leak simulato.

## KPI di sicurezza
- 0 endpoint sensibili accessibili senza ruolo previsto.
- 100% endpoint state-changing coperti da protezioni CSRF/JWT coerenti.
- 0 regressioni critiche in suite OWASP Top 10 rilevante.
- 100% template principali senza inline script non giustificati.
- Tempo medio triage security regression < 1 giorno lavorativo.

## Criteri di completamento
Una milestone è considerata completata solo se:
1. controlli implementati;
2. test automatici verdi;
3. evidenza documentata (commit + changelog sicurezza);
4. rollback plan disponibile per cambiamenti CSP/autenticazione.

## Riferimenti ufficiali
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- FastAPI Security: https://fastapi.tiangolo.com/tutorial/security/
- Starlette Middleware: https://www.starlette.io/middleware/
- MDN Content Security Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- NIST Secure Software Development Framework (SSDF): https://csrc.nist.gov/projects/ssdf
