# Valutazione migrazione Tailwind: CDN runtime -> build locale

## Data
2026-04-04

## Obiettivo
Ridurre la superficie di attacco lato frontend eliminando la dipendenza dal runtime `https://cdn.tailwindcss.com` nei template, migliorando coerenza CSP, disponibilità offline e governance supply-chain.

## Stato attuale
Template che caricano Tailwind via CDN runtime:
- `templates/index.html`
- `templates/scan_detail.html`
- `templates/scans_list.html`
- `templates/privacy_policy.html`
- `templates/terms_of_service.html`

### Rischi rilevati
1. **Supply-chain risk:** script remoto eseguito a runtime in tutte le pagine principali.
2. **CSP meno restrittiva del necessario:** la policy deve consentire script esterni dove non sono strettamente necessari.
3. **Affidabilità:** dipendenza da terza parte in fase di rendering UI.
4. **Prestazioni variabili:** caricamento e parsing runtime del motore Tailwind in browser.

## Decisione architetturale
**Approvata migrazione a build locale Tailwind CSS** con artefatto statico versionato (`static/css/tailwind.css`) e rimozione completa dello script CDN.

La migrazione è compatibile con l'assetto FastAPI/Jinja attuale e non richiede modifiche al dominio applicativo.

## Piano tecnico scelto
1. Aggiungere toolchain Node minimale (`package.json`) con `tailwindcss` e `@tailwindcss/cli`.
2. Introdurre file sorgente Tailwind (`assets/css/tailwind.input.css`) con direttive `@tailwind base/components/utilities`.
3. Configurare `content` su `templates/**/*.html`, `static/js/**/*.js` per purge classi.
4. Generare `static/css/tailwind.css` (dev) e `static/css/tailwind.min.css` (release).
5. Sostituire nei template `<script src="https://cdn.tailwindcss.com"></script>` con `<link rel="stylesheet" href="/static/css/tailwind.min.css">`.
6. Aggiornare CSP per rimuovere eccezioni script non più necessarie.
7. Aggiungere check CI: build CSS + fail se CDN Tailwind ricompare nei template.

## Criteri di accettazione
- Nessun template usa più `cdn.tailwindcss.com`.
- Nessuna regressione visiva bloccante nei percorsi principali (`/`, `/scans`, dettaglio scansione).
- CSP invariata o più restrittiva (mai più permissiva).
- Build deterministica e documentata per ambienti CI/CD.

## Impatto su sicurezza, UX e operations
- **Sicurezza:** riduzione rischio supply-chain e migliore hardening CSP.
- **UX:** comportamento UI più stabile su reti lente/intermittenti.
- **Ops:** maggiore controllo versioni e rollback dell'asset CSS.

## Riferimenti ufficiali
- Tailwind CSS (installation): https://tailwindcss.com/docs/installation
- Tailwind CSS (content configuration): https://tailwindcss.com/docs/content-configuration
- MDN CSP: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- OWASP ASVS (V14 Config): https://owasp.org/www-project-application-security-verification-standard/
