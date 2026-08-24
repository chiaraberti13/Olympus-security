# OpenVAS / Greenbone (`openvas`)

## Teoria minima
- **Obiettivo formativo:** Comprendere il vuln scanning infrastrutturale con Greenbone/OpenVAS e la correlazione a CVE via feed NVT.
- **Categoria:** Rete
- **Livello consigliato:** intermediate
- **Mappature:** OWASP A05, A06 · MITRE TA0007, TA0043
- **Tipo:** adapter **opzionale** verso un'istanza Greenbone/GVM esistente (come Nessus/Acunetix).

## Come funziona l'integrazione
La piattaforma **non avvia** un task GVM da zero: legge i **risultati** di vulnerabilità da un endpoint HTTP della tua istanza Greenbone (configurato via `.env`) e li normalizza nei findings, con CVE/CVSS che confluiscono nell'**enrichment** (CVSS, CISA KEV, EPSS dai feed ufficiali).

In assenza di configurazione il modulo viene **saltato** senza errori; senza scansioni live mostra **dati simulati** a scopo didattico.

## Configurazione (`.env`)
```env
VAP_OPENVAS_API_BASE_URL=https://gvm.example.local
VAP_OPENVAS_API_KEY=<api-key>
VAP_OPENVAS_VULNERABILITIES_ENDPOINT=/gmp/results
VAP_OPENVAS_TIMEOUT=30
```
L'adapter invia l'API key nell'header `X-API-KEY` e si aspetta una risposta JSON con una lista `results` (o `vulnerabilities`). Ogni elemento può contenere: `name`, `threat` (High/Medium/Low/Log) e/o `cvss_score`, `host`, `port`, `cve`, `description`, `solution`.

## Quando usarla
Quando disponi di un'istanza Greenbone/GVM e vuoi una valutazione di vulnerabilità di rete ampia su host/servizi **autorizzati**.

## Quando NON usarla
Senza un'istanza GVM configurata o senza autorizzazione esplicita sulla rete target.

## Errori comuni
- Risultati dipendenti dai feed NVT e dalla configurazione del task GVM.
- Versioni stimate da banner da confermare sul servizio reale.

## Checklist remediation
- [ ] Prioritizza per CVSS/EPSS e presenza in CISA KEV.
- [ ] Conferma versione reale del servizio prima del patching.
- [ ] Riduci l'esposizione (firewall, segmentazione) e applica gli aggiornamenti.
- [ ] Riesegui il task GVM di verifica post-fix.

## Step successivo di apprendimento
Approfondire la gestione dei task GVM, dei feed NVT e del tuning dei falsi positivi.

## Riferimenti ufficiali
- Greenbone Documentation: https://docs.greenbone.net/
- python-gvm (GMP): https://greenbone.github.io/python-gvm/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- MITRE ATT&CK: https://attack.mitre.org/
