# WhatWeb (`whatweb`)

## Teoria minima
- **Obiettivo formativo:** Comprendere output operativo dello scanner WhatWeb.
- **Categoria:** Recon
- **Livello consigliato:** intermediate
- **Mappature:** OWASP A05, A06 · MITRE TA0007

## Quando usarla
Quando serve un'analisi mirata con WhatWeb.

## Quando NON usarla
Quando manca autorizzazione formale o scope tecnico definito.

## Prerequisiti operativi
1. Verifica autorizzazione: Scope tecnico approvato + consenso del proprietario del sistema.
2. Conferma legale: Non usare su target di terzi senza autorizzazione tracciabile.
3. Stima durata e impatto: 10-45 min, invasività **medium**, rumore **medium**.

## Esempi di output da leggere
- Severity aggregate (critical/high/medium/low)
- Evidenze tecniche (request/response, banner, payload, endpoint)
- Confidence finding e stato validazione manuale

## Errori comuni
- Fingerprinting euristico suscettibile a header custom.
- Interpretare automaticamente tutti i finding come exploit confermati.
- Non correlare il risultato con il contesto business del target.

## Checklist remediation
- [ ] Conferma tecnica del finding con validazione manuale.
- [ ] Prioritizza in base a impatto business e superficie esposta.
- [ ] Definisci owner e SLA remediation.
- [ ] Riesegui scansione di verifica post-fix.

## Step successivo di apprendimento
Allenarsi su validazione manuale e prioritizzazione CVSS/business impact.

## Riferimenti ufficiali
- Scanner/tool: https://github.com/urbanadventurer/WhatWeb
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- MITRE ATT&CK: https://attack.mitre.org/
