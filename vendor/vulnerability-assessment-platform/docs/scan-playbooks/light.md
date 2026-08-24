# Light Baseline Scan (`light`)

## Teoria minima
- **Obiettivo formativo:** Eseguire una baseline rapida con basso impatto operativo.
- **Categoria:** Orchestrated
- **Livello consigliato:** beginner
- **Mappature:** OWASP A05, A06, A09 · MITRE TA0007

## Quando usarla
Health-check periodico e triage iniziale di un asset.

## Quando NON usarla
Audit approfonditi o validazioni pre-pen-test.

## Prerequisiti operativi
1. Verifica autorizzazione: Permesso di scansione base sul dominio/host.
2. Conferma legale: Mantieni la frequenza di scansione entro policy del cliente.
3. Stima durata e impatto: 5-20 min, invasività **low**, rumore **low**.

## Esempi di output da leggere
- Severity aggregate (critical/high/medium/low)
- Evidenze tecniche (request/response, banner, payload, endpoint)
- Confidence finding e stato validazione manuale

## Errori comuni
- Tecnologia rilevata ma non esposta
- Interpretare automaticamente tutti i finding come exploit confermati.
- Non correlare il risultato con il contesto business del target.

## Checklist remediation
- [ ] Conferma tecnica del finding con validazione manuale.
- [ ] Prioritizza in base a impatto business e superficie esposta.
- [ ] Definisci owner e SLA remediation.
- [ ] Riesegui scansione di verifica post-fix.

## Step successivo di apprendimento
Approfondire differenze tra passive e active recon.

## Riferimenti ufficiali
- Scanner/tool: ../user-manual.md#profili-di-scansione
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- MITRE ATT&CK: https://attack.mitre.org/
