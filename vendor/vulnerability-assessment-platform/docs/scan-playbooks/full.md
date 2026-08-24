# Full Stack Assessment (`full`)

## Teoria minima
- **Obiettivo formativo:** Comprendere una valutazione completa multi-tool end-to-end.
- **Categoria:** Orchestrated
- **Livello consigliato:** intermediate
- **Mappature:** OWASP A01, A03, A05, A06, A09 · MITRE TA0001, TA0007, TA0009

## Quando usarla
Assessment iniziale o prima di una release importante.

## Quando NON usarla
Quando hai finestre temporali molto ridotte o scope non autorizzato.

## Prerequisiti operativi
1. Verifica autorizzazione: Autorizzazione esplicita del proprietario del target.
2. Conferma legale: Esegui solo su sistemi di tua proprietà o con consenso scritto.
3. Stima durata e impatto: 30-120 min, invasività **medium**, rumore **high**.

## Esempi di output da leggere
- Severity aggregate (critical/high/medium/low)
- Evidenze tecniche (request/response, banner, payload, endpoint)
- Confidence finding e stato validazione manuale

## Errori comuni
- Header mancanti non applicabili
- Interpretare automaticamente tutti i finding come exploit confermati.
- Non correlare il risultato con il contesto business del target.

## Checklist remediation
- [ ] Conferma tecnica del finding con validazione manuale.
- [ ] Prioritizza in base a impatto business e superficie esposta.
- [ ] Definisci owner e SLA remediation.
- [ ] Riesegui scansione di verifica post-fix.

## Step successivo di apprendimento
Studiare prioritizzazione remediation basata su impatto business.

## Riferimenti ufficiali
- Scanner/tool: ../user-manual.md#profili-di-scansione
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- MITRE ATT&CK: https://attack.mitre.org/
