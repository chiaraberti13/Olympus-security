# WordPress Focused Assessment (`wordpress`)

## Teoria minima
- **Obiettivo formativo:** Analizzare rischi tipici di stack WordPress (core/plugin/theme).
- **Categoria:** CMS
- **Livello consigliato:** intermediate
- **Mappature:** OWASP A03, A06, A08 · MITRE TA0001, TA0007

## Quando usarla
Siti WordPress in produzione o staging con plugin di terze parti.

## Quando NON usarla
Target non WordPress o con WAF che blocca scansioni aggressive.

## Prerequisiti operativi
1. Verifica autorizzazione: Consenso esplicito per test su CMS e plugin.
2. Conferma legale: Rispetta ToS hosting e limiti del provider.
3. Stima durata e impatto: 20-60 min, invasività **medium**, rumore **medium**.

## Esempi di output da leggere
- Severity aggregate (critical/high/medium/low)
- Evidenze tecniche (request/response, banner, payload, endpoint)
- Confidence finding e stato validazione manuale

## Errori comuni
- Plugin enumerati ma non attivi
- Interpretare automaticamente tutti i finding come exploit confermati.
- Non correlare il risultato con il contesto business del target.

## Checklist remediation
- [ ] Conferma tecnica del finding con validazione manuale.
- [ ] Prioritizza in base a impatto business e superficie esposta.
- [ ] Definisci owner e SLA remediation.
- [ ] Riesegui scansione di verifica post-fix.

## Step successivo di apprendimento
Studiare hardening WordPress (least privilege, update policy, WAF).

## Riferimenti ufficiali
- Scanner/tool: ../user-manual.md#profili-di-scansione
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- MITRE ATT&CK: https://attack.mitre.org/
