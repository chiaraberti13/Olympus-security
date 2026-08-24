# Network & Infrastructure Scan (`network`)

## Teoria minima
- **Obiettivo formativo:** Mappare la superficie di rete (porte, servizi, versioni) e correlare i servizi esposti a CVE note tramite gli script NSE di Nmap.
- **Categoria:** Rete
- **Livello consigliato:** intermediate
- **Mappature:** OWASP A05, A06 · MITRE TA0007, TA0043
- **Moduli eseguiti:** `nmap_network` (service/version + script NSE `vulners`/`vuln`) e `testssl` (configurazione TLS).

## Quando usarla
Quando vuoi capire cosa è raggiungibile a livello di rete/infrastruttura: porte aperte, servizi e versioni potenzialmente vulnerabili, oltre alla configurazione TLS.

## Quando NON usarla
Su reti/sistemi senza autorizzazione esplicita o senza finestra di manutenzione concordata: lo scan di rete è più rumoroso e visibile.

## Prerequisiti operativi
1. Verifica autorizzazione: autorizzazione esplicita del proprietario della rete/host.
2. Conferma legale: lo scanning di rete non autorizzato è illegale; opera solo entro lo scope concordato.
3. Stima durata e impatto: 10-45 min, invasività **medium**, rumore **high**.
4. Tool esterno: richiede `nmap` installato (senza, il modulo viene saltato; in assenza di scansioni live vengono mostrati dati simulati a scopo didattico).

## Come funziona la correlazione CVE
Lo script NSE `vulners` associa **prodotto + versione** del servizio rilevato a CVE pubbliche. Le CVE estratte confluiscono nell'**enrichment** della piattaforma, che vi aggancia punteggi **CVSS**, presenza in **CISA KEV** e probabilità **EPSS** dai feed ufficiali aggiornati.

## Esempi di output da leggere
- Porte aperte e servizi (con banner/versione e CPE)
- Risultati script NSE con eventuali CVE rilevate
- Servizi notoriamente rischiosi se esposti (Telnet, SMB, RDP, Redis…)
- Esito configurazione TLS (cifrari/protocolli deboli)

## Errori comuni
- Versioni stimate da banner non sempre accurate
- CVE associate via `vulners` da confermare sul servizio reale
- Porte filtrate segnalate in modo ambiguo

## Checklist remediation
- [ ] Conferma versione e raggiungibilità reali del servizio.
- [ ] Prioritizza i servizi con CVE ad alto CVSS/EPSS o in CISA KEV.
- [ ] Riduci l'esposizione (firewall, segmentazione, allowlist IP).
- [ ] Applica patch/aggiornamenti e riesegui lo scan di verifica.

## Step successivo di apprendimento
Approfondire NSE, segmentazione di rete e hardening dei servizi esposti.

## Riferimenti ufficiali
- Scanner/tool: ../user-manual.md#profili-di-scansione
- Nmap NSE: https://nmap.org/book/nse.html
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- MITRE ATT&CK: https://attack.mitre.org/
