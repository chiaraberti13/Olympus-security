# SECURITY — Olympus Security

## 🇮🇹 Etica e uso autorizzato
I moduli offensivi (Argus, Helios, Artemis, Proteus, Mars) sono strumenti per **red teaming
autorizzato, difesa e formazione**. Usarli contro sistemi per cui non hai autorizzazione
scritta è illegale e non è supportato.
- **Scope file obbligatorio** per i moduli attivi (Helios, Artemis): date, target ammessi,
  host esclusi, rate limit. Ciò che è fuori scope viene **bloccato e registrato**.
- **Non distruttivo**: osservazione e simulazione controllata, mai exploit reali su terzi.
- **Proteus** non raccoglie mai credenziali reali: chi clicca vede una pagina di *training*.
- Tutti i dati d'esempio sono **sintetici** ("Olympus Demo Corp").

## 🇬🇧 Ethics & authorized use
Offensive modules are tools for **authorized red teaming, defense and training**. Using them
against systems you have no written authorization for is illegal and unsupported.
- **Mandatory scope file** for active modules; out-of-scope targets are **blocked and logged**.
- **Non-destructive**: controlled observation/simulation, never real exploitation of others.
- **Proteus** never collects real credentials (training page only).
- All example data is **synthetic** ("Olympus Demo Corp").

## Threat model (piattaforma / platform)
- Superficie / surface: parsing di JSON/log non fidati in ingresso.
- Controlli / controls: validazione Pydantic (extra=forbid), nessun eval/exec, config via env,
  nessuna credenziale hardcoded, logging senza secret, minimo privilegio.

## Modello di sicurezza OSINT / OSINT security model
Le funzionalità OSINT reintegrate da progetti esterni seguono regole rigide, senza eccezioni:
The OSINT features integrated from external projects follow strict rules, without exception:
- **Adapter reali dormienti / dormant real adapters**: il percorso di default di ogni demo è un
  doppio offline; gli adapter che interrogano terze parti si attivano solo con chiavi API via
  env (`OLYMPUS_NUMVERIFY_KEY`, `OLYMPUS_RAPIDAPI_KEY`) — **nessuna chiave committata**.
- **Scope + block+log** su ogni target (dominio, URL, numero E.164, handle).
- **Consenso esplicito**: i lookup privacy-sensibili (breach, messaging, metadati profilo)
  richiedono `--i-am-authorized` con disclaimer.
- **Nessuna evasione / no evasion**: User-Agent onesto, mai TLS-fingerprint impersonation,
  rotazione proxy o anti-bot.
- **Nessun exploit / no exploitation**: il check Metabase (CVE-2026-72898) legge solo
  versione/reachability, non invia mai un payload SQLi.

### Fonti curate / Curated sources
Concetti reimplementati (non copiati): **SearchPhone/OsintNum** → `argus phone`;
**user-scanner** → `argus accounts`; **WhatsApp-OSINT/WhatsOSINT/whatslookup** → segnale
messaging in `argus phone`; **Metabase GHSA-vwf4-m7j8-wcjf** → regola Apollo + check Artemis; **xss_scanner** → check
XSS riflesso non-distruttivo in Artemis (marker benigno, nessuna evasione WAF);
**ad_attack_architecture / adhammer** → pack di **detection** AD in Apollo (solo lato
difensivo: DCSync, Kerberoasting, pass-the-hash, LLMNR poisoning, golden ticket);
**GhostTrack** → **IP OSINT** in Argus (classificazione offline + geolocation/ASN keyless).

### Escluso per design / Excluded by design
- **hackingtool** — launcher di ~215 tool esterni, molti distruttivi (DDoS, RAT, payload,
  phishing con credenziali reali): fuori dai limiti di Olympus.
- **Wireless Pentest Tools** — richiedono hardware radio e deauth (DoS).
- **adhammer** (stack offensivo AD: DCSync/pass-the-hash/relay/golden-ticket) — se ne prende
  solo l'eventuale lato *detection*, mai l'esecuzione offensiva.
- **METATRON** — orchestratore LLM di tool offensivi: architetturale, non un tool discreto.

## Reporting
Apri una issue con label `security` senza includere dati reali.
Open an issue labeled `security` without including real data.
