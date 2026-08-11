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

## Reporting
Apri una issue con label `security` senza includere dati reali.
Open an issue labeled `security` without including real data.
