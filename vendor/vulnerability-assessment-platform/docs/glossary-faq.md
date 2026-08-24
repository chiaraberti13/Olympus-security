# Glossario Cyber & FAQ Operative

Questa pagina supporta il percorso didattico di VAP con definizioni rapide e risposte operative alle domande più comuni durante le scansioni.

## Glossario essenziale

### Asset
Risorsa da proteggere (applicazione, API, database, infrastruttura, endpoint cloud) che ha valore tecnico o di business.

### Attack Surface
Insieme dei punti esposti che un attaccante può usare (porte, endpoint, login, dipendenze vulnerabili, misconfigurazioni).

### CVE
Identificativo pubblico di una vulnerabilità nota (*Common Vulnerabilities and Exposures*).

### CVSS
Sistema di scoring della gravità tecnica di una vulnerabilità (*Common Vulnerability Scoring System*). In VAP è un indicatore di priorità, non l'unico criterio decisionale.

### False Positive
Segnalazione che sembra vulnerabilità ma non lo è dopo verifica manuale o contestuale.

### Finding
Evidenza prodotta da uno scanner (vulnerabilità, misconfigurazione, informazione utile al rischio).

### IDOR
Vulnerabilità di access control in cui un utente può accedere a risorse non autorizzate cambiando un identificatore.

### OWASP Top 10
Classifica delle categorie di rischio applicativo più critiche secondo OWASP.

### Remediation
Azione correttiva per ridurre o eliminare il rischio (patch, hardening, controllo accessi, validazione input, monitoraggio).

### Scope di scansione
Perimetro autorizzato della scansione (target, profondità, tipologie test, finestre temporali).

## FAQ operative

### 1) Quale tipo di scansione scelgo per iniziare?
Per una prima fotografia del rischio usa **light**: è più veloce e meno invasiva. Passa a **full** quando hai autorizzazioni, finestra di test e capacità di analizzare più output.

### 2) Perché VAP chiede consenso legale prima del run?
Perché i test di sicurezza devono essere autorizzati. Il consenso esplicito riduce rischio legale e rende tracciabile il mandato operativo.

### 3) Un finding "high" va sempre corretto subito?
In generale sì, ma la priorità reale dipende anche da esposizione, criticità business, compensating controls e probabilità di exploit.

### 4) Come gestisco i false positive?
Segui il flusso consigliato: riproduzione manuale, verifica contesto, raccolta evidenze e classificazione finale (confirmed/probable/needs-validation).

### 5) Perché alcuni scanner danno risultati diversi sullo stesso target?
Ogni tool ha motori, firme e profondità differenti. La correlazione multi-tool migliora copertura ma richiede interpretazione umana.

### 6) Cosa significa "needs-validation"?
La finding è plausibile ma non ancora confermata con evidenze sufficienti. Serve verifica manuale prima di aprire remediation definitiva.

### 7) Come riduco il rumore operativo durante uno scan?
Limita scope, scegli profilo coerente, pianifica finestre dedicate, monitora rate limit e usa la roadmap remediation per ordinare gli interventi.

### 8) Quali controlli minimi devo applicare dopo uno scan?
1. Conferma findings critiche.
2. Apri ticket remediation con owner e scadenza.
3. Riesegui scan di verifica.
4. Aggiorna evidenze in audit trail.

## Riferimenti ufficiali consigliati
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- NIST NVD (CVE/CVSS): https://nvd.nist.gov/
- FIRST CVSS: https://www.first.org/cvss/
