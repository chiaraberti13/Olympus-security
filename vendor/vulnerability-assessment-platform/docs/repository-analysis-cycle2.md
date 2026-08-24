## CICLO #2

### PROBLEMI TROVATI: 2

#### 🔴 CRITICI (0)
Nessuno.

#### 🟠 ALTA PRIORITÀ (0)
Nessuno.

#### 🟡 MEDIA PRIORITÀ (1)
1. Possibile drift tra `SCAN_TYPE_CHOICES` e aggiornamenti dinamici a `SCANNERS_MAP` durante test/estensioni runtime.
   - File: `scanner_engine.py`
   - Impatto: in scenari di estensione dinamica, le choices CLI possono non riflettere scanner iniettati a runtime.
   - Soluzione: rigenerare le choices nel parser con `choices=["full", *SCANNERS_MAP.keys()]` al build-time oppure esporre una factory dedicata.

#### 🟢 BASSA PRIORITÀ (1)
1. Warnings di deprecazione da dipendenze transitive (`passlib`, `python-jose`, `dateutil`).
   - File: runtime test output
   - Impatto: nessun blocco immediato, ma rischio incompatibilità con Python 3.13/3.14.
   - Soluzione: piano aggiornamento dipendenze e verifica compatibilità.

### RACCOMANDAZIONI AGGIUNTIVE
- Aggiungere test dedicati a `log_audit_event()` con assert sul payload strutturato.
- Integrare `pip-audit` e `bandit` nella pipeline CI come gate sicurezza.

### PROSSIMI STEP
1. Confermare se procedo con **CICLO #3** per ridurre i warning di deprecazione e hardening finale.
2. Definire policy per scanner dinamici/plug-in senza drift CLI.

---
STATO: IN CORSO
