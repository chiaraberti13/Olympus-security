# Apollo — detection engineering

## Italiano
Apollo carica un sottoinsieme YAML dichiarativo e rigoroso (mapping, liste e scalari semplici),
valida gli ID MITRE ATT&CK, confronta condizioni esatte con eventi `olympus.core.Event` ed
esporta `olympus.core.Alert`. Tag, anchor e costruttori YAML sono rifiutati: il contenuto delle
regole non viene mai eseguito.

```bash
# Una regola contro un singolo evento normalizzato
olympus apollo test examples/input/apollo-rule.yaml examples/input/apollo-event.json

# Un'intera cartella di regole contro uno stream di eventi (NDJSON, un Event per riga).
# Exit 1 se scattano alert.
olympus apollo run --rules examples/input/apollo-ad --events eventi.ndjson --output alert.json

# Carica e valida una cartella di regole, elencandole (tabella o json)
olympus apollo rules --rules examples/input/apollo-ad --format table

# Pack di detection Blue Team (endpoint/persistence) su telemetria Windows/Sysmon
olympus apollo rules --rules examples/input/apollo-blueteam --format table

# Pack Red Team: copertura tattiche MITRE non coperte da apollo-ad/apollo-blueteam
olympus apollo rules --rules examples/input/apollo-redteam --format table
```

Pack di regole inclusi: **apollo-ad** (Active Directory: DCSync, Kerberoasting, pass-the-hash,
LLMNR poisoning, golden ticket), **apollo-blueteam** (endpoint/persistence: LSASS credential
dumping, PowerShell encoded, installazione servizi e scheduled-task, cancellazione event log,
Office che lancia una shell) e **apollo-redteam** — metodologia distillata da RedTeam-Tools,
organizzata per tattica MITRE ATT&CK non ancora coperta: domain trust enumeration (Discovery),
servizio remoto stile PsExec su admin$ (Lateral Movement), hook da tastiera globale e accesso
webcam senza finestra visibile da processo non firmato (Collection — le stesse tecniche di
KLogger/symbiote, qui **solo rilevate**, mai reimplementate come tool offensivo), beacon C2 su
DNS TXT ad alta entropia (Command and Control), upload di un archivio appena creato verso un
host di file-sharing anonimo (Exfiltration), rename di massa con shadow copy cancellate
(Impact — ransomware). Tutti solo *detection*: Olympus non esegue mai la tecnica.

## English
Apollo loads a strict declarative YAML subset (mappings, lists and plain scalars), validates
MITRE ATT&CK IDs, matches exact conditions against `olympus.core.Event`, and exports
`olympus.core.Alert`. YAML tags, anchors and constructors are rejected, so rule content is
never executed.

`apollo test` evaluates one rule against one event fixture; `apollo run` evaluates a whole rule
directory against an NDJSON event stream (exit code 1 when alerts fire, so it fits a pipeline);
`apollo rules` loads and validates a rule directory and lists every rule as a table or JSON.

Included packs: **apollo-ad**, **apollo-blueteam**, and **apollo-redteam** — methodology
distilled from RedTeam-Tools, covering the MITRE tactics neither prior pack reached: domain
trust enumeration (Discovery), PsExec-style remote service creation over admin$ (Lateral
Movement), a global keyboard hook and an unsigned process opening the camera with no visible
window (Collection — the exact techniques KLogger and symbiote use, here only *detected*, never
reimplemented as an offensive tool), high-entropy DNS TXT beaconing (Command and Control), a
freshly archived file POSTed to an anonymous file host (Exfiltration), and bulk file-extension
rename with shadow copies deleted (Impact — ransomware). Every pack is detection-only: Olympus
never performs the technique.
