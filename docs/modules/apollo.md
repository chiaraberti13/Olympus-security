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
```

Pack di regole inclusi: **apollo-ad** (Active Directory: DCSync, Kerberoasting, pass-the-hash,
LLMNR poisoning, golden ticket) e **apollo-blueteam** (endpoint/persistence: LSASS credential
dumping, PowerShell encoded, installazione servizi e scheduled-task, cancellazione event log,
Office che lancia una shell). Tutti solo *detection*: Olympus non esegue mai la tecnica.

## English
Apollo loads a strict declarative YAML subset (mappings, lists and plain scalars), validates
MITRE ATT&CK IDs, matches exact conditions against `olympus.core.Event`, and exports
`olympus.core.Alert`. YAML tags, anchors and constructors are rejected, so rule content is
never executed.

`apollo test` evaluates one rule against one event fixture; `apollo run` evaluates a whole rule
directory against an NDJSON event stream (exit code 1 when alerts fire, so it fits a pipeline);
`apollo rules` loads and validates a rule directory and lists every rule as a table or JSON.
