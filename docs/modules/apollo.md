# Apollo — detection engineering

## Italiano
Apollo carica regole dichiarative nel sottoinsieme JSON interoperabile e sicuro di YAML 1.2,
valida gli ID MITRE ATT&CK, confronta condizioni esatte con eventi `olympus.core.Event` ed
esporta `olympus.core.Alert`. Non esegue codice contenuto nelle regole.

```bash
olympus apollo test examples/input/apollo-rule.yaml examples/input/apollo-event.json
olympus apollo demo
```

## English
Apollo loads declarative rules from the safe, interoperable JSON subset of YAML 1.2, validates
MITRE ATT&CK IDs, matches exact conditions against `olympus.core.Event`, and exports
`olympus.core.Alert`. Rule content is never executed. The demo is fully synthetic and offline.
