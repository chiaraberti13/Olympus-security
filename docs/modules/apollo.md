# Apollo — detection engineering

## Italiano
Apollo carica un sottoinsieme YAML dichiarativo e rigoroso (mapping, liste e scalari semplici),
valida gli ID MITRE ATT&CK, confronta condizioni esatte con eventi `olympus.core.Event` ed
esporta `olympus.core.Alert`. Tag, anchor e costruttori YAML sono rifiutati: il contenuto delle
regole non viene mai eseguito.

```bash
olympus apollo test examples/input/apollo-rule.yaml examples/input/apollo-event.json
olympus apollo demo
```

## English
Apollo loads a strict declarative YAML subset (mappings, lists and plain scalars), validates
MITRE ATT&CK IDs, matches exact conditions against `olympus.core.Event`, and exports
`olympus.core.Alert`. YAML tags, anchors and constructors are rejected, so rule content is
never executed. The demo is fully synthetic and offline.
