# Hermes — scanner di secret / Secret scanner

## Italiano
Hermes rileva token tramite prefissi noti ed entropia configurabile, analizza file, directory
e history Git, e produce SARIF 2.1.0. I valori non vengono mai scritti in output: sono
mascherati e identificati con fingerprint SHA-256.

```bash
olympus hermes scan . --output examples/output/hermes-results.sarif
olympus hermes scan . --history
olympus hermes demo
```

Il demo usa esclusivamente un token sintetico “Olympus Demo Corp” e termina con codice zero.

## English
Hermes detects tokens using known prefixes and configurable entropy, scans files, directories
and Git history, and emits SARIF 2.1.0. Values are never written to output: they are masked and
identified using SHA-256 fingerprints.

The commands above run a working-tree scan, include Git history, or execute the offline demo.
The demo uses only an unmistakably synthetic “Olympus Demo Corp” token and exits successfully.
