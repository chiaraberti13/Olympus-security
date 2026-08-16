# Hermes — scanner di secret / Secret scanner

## Italiano
Hermes rileva token tramite prefissi noti ed entropia configurabile, analizza file, directory
e history Git, e produce SARIF 2.1.0. I valori non vengono mai scritti in output: sono
mascherati e identificati con fingerprint SHA-256.

```bash
olympus hermes scan . --output examples/output/hermes-results.sarif
olympus hermes scan . --history

# Baseline: registra i fingerprint accettati, poi sopprimili nelle scansioni successive.
olympus hermes scan . --write-baseline hermes-baseline.json   # exit 1: findings registrati
olympus hermes scan . --baseline hermes-baseline.json         # exit 0: noti soppressi
```

Un **baseline** è un array JSON di fingerprint SHA-256 accettati: `--write-baseline` lo scrive
dai finding correnti, `--baseline` scarta i finding già accettati (utile per accettare i
sintetici noti e far emergere solo i nuovi secret).

## English
Hermes detects tokens using known prefixes and configurable entropy, scans files, directories
and Git history, and emits SARIF 2.1.0. Values are never written to output: they are masked and
identified using SHA-256 fingerprints.

A **baseline** is a JSON array of accepted SHA-256 fingerprints: `--write-baseline` records the
current findings, and `--baseline` drops findings already accepted — so a scan can accept known
synthetic fixtures and surface only genuinely new secrets.
