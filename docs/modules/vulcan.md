# Vulcan — Aggregazione findings & report / Findings aggregation & reporting

## Italiano
Vulcan è il capostipite del reporting: consuma gli array JSON canonici prodotti dagli altri
moduli (`core.Asset`, `core.Finding`, `core.Alert`) e li trasforma in un unico report
d'ingaggio — deduplicato, ordinato per severità, in JSON e Markdown.

```bash
# Report consolidato (JSON + Markdown), input ripetibili
olympus vulcan report --engagement acme-2026 \
  --findings artemis-findings.json --findings argus-phone-intel.json \
  --assets argus-assets.json --alerts apollo-alerts.json \
  --output report.json --markdown report.md

# Solo ranking dei findings per severità
olympus vulcan rank --findings artemis-findings.json
```

## English
Vulcan is the reporting capstone: it consumes the canonical JSON arrays produced by the other
modules (`core.Asset`, `core.Finding`, `core.Alert`) and turns them into a single engagement
report — deduplicated, ranked by severity, in JSON and Markdown. Inputs are repeatable, so the
outputs of several tools are merged into one consolidated view.
