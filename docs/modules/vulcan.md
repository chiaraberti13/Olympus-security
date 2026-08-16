# Vulcan — Aggregazione findings & report / Findings aggregation & reporting

## Italiano
Vulcan è il capostipite del reporting: consuma gli array JSON canonici prodotti dagli altri
moduli (`core.Asset`, `core.Finding`, `core.Alert`) e li trasforma in un unico report
d'ingaggio — deduplicato, ordinato per severità, in JSON e Markdown.

```bash
# Report consolidato (JSON + Markdown + HTML autonomo), input ripetibili.
# --min-severity filtra i findings sotto la soglia indicata.
olympus vulcan report --engagement acme-2026 \
  --findings artemis-findings.json --findings argus-phone-intel.json \
  --assets argus-assets.json --alerts apollo-alerts.json \
  --output report.json --markdown report.md --html report.html \
  --min-severity medium

# Solo ranking dei findings per severità (tabella o json)
olympus vulcan rank --findings artemis-findings.json --format table
```

## English
Vulcan is the reporting capstone: it consumes the canonical JSON arrays produced by the other
modules (`core.Asset`, `core.Finding`, `core.Alert`) and turns them into a single engagement
report — deduplicated, ranked by severity, in JSON, Markdown and a self-contained HTML page.
Inputs are repeatable, so the outputs of several tools are merged into one consolidated view;
`--min-severity` drops findings below a threshold and `rank --format` renders as a table or
JSON.
