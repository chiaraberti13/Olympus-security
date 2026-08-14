# Minerva — incident response e DFIR / Incident response and DFIR

## Italiano
Minerva mantiene una chain of custody append-only per oggetti `olympus.core.Evidence`. Ogni
evento contiene numero di sequenza, attore, azione, timestamp e hash SHA-256 collegato alla
voce precedente. Prima di aggiungere o verificare, l'intera catena viene validata; modifiche
retroattive, riordino e timestamp regressivi sono rilevati.
`minerva triage` valida un export Apollo, seleziona la severità massima, elimina i collegamenti
duplicati ed emette un oggetto condiviso `olympus.core.Incident`.

```bash
olympus minerva record examples/input/minerva-evidence.json custody.json \
  --actor analyst@example.test --action collected
olympus minerva verify custody.json
olympus minerva triage examples/output/apollo-alerts.json \
  --title "Suspicious process" --owner demo-soc --output incident.json
olympus minerva demo
```

## English
Minerva maintains an append-only chain of custody for `olympus.core.Evidence` objects. Each
event carries a sequence number, actor, action, timestamp, and a SHA-256 hash linked to the
previous entry. The complete chain is validated before appending or verifying, detecting
retroactive edits, reordering, and regressive timestamps. `minerva triage` validates an Apollo
alert export, selects the highest severity, removes duplicate links and emits a shared
`olympus.core.Incident`. The demo is synthetic and offline.
