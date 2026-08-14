# Argus — OSINT passivo / Passive OSINT

## Italiano
Argus esegue ricognizione esclusivamente passiva su domini autorizzati: DNS, postura email e
Certificate Transparency. `argus scan` richiede un file di scope, blocca e registra i target
fuori perimetro ed esporta asset conformi a `olympus.core.Asset`.

```bash
olympus argus scan --domain olympusdemocorp.example \
  --scope examples/input/argus-scope.json --output examples/output/argus-assets.json
olympus argus diff snapshot-prima.json snapshot-dopo.json
olympus argus demo
```

## English
Argus performs strictly passive reconnaissance on authorized domains: DNS, email posture and
Certificate Transparency. `argus scan` requires a scope file, blocks and logs out-of-scope
targets, and exports assets conforming to `olympus.core.Asset`.

The commands above scan, compare two snapshots, and run the fully offline synthetic
“Olympus Demo Corp” demonstration. No target infrastructure is actively probed.
