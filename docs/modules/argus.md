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

### OSINT su persone / people OSINT
Argus profila anche **numeri di telefono** e **handle/username**. Il core è offline e senza
chiavi; gli arricchimenti reali (operatore, breach intel, presenza messaging, metadati
profilo) sono opzionali, dormienti (chiavi via env) e protetti da `--i-am-authorized`.
Nessuna evasione (User-Agent onesto). / Argus also profiles **phone numbers** and
**usernames**. The core is offline and key-free; real enrichment (carrier, breach intel,
messaging presence, profile metadata) is optional, dormant (env keys) and gated behind
`--i-am-authorized`. No evasion (honest User-Agent).

```bash
# Numero singolo: parsing offline (nessuna chiave) + arricchimenti opzionali autorizzati
olympus argus phone --number "+1 650 555 0123" --scope examples/input/argus-phone-scope.json
# Batch: un numero per riga
olympus argus phone --input numeri.txt --scope examples/input/argus-phone-scope.json

# Username singolo o batch: presenza su siti curati + metadati pubblici (autorizzati)
olympus argus accounts --username olympus_demo --scope examples/input/argus-accounts-scope.json
olympus argus accounts --input handle.txt --scope examples/input/argus-accounts-scope.json
```

## English
Argus performs strictly passive reconnaissance on authorized domains: DNS, email posture and
Certificate Transparency. `argus scan` requires a scope file, blocks and logs out-of-scope
targets, and exports assets conforming to `olympus.core.Asset`.

The commands above scan, compare two snapshots, and run the fully offline synthetic
“Olympus Demo Corp” demonstration. No target infrastructure is actively probed.
