# Artemis — web recon autorizzata / Authorized web recon

## Italiano
Artemis applica lo scope prima di qualsiasi futura richiesta web. Il controllo normalizza
schema, hostname IDNA, porte di default e path; ammette solo HTTP(S), rifiuta credenziali negli
URL e confronta origin e prefissi di path con confini di segmento. I target fuori scope sono
bloccati e registrati senza query string, evitando di inserire token accidentali nell'audit.
Il client solo-GET disabilita i redirect automatici, riapplica lo scope prima di ogni hop e
limita timeout, numero di redirect e dimensione del body. Non invia form né esegue JavaScript.
Ogni hostname viene risolto una sola volta per hop: tutti gli indirizzi devono rientrare in
`allowed_ip_networks` e il transport si connette direttamente a uno degli IP già autorizzati.

```bash
olympus artemis check-scope --url https://portal.olympusdemocorp.example/app/login \
  --scope examples/input/artemis-scope.json
olympus artemis fetch --url https://portal.olympusdemocorp.example/app/login \
  --scope examples/input/artemis-scope.json --timeout 5 --max-bytes 1000000
olympus artemis demo

# Check CVE Metabase (CVE-2026-72898): fingerprint versione, NESSUN payload SQLi.
# Metabase CVE check: version fingerprint only, NO SQLi payload is ever sent.
olympus artemis metabase --url https://metabase.olympusdemocorp.example \
  --scope examples/input/artemis-metabase-scope.json
olympus artemis metabase-demo
```

## English
Artemis enforces scope before any future web request. Validation normalizes scheme, IDNA host,
default ports and path; allows HTTP(S) only, rejects URL credentials, and compares origins and
path prefixes on segment boundaries. Out-of-scope targets are blocked and audited without
query strings, preventing accidental tokens from entering logs. The GET-only client disables
automatic redirects, reapplies scope before every hop, and limits timeout, redirect count and
body size. It never submits forms or executes JavaScript. The demo uses an offline transport.
Each hostname is resolved once per hop: every answer must match `allowed_ip_networks`, and the
transport connects directly to an already authorized IP without a second DNS lookup.
