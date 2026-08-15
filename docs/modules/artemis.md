# Artemis — Web recon

> **🇮🇹 Italiano** · [🇬🇧 English below](#-english)

## 🇮🇹 Italiano

### Cosa fa
Artemis è il modulo Red di Olympus per la **ricognizione web**: content discovery, header
di sicurezza, misconfigurazioni CORS. È un modulo **attivo** (invia richieste HTTP reali al
target), quindi — a differenza di Argus — lo **scope è obbligatorio**: ogni comando verifica
l'host target contro un file di scope prima di qualunque richiesta; un target fuori
perimetro viene **bloccato e registrato**.

- **Header di sicurezza** — segnala CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy mancanti.
- **CORS misconfigurato** — rileva `Access-Control-Allow-Origin: *` combinato con
  `Access-Control-Allow-Credentials: true`, e riflessione arbitraria dell'header `Origin`
  con credenziali abilitate.
- **Content discovery** — verifica un insieme fisso di path sensibili noti (`.git/config`,
  `.env`, `.htpasswd`, `backup.zip`, `/admin`): una singola GET per path, nessun brute
  force, nessuna wordlist.
- **Check CVE Metabase (CVE-2026-72898)** — fingerprint **non-exploitativo**: legge la
  versione pubblica da `/api/session/properties` e la confronta con i range affetti; segnala
  un Finding `CRITICAL` con rimedio (upgrade) se vulnerabile. **Non invia mai** un payload
  SQLi: Olympus rileva il rischio, non lo sfrutta.

### Comandi
```bash
# Recon completa (header + CORS + content discovery) su un URL in scope
olympus artemis scan --url https://example.com --scope examples/input/artemis-scope.json \
    --output examples/output/artemis-findings.json

# Demo reale, offline e deterministica su un sito sintetico "Olympus Demo Corp"
olympus artemis demo
```

### File di scope
```json
{
  "engagement": "olympus-demo-corp-2026",
  "allowed_hosts": ["olympusdemocorp.example"],
  "excluded_hosts": []
}
```
Stessa semantica di Argus (match su hostname esatto o sottodominio), ma qui **obbligatoria**:
`artemis scan` non esegue mai una richiesta prima di aver verificato lo scope. I tentativi
fuori perimetro vengono appesi come riga JSON al log indicato da `--log` (default
`examples/output/artemis-blocked.log`).

### Output
`scan`/`demo` stampano (e opzionalmente esportano) un oggetto con l'`Asset` scansionato,
lo status HTTP e l'elenco dei `Finding` (conformi a `olympus.core`) trovati da tutti e tre
i motori.

### Esempi
`examples/input/artemis-scope.json` definisce il perimetro demo; l'output reale del comando
`demo` è in `examples/output/artemis-findings.json`.

### Etica
Non distruttivo: solo richieste HTTP GET standard, mai exploit o probing invasivo. Il
comando `demo` non tocca mai la rete reale: usa un `HttpClient` sintetico offline
(`olympus.artemis.demo_data`) su `olympusdemocorp.example` (TLD riservato alla
documentazione, RFC 2606).

---

## 🇬🇧 English

### What it does
Artemis is Olympus's Red module for **web reconnaissance**: content discovery, security
headers, CORS misconfigurations. It is an **active** module (it sends real HTTP requests
to the target), so — unlike Argus — **scope is mandatory**: every command checks the
target host against a scope file before any request; an out-of-scope target is **blocked
and logged**.

- **Security headers** — flags missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy.
- **CORS misconfiguration** — detects `Access-Control-Allow-Origin: *` combined with
  `Access-Control-Allow-Credentials: true`, and arbitrary `Origin` reflection with
  credentials allowed.
- **Content discovery** — checks a fixed set of well-known sensitive paths
  (`.git/config`, `.env`, `.htpasswd`, `backup.zip`, `/admin`): a single GET per path, no
  brute forcing, no wordlists.
- **Metabase CVE check (CVE-2026-72898)** — a **non-exploitative** fingerprint: it reads the
  public version from `/api/session/properties` and compares it against the affected ranges,
  emitting a `CRITICAL` finding with remediation (upgrade) when vulnerable. It **never sends**
  a SQLi payload: Olympus reports the risk, it does not exploit it.

### Commands
```bash
# Full recon (headers + CORS + content discovery) against an in-scope URL
olympus artemis scan --url https://example.com --scope examples/input/artemis-scope.json \
    --output examples/output/artemis-findings.json

# Real, offline, deterministic demo on a synthetic "Olympus Demo Corp" site
olympus artemis demo
```

### Scope file
```json
{
  "engagement": "olympus-demo-corp-2026",
  "allowed_hosts": ["olympusdemocorp.example"],
  "excluded_hosts": []
}
```
Same semantics as Argus's (exact hostname or subdomain match), but **mandatory** here:
`artemis scan` never runs a request before checking scope. Out-of-scope attempts are
appended as a JSON line to the log path given by `--log` (default
`examples/output/artemis-blocked.log`).

### Output
`scan`/`demo` print (and optionally export) an object with the scanned `Asset`, the HTTP
status, and the list of `Finding`s (conforming to `olympus.core`) found by all three
engines.

### Examples
`examples/input/artemis-scope.json` defines the demo perimeter; the `demo` command's real
output is at `examples/output/artemis-findings.json`.

### Ethics
Non-destructive: only standard HTTP GET requests, never exploitation or invasive probing.
The `demo` command never touches the real network: it uses a synthetic offline
`HttpClient` (`olympus.artemis.demo_data`) against `olympusdemocorp.example` (TLD reserved
for documentation, RFC 2606).
