# Argus — OSINT & recon passiva / OSINT & passive recon

> **🇮🇹 Italiano** · [🇬🇧 English below](#-english)

## 🇮🇹 Italiano

### Cosa fa
Argus è il modulo Red di Olympus per la **ricognizione passiva**: raccoglie informazioni
pubbliche su un dominio senza mai interagire attivamente con l'infrastruttura del target.
Copre tre fonti passive e le collega al contratto dati condiviso (`olympus.core.Asset`):

- **DNS** — A, AAAA, MX, TXT, e derivazione della postura SPF/DMARC.
- **Certificate Transparency** — enumerazione di sottodomini via i log pubblici CT (crt.sh),
  senza mai risolvere o sondare gli host scoperti.
- **Change monitoring** — diff tra due snapshot `argus-assets.json` per rilevare host nuovi,
  scomparsi o con IP cambiato (drift della superficie d'attacco).

Tutto ciò che Argus tocca deve essere **in perimetro**: ogni comando verifica il dominio
target contro un file di scope JSON prima di qualunque lookup; un target fuori perimetro
viene **bloccato e registrato** in un log di audit (mai eseguito, mai ignorato in silenzio).

### Comandi
```bash
# Ricognizione DNS/MX/SPF/DMARC + sottodomini CT, opzionalmente esportati come core.Asset
olympus argus scan --domain example.com --scope examples/input/argus-scope.json \
    --output examples/output/argus-assets.json

# Confronto tra due snapshot per il change monitoring
olympus argus diff --previous snapshot-vecchio.json --current snapshot-nuovo.json

# Demo reale, offline e deterministica su dati sintetici "Olympus Demo Corp"
olympus argus demo
```

### File di scope
```json
{
  "engagement": "olympus-demo-corp-2026",
  "allowed_domains": ["olympusdemocorp.example"],
  "excluded_domains": []
}
```
Un dominio è in perimetro se corrisponde (o è sottodominio di) una voce in
`allowed_domains` e non corrisponde a nessuna voce in `excluded_domains` (che ha
precedenza). I tentativi fuori perimetro vengono appesi come riga JSON al log indicato da
`--log` (default `examples/output/argus-blocked.log`).

### Output
Il comando `scan` stampa un riepilogo di ricognizione (`domain`, `a_records`,
`aaaa_records`, `mx_records`, `txt_records`, `spf`, `dmarc`, `subdomains`). Con `--output`,
gli stessi host vengono anche esportati come array JSON di `olympus.core.Asset`
(`schema_name="olympus.asset"`, `extra=forbid`), lo stesso schema condiviso da tutti gli
altri moduli. `diff` confronta due di questi export e restituisce `added`/`removed`/
`changed`/`unchanged` per hostname.

### Comportamento in assenza di rete
Il lookup Certificate Transparency è una fonte ausiliaria *best-effort*: se crt.sh non è
raggiungibile (rete assente, egress bloccato), `scan` stampa un avviso e prosegue con
`subdomains: []`, senza mai far fallire l'intera ricognizione DNS. Il comando `demo` non
dipende dalla rete: usa un dataset sintetico offline (`olympus.argus.demo_data`).

### Esempi
Vedi `examples/input/argus-scope.json`, `examples/input/argus-assets-previous.json` e
l'output reale prodotto da `argus demo` in `examples/output/argus-assets.json`.

### Etica
Nessun dato reale: `olympus argus demo` opera solo su `olympusdemocorp.example` (TLD
riservato alla documentazione, RFC 2606) e indirizzi nei blocchi riservati RFC 5737/3849.
Non distruttivo: solo query DNS/CT standard, mai probing attivo degli host scoperti.

---

## 🇬🇧 English

### What it does
Argus is Olympus's Red module for **passive reconnaissance**: it gathers public
information about a domain without ever actively probing the target's infrastructure. It
covers three passive sources and ties them into the shared data contract
(`olympus.core.Asset`):

- **DNS** — A, AAAA, MX, TXT, and SPF/DMARC posture derivation.
- **Certificate Transparency** — subdomain enumeration via public CT logs (crt.sh), never
  resolving or probing the discovered hosts.
- **Change monitoring** — diff between two `argus-assets.json` snapshots to detect new,
  removed, or IP-changed hosts (attack-surface drift).

Everything Argus touches must be **in scope**: every command checks the target domain
against a JSON scope file before any lookup; an out-of-scope target is **blocked and
logged** to an audit trail (never run, never silently dropped).

### Commands
```bash
# DNS/MX/SPF/DMARC recon + CT subdomains, optionally exported as core.Asset
olympus argus scan --domain example.com --scope examples/input/argus-scope.json \
    --output examples/output/argus-assets.json

# Compare two snapshots for change monitoring
olympus argus diff --previous old-snapshot.json --current new-snapshot.json

# Real, offline, deterministic demo on synthetic "Olympus Demo Corp" data
olympus argus demo
```

### Scope file
```json
{
  "engagement": "olympus-demo-corp-2026",
  "allowed_domains": ["olympusdemocorp.example"],
  "excluded_domains": []
}
```
A domain is in scope if it matches (or is a subdomain of) an entry in `allowed_domains`
and does not match any entry in `excluded_domains` (which takes precedence). Out-of-scope
attempts are appended as a JSON line to the log path given by `--log` (default
`examples/output/argus-blocked.log`).

### Output
The `scan` command prints a recon summary (`domain`, `a_records`, `aaaa_records`,
`mx_records`, `txt_records`, `spf`, `dmarc`, `subdomains`). With `--output`, the same hosts
are also exported as a JSON array of `olympus.core.Asset` (`schema_name="olympus.asset"`,
`extra=forbid`) — the same schema shared by every other module. `diff` compares two such
exports and returns `added`/`removed`/`changed`/`unchanged` by hostname.

### Behavior without network access
The Certificate Transparency lookup is a *best-effort* auxiliary source: if crt.sh is
unreachable (no network, blocked egress), `scan` prints a warning and continues with
`subdomains: []` instead of failing the whole (otherwise valid) DNS recon. `demo` never
depends on the network: it uses an offline synthetic dataset
(`olympus.argus.demo_data`).

### Examples
See `examples/input/argus-scope.json`, `examples/input/argus-assets-previous.json`, and the
real output produced by `argus demo` in `examples/output/argus-assets.json`.

### Ethics
No real data: `olympus argus demo` only ever operates on `olympusdemocorp.example` (TLD
reserved for documentation, RFC 2606) and addresses in the RFC 5737/3849 reserved ranges.
Non-destructive: only standard DNS/CT queries, never active probing of discovered hosts.
