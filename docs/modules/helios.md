# Helios — Network attack-surface mapper

> **🇮🇹 Italiano** · [🇬🇧 English below](#-english)

## 🇮🇹 Italiano

### Cosa fa
Helios è il modulo Red di Olympus per il **mapping della superficie d'attacco di rete**:
verifica quali porte TCP comuni sono aperte su un host, con **enforcement dello scope
obbligatorio** — a differenza di Argus (OSINT passivo), Helios è un modulo attivo che tocca
davvero l'infrastruttura del target, quindi ogni comando verifica il target contro un file
di scope prima di qualunque connessione; un target fuori perimetro viene **bloccato e
registrato**.

- **Port scan** — connessione TCP diretta (nessun banner grabbing, nessun exploit) su un
  profilo di porte comuni (SSH, HTTP/S, RDP, SMB, database...).
- **Scope obbligatorio** — file JSON con range CIDR e/o hostname esatti; un tentativo fuori
  scope non viene mai eseguito, solo bloccato e loggato.
- **Alert per esposizioni critiche** — porte ad alto rischio (Telnet, RDP, SMB, FTP) aperte
  generano automaticamente un `core.Alert`, non solo un `core.Finding`.

### Comandi
```bash
# Scan di un host in scope, con export opzionale come core.Asset/Finding/Alert
olympus helios scan --target 203.0.113.10 --scope examples/input/helios-scope.json \
    --output examples/output/helios-findings.json

# Demo reale, offline, su host sintetici "Olympus Demo Corp"
olympus helios demo
```

### File di scope
```json
{
  "engagement": "olympus-demo-corp-2026",
  "allowed_targets": ["203.0.113.0/24"],
  "excluded_targets": []
}
```
Un target è in perimetro se corrisponde a un range CIDR o a un hostname esatto in
`allowed_targets`, e non corrisponde a nessuna voce in `excluded_targets` (che ha
precedenza). I tentativi fuori perimetro vengono appesi come riga JSON al log indicato da
`--log` (default `examples/output/helios-blocked.log`).

### Output
`--output` scrive un oggetto JSON con tre array conformi a `olympus.core`:
`assets` (un host scansionato = un `Asset`), `findings` (una porta aperta = un `Finding`,
severità HIGH per le porte ad alto rischio) e `alerts` (un `Alert` per ogni finding HIGH o
CRITICAL) — lo stesso tipo di oggetto che produrrà il motore di detection di Apollo, così
Vulcan potrà aggregarli in modo uniforme.

### Esempi
`examples/input/helios-scope.json` definisce il perimetro demo; l'output reale del comando
`demo` è in `examples/output/helios-findings.json`, e un tentativo bloccato reale è
registrato in `examples/output/helios-blocked.log`.

### Etica
Non distruttivo: solo una connessione TCP diretta, mai exploit o probing invasivo. Il
comando `demo` non tocca mai la rete reale: usa un `PortScanner` sintetico offline
(`olympus.helios.demo_data`) su indirizzi del blocco riservato RFC 5737.

---

## 🇬🇧 English

### What it does
Helios is Olympus's Red module for **network attack-surface mapping**: it checks which
common TCP ports are open on a host, with **mandatory scope enforcement** — unlike Argus
(passive OSINT), Helios is an active module that really touches the target's
infrastructure, so every command checks the target against a scope file before any
connection; an out-of-scope target is **blocked and logged**.

- **Port scan** — a plain TCP connect (no banner grabbing, no exploitation) over a common
  ports profile (SSH, HTTP/S, RDP, SMB, databases...).
- **Mandatory scope** — a JSON file with CIDR ranges and/or exact hostnames; an
  out-of-scope attempt is never run, only blocked and logged.
- **Alerts for critical exposure** — high-risk ports (Telnet, RDP, SMB, FTP) found open
  automatically raise a `core.Alert`, not just a `core.Finding`.

### Commands
```bash
# Scan an in-scope host, optionally exported as core.Asset/Finding/Alert
olympus helios scan --target 203.0.113.10 --scope examples/input/helios-scope.json \
    --output examples/output/helios-findings.json

# Real, offline demo on synthetic "Olympus Demo Corp" hosts
olympus helios demo
```

### Scope file
```json
{
  "engagement": "olympus-demo-corp-2026",
  "allowed_targets": ["203.0.113.0/24"],
  "excluded_targets": []
}
```
A target is in scope if it matches a CIDR range or an exact hostname in
`allowed_targets`, and does not match any entry in `excluded_targets` (which takes
precedence). Out-of-scope attempts are appended as a JSON line to the log path given by
`--log` (default `examples/output/helios-blocked.log`).

### Output
`--output` writes a JSON object with three arrays conforming to `olympus.core`:
`assets` (one scanned host = one `Asset`), `findings` (one open port = one `Finding`, HIGH
severity for high-risk ports) and `alerts` (one `Alert` per HIGH/CRITICAL finding) — the
same object type Apollo's detection engine will produce, so Vulcan can later aggregate both
uniformly.

### Examples
`examples/input/helios-scope.json` defines the demo perimeter; the `demo` command's real
output is at `examples/output/helios-findings.json`, and a real blocked attempt is logged
at `examples/output/helios-blocked.log`.

### Ethics
Non-destructive: only a plain TCP connect, never exploitation or invasive probing. The
`demo` command never touches the real network: it uses a synthetic offline `PortScanner`
(`olympus.helios.demo_data`) against addresses in the RFC 5737 reserved range.
